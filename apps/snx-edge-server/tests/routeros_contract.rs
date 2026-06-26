//! Wiremock-backed contract tests for `Provisioner` against a fake RouterOS
//! REST endpoint.
//!
//! Strategy: stand up a `wiremock::MockServer`, point the server's
//! `RouterOsClient` at it (via the test-only `for_integration_tests`
//! constructor), and exercise `Provisioner::setup` / `teardown`. We assert
//! against the structured `SetupReport` and the recorded mock requests
//! rather than reaching into RouterOS state.
//!
//! The `RouterOsConfig` used by these tests carries the same defaults the
//! production loader assigns when no operator overrides are set; the env
//! vars under `*_env` are *not* read, so test isolation does not depend on
//! shell state.

use serde_json::{Value, json};
use snx_edge_server::config::RouterOsConfig;
use snx_edge_server::routeros::client::RouterOsClient;
use snx_edge_server::routeros::provisioner::{
    KIND_DEFAULT_ROUTE, KIND_DNS_DST_NAT, KIND_DOT_BLOCK, KIND_FASTTRACK_BYPASS, KIND_KILL_SWITCH,
    KIND_MANGLE_CONN_MARK, KIND_MANGLE_ROUTING_MARK, KIND_RFC1918_BYPASS, KIND_ROUTING_TABLE,
    Provisioner,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TAG: &str = "managed-by=snx-edge";
const CONTAINER_IP: &str = "172.19.0.2";

fn config() -> RouterOsConfig {
    RouterOsConfig {
        host_env: "ROUTEROS_HOST".into(),
        user_env: "ROUTEROS_USER".into(),
        password_env: "ROUTEROS_PASSWORD".into(),
        tls_skip_verify: true,
        comment_tag: TAG.into(),
        address_list_vpn: "vpn-clients".into(),
        address_list_bypass: "vpn-bypass".into(),
        routing_table: "vpn-route".into(),
        connection_mark: "vpn-conn".into(),
        routing_mark: "vpn-route".into(),
        auto_setup: false,
    }
}

fn client_for(server: &MockServer) -> RouterOsClient {
    // `for_integration_tests` skips the env-var lookup that production uses;
    // we feed the wiremock URL directly. The `/rest` suffix matches the
    // production `format!("https://{host}/rest")` so RouterOS REST paths
    // line up between unit and prod.
    RouterOsClient::for_integration_tests(format!("{}/rest", server.uri()), "u", "p", TAG)
}

/// All-empty list responses for the RouterOS endpoints `Provisioner::setup`
/// reads from. Shared by the happy-path and partial-failure tests.
async fn mount_empty_lists(server: &MockServer) {
    for p in [
        "/rest/routing/table",
        "/rest/ip/firewall/mangle",
        "/rest/ip/route",
        "/rest/ip/firewall/nat",
        "/rest/ip/firewall/filter",
        "/rest/ip/firewall/address-list",
    ] {
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200).set_body_json::<Value>(json!([])))
            .mount(server)
            .await;
    }
}

/// Universally accept PUTs (RouterOS uses PUT for resource creation) by
/// echoing back a plausible response body. RouterOS returns the created
/// object with a `.id` — we emit a fixed one for shape compliance.
async fn mount_accept_all_creates(server: &MockServer) {
    for p in [
        "/rest/routing/table",
        "/rest/ip/firewall/mangle",
        "/rest/ip/route",
        "/rest/ip/firewall/nat",
        "/rest/ip/firewall/filter",
        "/rest/ip/firewall/address-list",
    ] {
        Mock::given(method("PUT"))
            .and(path(p))
            .respond_with(
                ResponseTemplate::new(200).set_body_json::<Value>(json!({".id": "*1"})),
            )
            .mount(server)
            .await;
    }
}

#[tokio::test]
async fn provisioner_setup_full_happy_path() {
    let server = MockServer::start().await;
    mount_empty_lists(&server).await;
    mount_accept_all_creates(&server).await;

    let client = client_for(&server);
    let cfg = config();
    let prov = Provisioner::new(&client, &cfg);

    let report = prov.setup(CONTAINER_IP).await;

    assert!(
        report.failed.is_none(),
        "expected no failed step, got {:?}",
        report.failed,
    );
    assert_eq!(
        report.applied.len(),
        9,
        "expected 9 applied steps, got {:?}",
        report.applied,
    );
    // Sanity: the kind labels appear in the canonical order.
    assert_eq!(
        report.applied,
        vec![
            KIND_ROUTING_TABLE,
            KIND_MANGLE_CONN_MARK,
            KIND_MANGLE_ROUTING_MARK,
            KIND_DEFAULT_ROUTE,
            KIND_KILL_SWITCH,
            KIND_DNS_DST_NAT,
            KIND_DOT_BLOCK,
            KIND_FASTTRACK_BYPASS,
            KIND_RFC1918_BYPASS,
        ],
    );
}

#[tokio::test]
async fn provisioner_setup_partial_failure_returns_partial() {
    let server = MockServer::start().await;
    mount_empty_lists(&server).await;

    // Accept creates for the first three steps' resource paths.
    // Routing-table is a `/routing/table` PUT (step 1).
    Mock::given(method("PUT"))
        .and(path("/rest/routing/table"))
        .respond_with(ResponseTemplate::new(200).set_body_json::<Value>(json!({".id": "*1"})))
        .mount(&server)
        .await;

    // The mangle endpoint serves both step 2 (conn-mark) and step 3
    // (routing-mark). We need the *second* PUT (routing-mark) to fail with
    // 500 while the first still succeeds. Wiremock matches in registration
    // order; we register a "first PUT succeeds" mock with `up_to_n_times(1)`
    // before a catch-all 500 fallback.
    Mock::given(method("PUT"))
        .and(path("/rest/ip/firewall/mangle"))
        .respond_with(ResponseTemplate::new(200).set_body_json::<Value>(json!({".id": "*1"})))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/rest/ip/firewall/mangle"))
        .respond_with(ResponseTemplate::new(500).set_body_string("server error"))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let cfg = config();
    let prov = Provisioner::new(&client, &cfg);

    let report = prov.setup(CONTAINER_IP).await;

    let (step, _err) = report
        .failed
        .as_ref()
        .expect("expected setup to fail at the routing-mark step");
    assert_eq!(*step, KIND_MANGLE_ROUTING_MARK);
    assert_eq!(report.applied.len(), 2, "expected first two steps to be applied before the failure, got {:?}", report.applied);
    assert_eq!(report.applied[0], KIND_ROUTING_TABLE);
    assert_eq!(report.applied[1], KIND_MANGLE_CONN_MARK);
}

#[tokio::test]
async fn provisioner_setup_idempotent_on_re_run() {
    let server = MockServer::start().await;

    // Track the number of PUTs each path receives. Wiremock exposes
    // `received_requests()` on the MockServer to count; we rely on that at
    // the end of the test to assert no duplicates.
    //
    // Setup expects: every list endpoint returns *one* managed entry whose
    // comment carries the structured `kind=` tag. Each `ensure_*` should
    // detect the existing entry and skip the create step entirely.

    // Routing table list with a managed routing-table entry.
    Mock::given(method("GET"))
        .and(path("/rest/routing/table"))
        .respond_with(ResponseTemplate::new(200).set_body_json::<Value>(json!([{
            ".id": "*1",
            "name": "vpn-route",
            "comment": format!("{TAG};kind={KIND_ROUTING_TABLE}"),
        }])))
        .mount(&server)
        .await;

    // Mangle list serves both ensure_* helpers; include both kinds.
    Mock::given(method("GET"))
        .and(path("/rest/ip/firewall/mangle"))
        .respond_with(ResponseTemplate::new(200).set_body_json::<Value>(json!([
            {".id": "*1", "chain": "prerouting", "comment": format!("{TAG};kind={KIND_MANGLE_CONN_MARK}")},
            {".id": "*2", "chain": "prerouting", "comment": format!("{TAG};kind={KIND_MANGLE_ROUTING_MARK}")},
        ])))
        .mount(&server)
        .await;

    // Routes — default + kill-switch.
    Mock::given(method("GET"))
        .and(path("/rest/ip/route"))
        .respond_with(ResponseTemplate::new(200).set_body_json::<Value>(json!([
            {".id": "*1", "comment": format!("{TAG};kind={KIND_DEFAULT_ROUTE}")},
            {".id": "*2", "type": "blackhole", "comment": format!("{TAG};kind={KIND_KILL_SWITCH}")},
        ])))
        .mount(&server)
        .await;

    // NATs — both protocols already present.
    Mock::given(method("GET"))
        .and(path("/rest/ip/firewall/nat"))
        .respond_with(ResponseTemplate::new(200).set_body_json::<Value>(json!([
            {".id": "*1", "protocol": "udp", "comment": format!("{TAG};kind={KIND_DNS_DST_NAT}")},
            {".id": "*2", "protocol": "tcp", "comment": format!("{TAG};kind={KIND_DNS_DST_NAT}")},
        ])))
        .mount(&server)
        .await;

    // Filter — DoT block + FastTrack.
    Mock::given(method("GET"))
        .and(path("/rest/ip/firewall/filter"))
        .respond_with(ResponseTemplate::new(200).set_body_json::<Value>(json!([
            {".id": "*1", "chain": "forward", "action": "drop", "comment": format!("{TAG};kind={KIND_DOT_BLOCK}")},
            {".id": "*2", "chain": "forward", "action": "fasttrack-connection", "comment": format!("{TAG};kind={KIND_FASTTRACK_BYPASS}")},
        ])))
        .mount(&server)
        .await;

    // Address-list — already contains all three RFC1918 ranges so the
    // bypass step is a complete no-op on the second run.
    Mock::given(method("GET"))
        .and(path("/rest/ip/firewall/address-list"))
        .respond_with(ResponseTemplate::new(200).set_body_json::<Value>(json!([
            {".id": "*1", "list": "vpn-bypass", "address": "192.168.0.0/16", "comment": format!("{TAG};kind={KIND_RFC1918_BYPASS}")},
            {".id": "*2", "list": "vpn-bypass", "address": "172.16.0.0/12",  "comment": format!("{TAG};kind={KIND_RFC1918_BYPASS}")},
            {".id": "*3", "list": "vpn-bypass", "address": "10.0.0.0/8",     "comment": format!("{TAG};kind={KIND_RFC1918_BYPASS}")},
        ])))
        .mount(&server)
        .await;

    // No PUT mocks at all — any PUT would hit wiremock's 404 default and
    // surface as a `BadGateway` failure, which would in turn appear in
    // `report.failed`. That is the assertion: idempotent setup never PUTs.

    let client = client_for(&server);
    let cfg = config();
    let prov = Provisioner::new(&client, &cfg);

    let report1 = prov.setup(CONTAINER_IP).await;
    assert!(
        report1.failed.is_none(),
        "first run should be no-op, got {:?}",
        report1.failed
    );
    assert_eq!(report1.applied.len(), 9);

    let report2 = prov.setup(CONTAINER_IP).await;
    assert!(
        report2.failed.is_none(),
        "second run should be no-op, got {:?}",
        report2.failed
    );
    assert_eq!(report2.applied.len(), 9);

    // Now look at the recorded requests: we should see GETs but zero PUTs.
    let requests = server
        .received_requests()
        .await
        .expect("wiremock recording enabled");
    let put_count = requests
        .iter()
        .filter(|r| r.method.as_str().eq_ignore_ascii_case("PUT"))
        .count();
    assert_eq!(
        put_count, 0,
        "idempotent re-run must not issue any PUT/create requests"
    );
}

#[tokio::test]
async fn provisioner_teardown_removes_only_managed() {
    let server = MockServer::start().await;

    // Each list endpoint returns a mix of managed (carrying the structured
    // tag) and user-modified entries that share the path but have no tag.
    let managed = |kind: &str| format!("{TAG};kind={kind}");
    let mock_list = |path_str: &'static str, body: Value| {
        Mock::given(method("GET"))
            .and(path(path_str))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
    };

    mock_list(
        "/rest/ip/firewall/filter",
        json!([
            {".id": "*1", "comment": managed(KIND_DOT_BLOCK)},
            {".id": "*2", "comment": "user-defined rule, do not touch"},
            {".id": "*3", "comment": managed(KIND_FASTTRACK_BYPASS)},
        ]),
    )
    .mount(&server)
    .await;

    mock_list(
        "/rest/ip/firewall/nat",
        json!([
            {".id": "*4", "comment": managed(KIND_DNS_DST_NAT)},
            {".id": "*5"},
        ]),
    )
    .mount(&server)
    .await;

    mock_list(
        "/rest/ip/firewall/mangle",
        json!([
            {".id": "*6", "comment": managed(KIND_MANGLE_CONN_MARK)},
            {".id": "*7", "comment": managed(KIND_MANGLE_ROUTING_MARK)},
            {".id": "*8", "comment": "operator note"},
        ]),
    )
    .mount(&server)
    .await;

    mock_list(
        "/rest/ip/route",
        json!([
            {".id": "*9",  "comment": managed(KIND_DEFAULT_ROUTE)},
            {".id": "*10", "comment": managed(KIND_KILL_SWITCH)},
        ]),
    )
    .mount(&server)
    .await;

    mock_list(
        "/rest/ip/firewall/address-list",
        json!([
            {".id": "*11", "list": "vpn-bypass", "address": "10.0.0.0/8", "comment": managed(KIND_RFC1918_BYPASS)},
            {".id": "*12", "list": "user-list", "address": "8.8.8.8"},
        ]),
    )
    .mount(&server)
    .await;

    mock_list(
        "/rest/routing/table",
        json!([
            {".id": "*13", "name": "vpn-route", "comment": managed(KIND_ROUTING_TABLE)},
        ]),
    )
    .mount(&server)
    .await;

    // Accept any DELETE — we count them afterwards.
    for p in [
        "/rest/ip/firewall/filter",
        "/rest/ip/firewall/nat",
        "/rest/ip/firewall/mangle",
        "/rest/ip/route",
        "/rest/ip/firewall/address-list",
        "/rest/routing/table",
    ] {
        // wiremock's `path` matcher requires an exact match — DELETEs are
        // sent to `<path>/<id>` so we widen with `path_regex`.
        Mock::given(method("DELETE"))
            .and(wiremock::matchers::path_regex(format!(
                "^{}/\\*[0-9a-fA-F]+$",
                regex_escape(p)
            )))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
    }

    let client = client_for(&server);
    let cfg = config();
    let prov = Provisioner::new(&client, &cfg);

    let removed = prov.teardown().await.expect("teardown succeeds");
    // 2 filter + 1 nat + 2 mangle + 2 route + 1 address-list + 1 routing-table
    assert_eq!(removed, 9, "expected 9 managed objects removed");

    // Verify only managed IDs were targeted by DELETE.
    let managed_ids: std::collections::HashSet<&str> = [
        "*1", "*3", "*4", "*6", "*7", "*9", "*10", "*11", "*13",
    ]
    .into_iter()
    .collect();
    let user_ids: std::collections::HashSet<&str> = ["*2", "*5", "*8", "*12"].into_iter().collect();

    let requests = server.received_requests().await.unwrap();
    let deletes: Vec<_> = requests
        .iter()
        .filter(|r| r.method.as_str().eq_ignore_ascii_case("DELETE"))
        .map(|r| r.url.path().to_string())
        .collect();
    for url in &deletes {
        let last = url.rsplit('/').next().unwrap();
        assert!(
            managed_ids.contains(last),
            "DELETE targeted non-managed id {last} (url {url})",
        );
        assert!(
            !user_ids.contains(last),
            "DELETE targeted user-owned id {last} (url {url})",
        );
    }
    assert_eq!(
        deletes.len(),
        managed_ids.len(),
        "expected one DELETE per managed object",
    );
}

/// P0-7 regression: operator-added VPN-client entries created via
/// [`RouterOsClient::add_address`] must carry the structured `;kind=vpn-client`
/// tag so the legacy-sweep at the start of [`Provisioner::setup`] PRESERVES
/// them. A bare `managed-by=snx-edge` entry (no `;kind=`) is still swept.
///
/// The kinded comment is *captured from a real `add_address` call* (not
/// hard-coded), so this test fails if `add_address` ever reverts to writing a
/// bare tag — that bare comment would be classified as legacy and deleted,
/// which is exactly the bug being fixed.
#[tokio::test]
async fn legacy_sweep_preserves_kinded_client_entries() {
    // --- Phase 1: capture the comment `add_address` writes for a client. ---
    let kinded_comment = {
        let server = MockServer::start().await;
        // Dedup pre-check sees an empty list.
        Mock::given(method("GET"))
            .and(path("/rest/ip/firewall/address-list"))
            .respond_with(ResponseTemplate::new(200).set_body_json::<Value>(json!([])))
            .mount(&server)
            .await;
        // Echo back a plausible created object — `address` is a required field
        // on `AddressListEntry`, so the response must carry it.
        Mock::given(method("PUT"))
            .and(path("/rest/ip/firewall/address-list"))
            .respond_with(ResponseTemplate::new(200).set_body_json::<Value>(json!({
                ".id": "*1",
                "list": "vpn-clients",
                "address": "10.99.0.5",
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        client
            .add_address("vpn-clients", "10.99.0.5", "vpn-client", None, None)
            .await
            .expect("add_address succeeds");

        let requests = server.received_requests().await.unwrap();
        let put = requests
            .iter()
            .find(|r| r.method.as_str().eq_ignore_ascii_case("PUT"))
            .expect("add_address issues a PUT");
        let body: Value = serde_json::from_slice(&put.body).expect("PUT body is JSON");
        body["comment"]
            .as_str()
            .expect("PUT body carries a comment")
            .to_string()
    };

    assert!(
        kinded_comment.contains(";kind=vpn-client"),
        "add_address must tag client entries with kind=vpn-client, got {kinded_comment:?}",
    );

    // --- Phase 2: the legacy sweep preserves the kinded entry. ---
    let server = MockServer::start().await;

    // Address-list: one kinded vpn-client (must survive) + one bare legacy
    // entry (must be swept). IDs must be hex — `delete()` validates the form.
    Mock::given(method("GET"))
        .and(path("/rest/ip/firewall/address-list"))
        .respond_with(ResponseTemplate::new(200).set_body_json::<Value>(json!([
            {".id": "*c0ffee", "list": "vpn-clients", "address": "10.99.0.5", "comment": kinded_comment},
            {".id": "*dead",   "list": "vpn-clients", "address": "10.99.0.6", "comment": TAG},
        ])))
        .mount(&server)
        .await;

    // All other legacy paths empty so the sweep only ever touches the
    // address-list. The `ensure_*` idempotency GETs re-read these too.
    for p in [
        "/rest/ip/firewall/filter",
        "/rest/ip/firewall/nat",
        "/rest/ip/firewall/mangle",
        "/rest/ip/route",
        "/rest/routing/table",
    ] {
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200).set_body_json::<Value>(json!([])))
            .mount(&server)
            .await;
    }

    mount_accept_all_creates(&server).await;

    Mock::given(method("DELETE"))
        .and(wiremock::matchers::path_regex(r".*/\*[0-9a-fA-F]+$"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let cfg = config();
    let prov = Provisioner::new(&client, &cfg);

    let report = prov.setup(CONTAINER_IP).await;
    assert!(
        report.failed.is_none(),
        "expected setup to succeed, got {:?}",
        report.failed,
    );

    let requests = server.received_requests().await.unwrap();
    let deletes: Vec<String> = requests
        .iter()
        .filter(|r| r.method.as_str().eq_ignore_ascii_case("DELETE"))
        .map(|r| r.url.path().to_string())
        .collect();

    assert!(
        deletes.iter().any(|u| u.ends_with("/*dead")),
        "bare legacy entry must be swept, deletes={deletes:?}",
    );
    assert!(
        !deletes.iter().any(|u| u.ends_with("/*c0ffee")),
        "kinded vpn-client entry must NOT be swept, deletes={deletes:?}",
    );
}

/// Tiny regex-escape helper. Keeps the test file dependency-free of `regex`
/// crate while we splice known-safe paths into a regex literal.
fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        if matches!(
            c,
            '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$' | '\\'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[tokio::test]
async fn routeros_legacy_migration_deletes_old_tag_objects() {
    let server = MockServer::start().await;

    // Each list endpoint has a single legacy entry (bare `managed-by=...`
    // with no `;kind=`). The migration sweep deletes these *before* setup
    // creates the structured replacements.
    let legacy_body = json!([
        {".id": "*deadbeef", "comment": TAG},
    ]);
    for p in [
        "/rest/ip/firewall/filter",
        "/rest/ip/firewall/nat",
        "/rest/ip/firewall/mangle",
        "/rest/ip/route",
        "/rest/ip/firewall/address-list",
        "/rest/routing/table",
    ] {
        // First call returns the legacy object. Second call returns empty
        // (post-migration view). `up_to_n_times(1)` registers the "legacy"
        // response only once; subsequent GETs fall through to the empty
        // mock registered immediately after.
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200).set_body_json(legacy_body.clone()))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200).set_body_json::<Value>(json!([])))
            .mount(&server)
            .await;
    }

    // Accept legacy DELETEs.
    Mock::given(method("DELETE"))
        .and(wiremock::matchers::path_regex(r".*/\*[0-9a-fA-F]+$"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    // Accept all PUTs (the post-migration recreation phase).
    mount_accept_all_creates(&server).await;

    let client = client_for(&server);
    let cfg = config();
    let prov = Provisioner::new(&client, &cfg);

    let report = prov.setup(CONTAINER_IP).await;
    assert!(
        report.failed.is_none(),
        "expected setup to succeed, got {:?}",
        report.failed,
    );

    // Inspect request order: every DELETE for a legacy `*deadbeef` id must
    // happen *before* the first PUT (the migration runs at the start of
    // `setup`). We collect only DELETE/PUT events to keep the assertion
    // robust against the many GETs interleaved by the idempotency checks.
    let requests = server.received_requests().await.unwrap();
    let mut first_put_idx: Option<usize> = None;
    let mut last_legacy_delete_idx: Option<usize> = None;
    for (i, r) in requests.iter().enumerate() {
        let m = r.method.as_str();
        if m.eq_ignore_ascii_case("PUT") && first_put_idx.is_none() {
            first_put_idx = Some(i);
        }
        if m.eq_ignore_ascii_case("DELETE") && r.url.path().ends_with("/*deadbeef") {
            last_legacy_delete_idx = Some(i);
        }
    }
    let first_put_idx = first_put_idx.expect("expected at least one PUT in setup recreation phase");
    let last_legacy_delete_idx =
        last_legacy_delete_idx.expect("expected legacy DELETEs to be issued");
    assert!(
        last_legacy_delete_idx < first_put_idx,
        "legacy DELETE (#{last_legacy_delete_idx}) must precede first PUT (#{first_put_idx})",
    );
}
