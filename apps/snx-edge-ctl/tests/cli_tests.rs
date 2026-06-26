//! Black-box CLI tests for `snx-edge-ctl`.
//!
//! These tests do **not** require a running server — they exercise clap
//! argument parsing, the `--help` / `--version` paths, and unknown-command
//! error handling. Anything that talks to a server is out of scope; that
//! belongs in the server's integration suite.
//!
//! Tests that mutate process-wide environment variables (e.g. `XDG_*`,
//! `HOME`) are wrapped with `serial_test::serial` so they do not race
//! each other when the suite is run multi-threaded.

use assert_cmd::Command;
use predicates::prelude::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn help_lists_top_level_commands() {
    Command::cargo_bin("snx-edge-ctl")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        // Each top-level subcommand we ship must appear in the help text.
        // These names are public CLI surface — losing one is a breaking
        // change for users.
        .stdout(predicate::str::contains("login"))
        .stdout(predicate::str::contains("logout"))
        .stdout(predicate::str::contains("server"))
        .stdout(predicate::str::contains("connect"))
        .stdout(predicate::str::contains("disconnect"))
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("profiles"))
        .stdout(predicate::str::contains("routing"))
        .stdout(predicate::str::contains("users"))
        .stdout(predicate::str::contains("logs"));
}

#[test]
fn version_prints_pkg_version() {
    let v = env!("CARGO_PKG_VERSION");
    Command::cargo_bin("snx-edge-ctl")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(v));
}

#[test]
fn unknown_subcommand_fails() {
    Command::cargo_bin("snx-edge-ctl")
        .unwrap()
        .arg("nonexistent-command")
        .assert()
        .failure();
}

#[test]
fn quiet_mode_with_help_still_prints() {
    // `--quiet` controls subcommand output, not clap's `--help`. Help must
    // always render — otherwise users have no escape hatch when they wedge
    // their config.
    Command::cargo_bin("snx-edge-ctl")
        .unwrap()
        .args(["--quiet", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn no_subcommand_prints_usage_and_fails() {
    // Invoking the ctl with no subcommand at all should be an error (clap
    // requires a subcommand) and emit usage to stderr. This pins the
    // current behaviour so we do not accidentally regress to "do nothing".
    Command::cargo_bin("snx-edge-ctl")
        .unwrap()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage").or(predicate::str::contains("USAGE")));
}

#[test]
fn routing_help_lists_subactions() {
    Command::cargo_bin("snx-edge-ctl")
        .unwrap()
        .args(["routing", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("clients"))
        .stdout(predicate::str::contains("bypass"))
        .stdout(predicate::str::contains("setup"))
        .stdout(predicate::str::contains("teardown"))
        .stdout(predicate::str::contains("diagnostics"));
}

#[test]
fn profiles_help_lists_subactions() {
    Command::cargo_bin("snx-edge-ctl")
        .unwrap()
        .args(["profiles", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("create"))
        .stdout(predicate::str::contains("delete"));
}

#[test]
fn users_help_lists_subactions() {
    Command::cargo_bin("snx-edge-ctl")
        .unwrap()
        .args(["users", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("create"))
        .stdout(predicate::str::contains("delete"));
}

/// `connect` MUST exit non-zero when the server reports an MFA challenge that
/// cannot be resolved (here: `--quiet`, where there is no interactive prompt).
/// This pins the P1-14 fix: previously `connect` returned exit 0 on `Mfa`.
///
/// We stand up a `wiremock` server that returns a `TunnelStatus` whose
/// `connection.state == "Mfa"` for `POST /api/v1/tunnel/connect`. Auth is
/// bypassed with `--token` (so no keyring / login round-trip is needed) and a
/// UUID `--profile` is passed so the CLI does not call `list_profiles`. `HOME`
/// / `XDG_CONFIG_HOME` are redirected at a temp dir so the real `client.toml`
/// is never read or written.
#[tokio::test]
async fn connect_exits_nonzero_on_mfa_in_quiet_mode() {
    let server = MockServer::start().await;

    let mfa_status = serde_json::json!({
        "connection": {
            "state": "Mfa",
            "mfa_type": "otp",
            "prompt": "Enter your one-time code"
        },
        "uptime_seconds": null,
        "tx_bytes": 0,
        "rx_bytes": 0
    });

    Mock::given(method("POST"))
        .and(path("/api/v1/tunnel/connect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&mfa_status))
        .mount(&server)
        .await;

    let uri = server.uri();
    let home = tempfile::tempdir().unwrap();
    let home_path = home.path().to_path_buf();

    // `assert_cmd` is blocking; run it off the async runtime so the wiremock
    // server can keep serving requests while the child process dials it.
    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("snx-edge-ctl")
            .unwrap()
            .env("HOME", &home_path)
            .env("XDG_CONFIG_HOME", home_path.join(".config"))
            .args([
                "--server",
                &uri,
                "--token",
                "test-token",
                "--quiet",
                "connect",
                "--profile",
                "11111111-1111-4111-8111-111111111111",
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("MFA"));
    })
    .await
    .unwrap();
}

/// Currently `--server invalid-url <subcommand>` is *not* validated up front
/// — the URL is only parsed when reqwest tries to dial. This test pins the
/// gap so a future change that adds eager validation can flip the assertion
/// to `failure()` without searching for the test.
#[test]
#[ignore = "Eager URL validation not implemented; failure surfaces only on first \
            HTTP request. Track in the audit doc and remove the #[ignore] once \
            ApiClient validates `--server` synchronously."]
fn invalid_server_url_eagerly_rejected() {
    Command::cargo_bin("snx-edge-ctl")
        .unwrap()
        .args(["--server", "definitely not a url", "status"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid").or(predicate::str::contains("URL")));
}
