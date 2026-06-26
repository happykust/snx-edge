use crate::config::RouterOsConfig;
use crate::error::AppError;
use crate::routeros::client::{RouterOsClient, comment_matches_kind};
use crate::routeros::models::*;

// === Kind labels for structured `managed-by=...;kind=<kind>` comments. ===
//
// These are the compile-time labels used both as the `kind=` value on
// RouterOS objects we manage *and* as step names returned in [`SetupReport`].
// Keep in sync with the `ensure_*` methods below.
pub const KIND_ROUTING_TABLE: &str = "routing-table";
pub const KIND_MANGLE_CONN_MARK: &str = "mangle-conn-mark";
pub const KIND_MANGLE_ROUTING_MARK: &str = "mangle-routing-mark";
pub const KIND_DEFAULT_ROUTE: &str = "default-route";
pub const KIND_KILL_SWITCH: &str = "kill-switch";
pub const KIND_DNS_DST_NAT: &str = "dns-dst-nat";
pub const KIND_DOT_BLOCK: &str = "dot-block";
pub const KIND_FASTTRACK_BYPASS: &str = "fasttrack-bypass";
pub const KIND_RFC1918_BYPASS: &str = "rfc1918-bypass";
pub const KIND_MSS_CLAMP: &str = "mss-clamp";

/// Build a structured comment of the form `<tag_prefix>;kind=<kind>`.
fn comment_for_kind(tag_prefix: &str, kind: &str) -> String {
    format!("{tag_prefix};kind={kind}")
}

/// Outcome of running [`Provisioner::setup`].
///
/// On success, `failed` is `None` and `applied` lists every step that ran.
/// On failure, the first failing step is recorded in `failed` and `applied`
/// holds every step that completed successfully *before* it; subsequent steps
/// are skipped because they may depend on the failed one.
#[derive(Debug)]
pub struct SetupReport {
    pub applied: Vec<&'static str>,
    pub failed: Option<(&'static str, AppError)>,
}

impl SetupReport {
    fn new() -> Self {
        Self {
            applied: Vec::new(),
            failed: None,
        }
    }
}

/// Where each managed object kind lives in the RouterOS REST tree.
/// Used for the legacy-comment migration sweep at the start of `setup`.
const LEGACY_PATHS: &[&str] = &[
    "/ip/firewall/filter",
    "/ip/firewall/nat",
    "/ip/firewall/mangle",
    "/ip/route",
    "/ip/firewall/address-list",
    "/routing/table",
];

/// Provisions and validates PBR rules on RouterOS.
pub struct Provisioner<'a> {
    client: &'a RouterOsClient,
    config: &'a RouterOsConfig,
}

impl<'a> Provisioner<'a> {
    pub fn new(client: &'a RouterOsClient, config: &'a RouterOsConfig) -> Self {
        Self { client, config }
    }

    /// Create the full PBR setup on RouterOS.
    ///
    /// Idempotent: each step checks for an existing managed object with the
    /// matching `kind=` before creating.  Stops on the first error and
    /// returns a [`SetupReport`] describing how far it got.
    ///
    /// P0-9: if any step fails after earlier steps have already applied managed
    /// objects, the partial layout is rolled back via [`rollback`](Self::rollback)
    /// before returning — a half-applied PBR config (e.g. kill-switch without a
    /// default route) would blackhole the LAN with no auto-recovery. The
    /// returned [`SetupReport`] is unaffected by the rollback.
    pub async fn setup(&self, container_ip: &str) -> SetupReport {
        let tag = &self.config.comment_tag;
        let mut report = SetupReport::new();

        // Migrate legacy (pre-`kind=`) managed objects.  These were created
        // by older versions of snx-edge using a bare `managed-by=snx-edge`
        // comment; the new `ensure_*` methods match on `kind=<kind>` and
        // would otherwise create duplicates next to the legacy entries.
        //
        // Strategy: deletion.  We *know* `setup` will recreate equivalent
        // objects in the loop below, so dropping the legacy ones is safe and
        // simpler than trying to upgrade comments in place (which would need
        // RouterOS PATCH per object).  Failures here are logged and ignored
        // — the migration is best-effort and the worst case is a duplicate
        // the operator can clean up manually.
        if let Err(e) = self.migrate_legacy_objects(tag).await {
            tracing::warn!(error = %e, "legacy managed-object migration failed; continuing");
        }

        // The `step!` macro records each successful step in `report.applied`
        // and, on the first failure, records it in `report.failed` and breaks
        // out of `'steps` (skipping the rest, which may depend on the failed
        // one) so the rollback below can run.
        'steps: {
            macro_rules! step {
                ($name:expr, $expr:expr) => {{
                    match $expr.await {
                        Ok(()) => report.applied.push($name),
                        Err(e) => {
                            tracing::error!(step = $name, error = %e, "PBR setup step failed");
                            report.failed = Some(($name, e));
                            break 'steps;
                        }
                    }
                }};
            }

            step!(KIND_ROUTING_TABLE, self.ensure_routing_table(tag));
            step!(
                KIND_MANGLE_CONN_MARK,
                self.ensure_mangle_connection_mark(tag)
            );
            step!(
                KIND_MANGLE_ROUTING_MARK,
                self.ensure_mangle_routing_mark(tag)
            );
            step!(KIND_MSS_CLAMP, self.ensure_mss_clamp(tag));
            step!(KIND_DEFAULT_ROUTE, self.ensure_vpn_route(container_ip, tag));
            step!(KIND_KILL_SWITCH, self.ensure_killswitch(tag));
            step!(
                KIND_DNS_DST_NAT,
                self.ensure_dns_redirect(container_ip, tag)
            );
            step!(KIND_DOT_BLOCK, self.ensure_dot_block(tag));
            step!(KIND_FASTTRACK_BYPASS, self.ensure_fasttrack_exclusion(tag));
            step!(KIND_RFC1918_BYPASS, self.ensure_default_bypass(tag));

            tracing::info!("PBR setup completed successfully");
        }

        // P0-9: never leave a half-applied PBR layout on the router. On any
        // step failure, roll back ONLY the objects this run created, identified
        // by `report.applied` (the `KIND_*` labels of the steps that succeeded).
        // We deliberately do NOT call `teardown` here: `teardown` matches purely
        // on the bare tag and would also delete operator-managed kinded
        // address-list entries (`kind=vpn-client`, `kind=vpn-corp`, operator
        // `kind=vpn-bypass`). Since `setup` is documented idempotent/re-runnable,
        // a single transient RouterOS 5xx on a re-run would otherwise destroy all
        // operator corp/client subnets (Task 1.2 regression). Operator kinds are
        // never step labels, so they can never appear in `applied` and always
        // survive. The rollback never mutates `report`, so the caller still sees
        // how far setup got and which step failed.
        if report.failed.is_some() {
            tracing::warn!(
                failed = ?report.failed,
                "PBR setup failed mid-way; rolling back applied objects"
            );
            if let Err(e) = self.rollback(&report.applied).await {
                tracing::error!(
                    error = %e,
                    "rollback failed; manual cleanup may be required"
                );
            }
        }

        report
    }

    /// Remove all managed rules from RouterOS.
    pub async fn teardown(&self) -> Result<usize, AppError> {
        let mut total = 0;

        // Order matters: remove dependent rules first
        total += self.client.delete_managed("/ip/firewall/filter").await?;
        total += self.client.delete_managed("/ip/firewall/nat").await?;
        total += self.client.delete_managed("/ip/firewall/mangle").await?;
        total += self.client.delete_managed("/ip/route").await?;
        total += self
            .client
            .delete_managed("/ip/firewall/address-list")
            .await?;
        total += self.client.delete_managed("/routing/table").await?;

        tracing::info!("PBR teardown completed: {total} rules removed");
        Ok(total)
    }

    /// Roll back **only** the managed objects this `setup` run created.
    ///
    /// Mirrors [`teardown`](Self::teardown)'s per-path structure and order
    /// (dependents first) so a partially applied layout unwinds in the reverse
    /// of how it was built. The crucial difference: `teardown` deletes anything
    /// carrying the bare tag, whereas this deletes an object only when its
    /// comment carries one of `applied_kinds` — the `KIND_*` step labels recorded
    /// in [`SetupReport::applied`].
    ///
    /// This is what keeps operator-managed kinded address-list entries safe:
    /// `kind=vpn-client` / `kind=vpn-corp` / operator `kind=vpn-bypass` are never
    /// `setup` steps, so they can never appear in `applied` and are therefore
    /// never rolled back. (`kind=rfc1918-bypass` IS a setup step, so rolling it
    /// back when this run created it is correct.)
    async fn rollback(&self, applied_kinds: &[&str]) -> Result<usize, AppError> {
        let mut total = 0;

        // Same order as `teardown`: remove dependent rules first.
        for path in [
            "/ip/firewall/filter",
            "/ip/firewall/nat",
            "/ip/firewall/mangle",
            "/ip/route",
            "/ip/firewall/address-list",
            "/routing/table",
        ] {
            total += self.delete_applied(path, applied_kinds).await?;
        }

        tracing::info!("PBR rollback completed: {total} objects removed");
        Ok(total)
    }

    /// Delete every object at `path` whose comment matches our tag **and** one
    /// of `kinds`. The kinded-comment counterpart of
    /// [`RouterOsClient::delete_managed`](crate::routeros::client::RouterOsClient::delete_managed),
    /// which matches the tag alone.
    async fn delete_applied(&self, path: &str, kinds: &[&str]) -> Result<usize, AppError> {
        #[derive(serde::Deserialize)]
        struct IdEntry {
            #[serde(rename = ".id")]
            id: String,
            #[serde(default)]
            comment: Option<String>,
        }

        let tag = &self.config.comment_tag;
        let all: Vec<IdEntry> = self.client.list(path).await?;
        let mut count = 0;
        for entry in all {
            let matches = entry
                .comment
                .as_deref()
                .map(|c| kinds.iter().any(|k| comment_matches_kind(c, tag, k)))
                .unwrap_or(false);
            if matches {
                self.client.delete(path, &entry.id).await?;
                count += 1;
            }
        }
        Ok(count)
    }

    /// Sweep for objects carrying the bare legacy `managed-by=...` comment
    /// (no `;kind=` field) and remove them, so the new `ensure_*` methods
    /// don't create duplicates next to them.
    async fn migrate_legacy_objects(&self, _tag: &str) -> Result<(), AppError> {
        let mut total = 0usize;
        for path in LEGACY_PATHS {
            let ids = self.client.list_legacy_managed(path).await?;
            for id in &ids {
                self.client.delete(path, id).await?;
            }
            total += ids.len();
        }
        if total > 0 {
            tracing::info!(
                count = total,
                "removed legacy managed objects (pre `kind=` migration)"
            );
        }
        Ok(())
    }

    /// Run diagnostics on the current RouterOS configuration.
    pub async fn diagnostics(&self) -> Result<DiagnosticsResult, AppError> {
        let mut warnings = Vec::new();

        // Check routing table
        let tables: Vec<RoutingTable> = self.client.list("/routing/table").await?;
        let routing_table_exists = tables.iter().any(|t| t.name == self.config.routing_table);
        if !routing_table_exists {
            warnings.push(format!(
                "routing table '{}' not found",
                self.config.routing_table
            ));
        }

        // Check mangle rules
        let mangles: Vec<MangleRule> = self.client.list_managed("/ip/firewall/mangle").await?;
        let mangle_rules_count = mangles.len();
        let mangle_rules_present = mangle_rules_count >= 3;
        if !mangle_rules_present {
            warnings.push(format!(
                "expected 3 mangle rules, found {mangle_rules_count}"
            ));
        }
        let mss_clamp = mangles.iter().any(|m| {
            m.comment
                .as_deref()
                .map(|c| comment_matches_kind(c, &self.config.comment_tag, KIND_MSS_CLAMP))
                .unwrap_or(false)
        });

        // Check routes
        let routes: Vec<RouteEntry> = self.client.list_managed("/ip/route").await?;
        let vpn_route_active = routes.iter().any(|r| {
            r.routing_table.as_deref() == Some(&self.config.routing_table) && r.route_type.is_none()
        });
        let killswitch_present = routes
            .iter()
            .any(|r| r.route_type.as_deref() == Some("blackhole"));

        if !vpn_route_active {
            warnings.push("VPN gateway route not found".to_string());
        }
        if !killswitch_present {
            warnings.push("kill switch (blackhole route) not found".to_string());
        }

        // Check NAT (DNS redirect)
        let nats: Vec<NatRule> = self.client.list_managed("/ip/firewall/nat").await?;
        let dns_redirect_active = nats.iter().any(|r| r.dst_port.as_deref() == Some("53"));

        // Check filter (FastTrack)
        let filters: Vec<FilterRule> = self.client.list_managed("/ip/firewall/filter").await?;
        let fasttrack_configured = filters.iter().any(|r| r.action == "fasttrack-connection");

        // Gateway reachability (simplified — just check route exists)
        let gateway_reachable = vpn_route_active;

        // Address lists counts
        let vpn_clients = self
            .client
            .list_address_list(&self.config.address_list_vpn)
            .await?;
        let vpn_bypass = self
            .client
            .list_address_list(&self.config.address_list_bypass)
            .await?;

        let status = if warnings.is_empty() {
            "healthy"
        } else {
            "degraded"
        }
        .to_string();

        Ok(DiagnosticsResult {
            status,
            checks: DiagnosticsChecks {
                routing_table_exists,
                mangle_rules_present,
                mangle_rules_count,
                mss_clamp,
                vpn_route_active,
                killswitch_present,
                dns_redirect_active,
                fasttrack_configured,
                gateway_reachable,
                vpn_clients_count: vpn_clients.len(),
                vpn_bypass_count: vpn_bypass.len(),
            },
            warnings,
        })
    }

    /// Snapshot of which expected managed objects are currently present.
    ///
    /// Used by `/api/v1/routing/status` to derive a coarse `configured /
    /// partial / absent` state without running the full diagnostics path.
    pub async fn presence_snapshot(&self) -> Result<PresenceSnapshot, AppError> {
        let tag = &self.config.comment_tag;

        let tables: Vec<RoutingTable> = self.client.list("/routing/table").await?;
        let mangles: Vec<MangleRule> = self.client.list("/ip/firewall/mangle").await?;
        let routes: Vec<RouteEntry> = self.client.list("/ip/route").await?;
        let nats: Vec<NatRule> = self.client.list("/ip/firewall/nat").await?;
        let filters: Vec<FilterRule> = self.client.list("/ip/firewall/filter").await?;
        let bypass = self
            .client
            .list_address_list(&self.config.address_list_bypass)
            .await?;

        let routing_table = tables.iter().any(|t| {
            t.name == self.config.routing_table
                && t.comment
                    .as_deref()
                    .map(|c| comment_matches_kind(c, tag, KIND_ROUTING_TABLE))
                    .unwrap_or(false)
        });
        let mangle_conn_mark = mangles.iter().any(|m| {
            m.comment
                .as_deref()
                .map(|c| comment_matches_kind(c, tag, KIND_MANGLE_CONN_MARK))
                .unwrap_or(false)
        });
        let mangle_routing_mark = mangles.iter().any(|m| {
            m.comment
                .as_deref()
                .map(|c| comment_matches_kind(c, tag, KIND_MANGLE_ROUTING_MARK))
                .unwrap_or(false)
        });
        let mss_clamp = mangles.iter().any(|m| {
            m.comment
                .as_deref()
                .map(|c| comment_matches_kind(c, tag, KIND_MSS_CLAMP))
                .unwrap_or(false)
        });
        let default_route = routes.iter().any(|r| {
            r.comment
                .as_deref()
                .map(|c| comment_matches_kind(c, tag, KIND_DEFAULT_ROUTE))
                .unwrap_or(false)
        });
        let kill_switch = routes.iter().any(|r| {
            r.comment
                .as_deref()
                .map(|c| comment_matches_kind(c, tag, KIND_KILL_SWITCH))
                .unwrap_or(false)
        });
        let dns_dst_nat = nats.iter().any(|r| {
            r.comment
                .as_deref()
                .map(|c| comment_matches_kind(c, tag, KIND_DNS_DST_NAT))
                .unwrap_or(false)
        });
        let dot_block = filters.iter().any(|r| {
            r.comment
                .as_deref()
                .map(|c| comment_matches_kind(c, tag, KIND_DOT_BLOCK))
                .unwrap_or(false)
        });
        let fasttrack_bypass = filters.iter().any(|r| {
            r.comment
                .as_deref()
                .map(|c| comment_matches_kind(c, tag, KIND_FASTTRACK_BYPASS))
                .unwrap_or(false)
        });
        let rfc1918_bypass = bypass.iter().any(|e| {
            e.comment
                .as_deref()
                .map(|c| comment_matches_kind(c, tag, KIND_RFC1918_BYPASS))
                .unwrap_or(false)
        });

        Ok(PresenceSnapshot {
            routing_table,
            mangle_conn_mark,
            mangle_routing_mark,
            mss_clamp,
            default_route,
            kill_switch,
            dns_dst_nat,
            dot_block,
            fasttrack_bypass,
            rfc1918_bypass,
        })
    }

    // === Reconciler-facing default-route control ===

    /// Ensure the distance-1 default route through the container exists.
    ///
    /// Idempotent wrapper over [`ensure_vpn_route`](Self::ensure_vpn_route);
    /// called by the reconciler when the tunnel comes up so corp traffic has a
    /// live next hop into the container alongside the always-present blackhole.
    pub async fn set_default_route_present(&self, gateway: &str) -> Result<(), AppError> {
        self.ensure_vpn_route(gateway, &self.config.comment_tag)
            .await
    }

    /// Remove the managed distance-1 default route, leaving only the blackhole
    /// (fail-closed). Called by the reconciler when the tunnel goes down.
    ///
    /// Matches on the structured `kind=default-route` comment so the blackhole
    /// (`kind=kill-switch`) and any other managed routes are left untouched.
    pub async fn clear_default_route(&self) -> Result<(), AppError> {
        let tag = &self.config.comment_tag;
        let routes: Vec<RouteEntry> = self.client.list_managed("/ip/route").await?;
        for r in routes.iter().filter(|r| {
            r.comment
                .as_deref()
                .map(|c| comment_matches_kind(c, tag, KIND_DEFAULT_ROUTE))
                .unwrap_or(false)
        }) {
            self.client.delete("/ip/route", &r.id).await?;
        }
        Ok(())
    }

    // === Private helpers for idempotent rule creation ===

    async fn ensure_routing_table(&self, tag: &str) -> Result<(), AppError> {
        let tables: Vec<RoutingTable> = self.client.list("/routing/table").await?;
        if tables.iter().any(|t| {
            t.name == self.config.routing_table
                && t.comment
                    .as_deref()
                    .map(|c| comment_matches_kind(c, tag, KIND_ROUTING_TABLE))
                    .unwrap_or(false)
        }) {
            return Ok(());
        }
        // Also accept an existing routing table with the same name but no
        // managed comment (e.g. user-created) — don't try to recreate it.
        if tables.iter().any(|t| t.name == self.config.routing_table) {
            return Ok(());
        }
        let body = serde_json::json!({
            "name": self.config.routing_table,
            "fib": "",
            "comment": comment_for_kind(tag, KIND_ROUTING_TABLE),
        });
        let _: serde_json::Value = self.client.create("/routing/table", &body).await?;
        Ok(())
    }

    async fn ensure_mangle_connection_mark(&self, tag: &str) -> Result<(), AppError> {
        let existing: Vec<MangleRule> = self.client.list_managed("/ip/firewall/mangle").await?;
        if existing.iter().any(|m| {
            m.comment
                .as_deref()
                .map(|c| comment_matches_kind(c, tag, KIND_MANGLE_CONN_MARK))
                .unwrap_or(false)
        }) {
            return Ok(());
        }
        // Split-tunnel: mark only connections whose source is a VPN client
        // *and* whose destination is in the operator-supplied corp address
        // list. This is a positive match — unlike the old full-tunnel logic
        // that marked everything except the RFC1918 bypass list — so only
        // corp subnets are steered into the tunnel; all other traffic keeps
        // its normal main-table route.
        let body = serde_json::json!({
            "chain": "prerouting",
            "src-address-list": self.config.address_list_vpn,
            "dst-address-list": self.config.address_list_corp,
            "connection-state": "new",
            "action": "mark-connection",
            "new-connection-mark": self.config.connection_mark,
            "passthrough": "yes",
            "comment": comment_for_kind(tag, KIND_MANGLE_CONN_MARK),
        });
        let _: serde_json::Value = self.client.create("/ip/firewall/mangle", &body).await?;
        Ok(())
    }

    /// Clamp the TCP MSS of marked (corp-bound) connections to the path MTU.
    ///
    /// P0-8: the Check Point tunnel MTU (~1350) is well below the LAN's 1500,
    /// so without this clamp large packets toward corp hosts depend on PMTUD,
    /// which routinely blackholes when ICMP "fragmentation needed" is filtered.
    /// Rewriting the SYN MSS to `clamp-to-pmtu` makes both ends negotiate a
    /// safe segment size up-front. Scoped to the VPN connection-mark so only
    /// tunnelled corp traffic is touched.
    async fn ensure_mss_clamp(&self, tag: &str) -> Result<(), AppError> {
        let existing: Vec<MangleRule> = self.client.list_managed("/ip/firewall/mangle").await?;
        if existing.iter().any(|m| {
            m.comment
                .as_deref()
                .map(|c| comment_matches_kind(c, tag, KIND_MSS_CLAMP))
                .unwrap_or(false)
        }) {
            return Ok(());
        }
        let body = serde_json::json!({
            "chain": "forward",
            "connection-mark": self.config.connection_mark,
            "protocol": "tcp",
            "tcp-flags": "syn",
            "action": "change-mss",
            "new-mss": "clamp-to-pmtu",
            "passthrough": "yes",
            "comment": comment_for_kind(tag, KIND_MSS_CLAMP),
        });
        let _: serde_json::Value = self.client.create("/ip/firewall/mangle", &body).await?;
        Ok(())
    }

    async fn ensure_mangle_routing_mark(&self, tag: &str) -> Result<(), AppError> {
        let existing: Vec<MangleRule> = self.client.list_managed("/ip/firewall/mangle").await?;
        if existing.iter().any(|m| {
            m.comment
                .as_deref()
                .map(|c| comment_matches_kind(c, tag, KIND_MANGLE_ROUTING_MARK))
                .unwrap_or(false)
        }) {
            return Ok(());
        }
        let body = serde_json::json!({
            "chain": "prerouting",
            "connection-mark": self.config.connection_mark,
            "action": "mark-routing",
            "new-routing-mark": self.config.routing_mark,
            "passthrough": "no",
            "comment": comment_for_kind(tag, KIND_MANGLE_ROUTING_MARK),
        });
        let _: serde_json::Value = self.client.create("/ip/firewall/mangle", &body).await?;
        Ok(())
    }

    async fn ensure_vpn_route(&self, gateway: &str, tag: &str) -> Result<(), AppError> {
        let existing: Vec<RouteEntry> = self.client.list_managed("/ip/route").await?;
        if existing.iter().any(|r| {
            r.comment
                .as_deref()
                .map(|c| comment_matches_kind(c, tag, KIND_DEFAULT_ROUTE))
                .unwrap_or(false)
        }) {
            return Ok(());
        }
        let body = serde_json::json!({
            "dst-address": "0.0.0.0/0",
            "gateway": gateway,
            "routing-table": self.config.routing_table,
            "check-gateway": "ping",
            "distance": "1",
            "comment": comment_for_kind(tag, KIND_DEFAULT_ROUTE),
        });
        let _: serde_json::Value = self.client.create("/ip/route", &body).await?;
        Ok(())
    }

    async fn ensure_killswitch(&self, tag: &str) -> Result<(), AppError> {
        let existing: Vec<RouteEntry> = self.client.list_managed("/ip/route").await?;
        if existing.iter().any(|r| {
            r.comment
                .as_deref()
                .map(|c| comment_matches_kind(c, tag, KIND_KILL_SWITCH))
                .unwrap_or(false)
        }) {
            return Ok(());
        }
        let body = serde_json::json!({
            "dst-address": "0.0.0.0/0",
            "type": "blackhole",
            "routing-table": self.config.routing_table,
            "distance": "254",
            "comment": comment_for_kind(tag, KIND_KILL_SWITCH),
        });
        let _: serde_json::Value = self.client.create("/ip/route", &body).await?;
        Ok(())
    }

    async fn ensure_dns_redirect(&self, container_ip: &str, tag: &str) -> Result<(), AppError> {
        let existing: Vec<NatRule> = self.client.list_managed("/ip/firewall/nat").await?;
        for proto in ["udp", "tcp"] {
            if existing.iter().any(|r| {
                r.protocol.as_deref() == Some(proto)
                    && r.comment
                        .as_deref()
                        .map(|c| comment_matches_kind(c, tag, KIND_DNS_DST_NAT))
                        .unwrap_or(false)
            }) {
                continue;
            }
            let body = serde_json::json!({
                "chain": "dstnat",
                "src-address-list": self.config.address_list_vpn,
                "dst-port": "53",
                "protocol": proto,
                "action": "dst-nat",
                "to-addresses": container_ip,
                "comment": comment_for_kind(tag, KIND_DNS_DST_NAT),
            });
            let _: serde_json::Value = self.client.create("/ip/firewall/nat", &body).await?;
        }
        Ok(())
    }

    async fn ensure_dot_block(&self, tag: &str) -> Result<(), AppError> {
        // Block DNS-over-TLS so VPN clients can't bypass the container's
        // split-DNS forwarder over an encrypted channel. Drop both tcp/853
        // (classic DoT) and udp/853 (DoT-over-QUIC / DoQ). RouterOS filter rules
        // are single-protocol, so this is two rules — each checked-before-create
        // by its DoT-block kind tag *and* protocol to stay idempotent.
        //
        // P2 (documented, intentionally NOT done here): full DoH on tcp/443
        // cannot be dropped wholesale without breaking all HTTPS. Selectively
        // dropping known public DoH resolver IPs is left as a future task.
        let existing: Vec<FilterRule> = self.client.list_managed("/ip/firewall/filter").await?;
        for proto in ["tcp", "udp"] {
            let already = existing.iter().any(|r| {
                r.comment
                    .as_deref()
                    .map(|c| comment_matches_kind(c, tag, KIND_DOT_BLOCK))
                    .unwrap_or(false)
                    && r.protocol.as_deref() == Some(proto)
            });
            if already {
                continue;
            }
            let body = serde_json::json!({
                "chain": "forward",
                "src-address-list": self.config.address_list_vpn,
                "dst-port": "853",
                "protocol": proto,
                "action": "drop",
                "comment": comment_for_kind(tag, KIND_DOT_BLOCK),
            });
            let _: serde_json::Value = self.client.create("/ip/firewall/filter", &body).await?;
        }
        Ok(())
    }

    async fn ensure_fasttrack_exclusion(&self, tag: &str) -> Result<(), AppError> {
        let existing: Vec<FilterRule> = self.client.list_managed("/ip/firewall/filter").await?;
        if existing.iter().any(|r| {
            r.comment
                .as_deref()
                .map(|c| comment_matches_kind(c, tag, KIND_FASTTRACK_BYPASS))
                .unwrap_or(false)
        }) {
            return Ok(());
        }
        let body = serde_json::json!({
            "chain": "forward",
            "action": "fasttrack-connection",
            "connection-state": "established,related",
            "connection-mark": "no-mark",
            "comment": comment_for_kind(tag, KIND_FASTTRACK_BYPASS),
        });
        let _: serde_json::Value = self.client.create("/ip/firewall/filter", &body).await?;
        Ok(())
    }

    async fn ensure_default_bypass(&self, tag: &str) -> Result<(), AppError> {
        // Under split-tunnel the connection-mark rule now positively matches
        // the corp dst-list, so this RFC1918 bypass list no longer influences
        // which traffic is marked. It is kept as defensive belt-and-suspenders
        // (e.g. operators may reference it elsewhere) but is effectively inert
        // for marking purposes.
        let existing = self
            .client
            .list_address_list(&self.config.address_list_bypass)
            .await?;

        let defaults = ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"];
        for addr in defaults {
            if existing.iter().any(|e| e.address == addr) {
                continue;
            }
            let body = serde_json::json!({
                "list": self.config.address_list_bypass,
                "address": addr,
                "comment": comment_for_kind(tag, KIND_RFC1918_BYPASS),
            });
            let _: serde_json::Value = self
                .client
                .create("/ip/firewall/address-list", &body)
                .await?;
        }
        Ok(())
    }
}

/// Per-kind presence flags returned by [`Provisioner::presence_snapshot`].
#[derive(Debug, Clone)]
pub struct PresenceSnapshot {
    pub routing_table: bool,
    pub mangle_conn_mark: bool,
    pub mangle_routing_mark: bool,
    pub mss_clamp: bool,
    pub default_route: bool,
    pub kill_switch: bool,
    pub dns_dst_nat: bool,
    pub dot_block: bool,
    pub fasttrack_bypass: bool,
    pub rfc1918_bypass: bool,
}

impl PresenceSnapshot {
    /// Total expected managed-object kinds.
    pub const EXPECTED: usize = 10;

    /// Number of expected kinds currently present.
    pub fn present_count(&self) -> usize {
        [
            self.routing_table,
            self.mangle_conn_mark,
            self.mangle_routing_mark,
            self.mss_clamp,
            self.default_route,
            self.kill_switch,
            self.dns_dst_nat,
            self.dot_block,
            self.fasttrack_bypass,
            self.rfc1918_bypass,
        ]
        .into_iter()
        .filter(|b| *b)
        .count()
    }

    /// Coarse "configured" / "partial" / "absent" label.
    pub fn state(&self) -> &'static str {
        match self.present_count() {
            n if n == Self::EXPECTED => "configured",
            0 => "absent",
            _ => "partial",
        }
    }
}
