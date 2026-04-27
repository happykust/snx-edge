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

        macro_rules! step {
            ($name:expr, $expr:expr) => {{
                match $expr.await {
                    Ok(()) => report.applied.push($name),
                    Err(e) => {
                        tracing::error!(step = $name, error = %e, "PBR setup step failed");
                        report.failed = Some(($name, e));
                        return report;
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
        let mangle_rules_present = mangle_rules_count >= 2;
        if !mangle_rules_present {
            warnings.push(format!(
                "expected 2 mangle rules, found {mangle_rules_count}"
            ));
        }

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
            default_route,
            kill_switch,
            dns_dst_nat,
            dot_block,
            fasttrack_bypass,
            rfc1918_bypass,
        })
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
        let body = serde_json::json!({
            "chain": "prerouting",
            "src-address-list": self.config.address_list_vpn,
            "dst-address-list": format!("!{}", self.config.address_list_bypass),
            "connection-state": "new",
            "action": "mark-connection",
            "new-connection-mark": self.config.connection_mark,
            "passthrough": "yes",
            "comment": comment_for_kind(tag, KIND_MANGLE_CONN_MARK),
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
        let existing: Vec<FilterRule> = self.client.list_managed("/ip/firewall/filter").await?;
        if existing.iter().any(|r| {
            r.comment
                .as_deref()
                .map(|c| comment_matches_kind(c, tag, KIND_DOT_BLOCK))
                .unwrap_or(false)
        }) {
            return Ok(());
        }
        let body = serde_json::json!({
            "chain": "forward",
            "src-address-list": self.config.address_list_vpn,
            "dst-port": "853",
            "protocol": "tcp",
            "action": "drop",
            "comment": comment_for_kind(tag, KIND_DOT_BLOCK),
        });
        let _: serde_json::Value = self.client.create("/ip/firewall/filter", &body).await?;
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
    pub default_route: bool,
    pub kill_switch: bool,
    pub dns_dst_nat: bool,
    pub dot_block: bool,
    pub fasttrack_bypass: bool,
    pub rfc1918_bypass: bool,
}

impl PresenceSnapshot {
    /// Total expected managed-object kinds.
    pub const EXPECTED: usize = 9;

    /// Number of expected kinds currently present.
    pub fn present_count(&self) -> usize {
        [
            self.routing_table,
            self.mangle_conn_mark,
            self.mangle_routing_mark,
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
