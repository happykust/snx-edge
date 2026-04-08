use crate::config::RouterOsConfig;
use crate::error::AppError;
use crate::routeros::client::RouterOsClient;
use crate::routeros::models::*;

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
    /// Idempotent: checks for existing managed rules before creating.
    pub async fn setup(&self, container_ip: &str) -> Result<(), AppError> {
        let tag = &self.config.comment_tag;

        // 1. Routing table
        self.ensure_routing_table(tag).await?;

        // 2. Mangle: mark connections from vpn-clients
        self.ensure_mangle_connection_mark(tag).await?;

        // 3. Mangle: mark routing for marked connections
        self.ensure_mangle_routing_mark(tag).await?;

        // 4. Route: default via container in vpn-route table
        self.ensure_vpn_route(container_ip, tag).await?;

        // 5. Kill switch: blackhole route
        self.ensure_killswitch(tag).await?;

        // 6. DNS dst-nat for vpn-clients (UDP + TCP) → container
        self.ensure_dns_redirect(container_ip, tag).await?;

        // 7. Block DoT port 853
        self.ensure_dot_block(tag).await?;

        // 8. FastTrack exclusion for marked connections
        self.ensure_fasttrack_exclusion(tag).await?;

        // 9. Default vpn-bypass entries (RFC1918)
        self.ensure_default_bypass(tag).await?;

        tracing::info!("PBR setup completed successfully");
        Ok(())
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

    // === Private helpers for idempotent rule creation ===

    async fn ensure_routing_table(&self, tag: &str) -> Result<(), AppError> {
        let tables: Vec<RoutingTable> = self.client.list("/routing/table").await?;
        if tables.iter().any(|t| t.name == self.config.routing_table) {
            return Ok(());
        }
        let body = serde_json::json!({
            "name": self.config.routing_table,
            "fib": "",
            "comment": tag,
        });
        let _: serde_json::Value = self.client.create("/routing/table", &body).await?;
        Ok(())
    }

    async fn ensure_mangle_connection_mark(&self, tag: &str) -> Result<(), AppError> {
        let existing: Vec<MangleRule> = self.client.list_managed("/ip/firewall/mangle").await?;
        if existing
            .iter()
            .any(|m| m.new_connection_mark.as_deref() == Some(&self.config.connection_mark))
        {
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
            "comment": tag,
        });
        let _: serde_json::Value = self.client.create("/ip/firewall/mangle", &body).await?;
        Ok(())
    }

    async fn ensure_mangle_routing_mark(&self, tag: &str) -> Result<(), AppError> {
        let existing: Vec<MangleRule> = self.client.list_managed("/ip/firewall/mangle").await?;
        if existing
            .iter()
            .any(|m| m.new_routing_mark.as_deref() == Some(&self.config.routing_mark))
        {
            return Ok(());
        }
        let body = serde_json::json!({
            "chain": "prerouting",
            "connection-mark": self.config.connection_mark,
            "action": "mark-routing",
            "new-routing-mark": self.config.routing_mark,
            "passthrough": "no",
            "comment": tag,
        });
        let _: serde_json::Value = self.client.create("/ip/firewall/mangle", &body).await?;
        Ok(())
    }

    async fn ensure_vpn_route(&self, gateway: &str, tag: &str) -> Result<(), AppError> {
        let existing: Vec<RouteEntry> = self.client.list_managed("/ip/route").await?;
        if existing.iter().any(|r| {
            r.routing_table.as_deref() == Some(&self.config.routing_table)
                && r.route_type.is_none()
                && r.gateway.is_some()
        }) {
            return Ok(());
        }
        let body = serde_json::json!({
            "dst-address": "0.0.0.0/0",
            "gateway": gateway,
            "routing-table": self.config.routing_table,
            "check-gateway": "ping",
            "distance": "1",
            "comment": tag,
        });
        let _: serde_json::Value = self.client.create("/ip/route", &body).await?;
        Ok(())
    }

    async fn ensure_killswitch(&self, tag: &str) -> Result<(), AppError> {
        let existing: Vec<RouteEntry> = self.client.list_managed("/ip/route").await?;
        if existing
            .iter()
            .any(|r| r.route_type.as_deref() == Some("blackhole"))
        {
            return Ok(());
        }
        let body = serde_json::json!({
            "dst-address": "0.0.0.0/0",
            "type": "blackhole",
            "routing-table": self.config.routing_table,
            "distance": "254",
            "comment": tag,
        });
        let _: serde_json::Value = self.client.create("/ip/route", &body).await?;
        Ok(())
    }

    async fn ensure_dns_redirect(&self, container_ip: &str, tag: &str) -> Result<(), AppError> {
        let existing: Vec<NatRule> = self.client.list_managed("/ip/firewall/nat").await?;
        for proto in ["udp", "tcp"] {
            if existing.iter().any(|r| {
                r.dst_port.as_deref() == Some("53") && r.protocol.as_deref() == Some(proto)
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
                "comment": tag,
            });
            let _: serde_json::Value = self.client.create("/ip/firewall/nat", &body).await?;
        }
        Ok(())
    }

    async fn ensure_dot_block(&self, tag: &str) -> Result<(), AppError> {
        let existing: Vec<FilterRule> = self.client.list_managed("/ip/firewall/filter").await?;
        if existing
            .iter()
            .any(|r| r.dst_port.as_deref() == Some("853"))
        {
            return Ok(());
        }
        let body = serde_json::json!({
            "chain": "forward",
            "src-address-list": self.config.address_list_vpn,
            "dst-port": "853",
            "protocol": "tcp",
            "action": "drop",
            "comment": tag,
        });
        let _: serde_json::Value = self.client.create("/ip/firewall/filter", &body).await?;
        Ok(())
    }

    async fn ensure_fasttrack_exclusion(&self, tag: &str) -> Result<(), AppError> {
        let existing: Vec<FilterRule> = self.client.list_managed("/ip/firewall/filter").await?;
        if existing.iter().any(|r| r.action == "fasttrack-connection") {
            return Ok(());
        }
        let body = serde_json::json!({
            "chain": "forward",
            "action": "fasttrack-connection",
            "connection-state": "established,related",
            "connection-mark": "no-mark",
            "comment": tag,
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
                "comment": tag,
            });
            let _: serde_json::Value = self
                .client
                .create("/ip/firewall/address-list", &body)
                .await?;
        }
        Ok(())
    }
}
