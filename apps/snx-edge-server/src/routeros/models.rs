use serde::{Deserialize, Serialize};

/// RouterOS address-list entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressListEntry {
    #[serde(rename = ".id", default)]
    pub id: String,
    pub list: String,
    pub address: String,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub disabled: Option<String>,
    #[serde(rename = "creation-time", default)]
    pub creation_time: Option<String>,
}

/// RouterOS mangle rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MangleRule {
    #[serde(rename = ".id", default)]
    pub id: String,
    #[serde(default)]
    pub chain: String,
    #[serde(default)]
    pub action: String,
    #[serde(rename = "src-address-list", default)]
    pub src_address_list: Option<String>,
    #[serde(rename = "dst-address-list", default)]
    pub dst_address_list: Option<String>,
    #[serde(rename = "connection-state", default)]
    pub connection_state: Option<String>,
    #[serde(rename = "connection-mark", default)]
    pub connection_mark: Option<String>,
    #[serde(rename = "new-connection-mark", default)]
    pub new_connection_mark: Option<String>,
    #[serde(rename = "new-routing-mark", default)]
    pub new_routing_mark: Option<String>,
    #[serde(default)]
    pub passthrough: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
}

/// RouterOS route entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    #[serde(rename = ".id", default)]
    pub id: String,
    #[serde(rename = "dst-address", default)]
    pub dst_address: String,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(rename = "routing-table", default)]
    pub routing_table: Option<String>,
    #[serde(default)]
    pub distance: Option<String>,
    #[serde(rename = "check-gateway", default)]
    pub check_gateway: Option<String>,
    #[serde(rename = "type", default)]
    pub route_type: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
}

/// RouterOS NAT rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatRule {
    #[serde(rename = ".id", default)]
    pub id: String,
    #[serde(default)]
    pub chain: String,
    #[serde(default)]
    pub action: String,
    #[serde(rename = "src-address-list", default)]
    pub src_address_list: Option<String>,
    #[serde(rename = "dst-port", default)]
    pub dst_port: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
}

/// RouterOS filter rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterRule {
    #[serde(rename = ".id", default)]
    pub id: String,
    #[serde(default)]
    pub chain: String,
    #[serde(default)]
    pub action: String,
    #[serde(rename = "src-address-list", default)]
    pub src_address_list: Option<String>,
    #[serde(rename = "dst-port", default)]
    pub dst_port: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(rename = "connection-state", default)]
    pub connection_state: Option<String>,
    #[serde(rename = "connection-mark", default)]
    pub connection_mark: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
}

/// RouterOS routing table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingTable {
    #[serde(rename = ".id", default)]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub fib: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
}

/// Diagnostics result.
#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticsResult {
    pub status: String,
    pub checks: DiagnosticsChecks,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticsChecks {
    pub routing_table_exists: bool,
    pub mangle_rules_present: bool,
    pub mangle_rules_count: usize,
    pub vpn_route_active: bool,
    pub killswitch_present: bool,
    pub dns_redirect_active: bool,
    pub fasttrack_configured: bool,
    pub gateway_reachable: bool,
    pub vpn_clients_count: usize,
    pub vpn_bypass_count: usize,
}
