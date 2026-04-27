//! RouterOS REST DTOs.
//!
//! These shapes match the JSON returned by RouterOS's REST API. The same
//! types are re-exported from `snx-edge-types::routing` so clients can
//! deserialise responses without redefining them.

pub use snx_edge_types::routing::{
    AddressListEntry, DiagnosticsChecks, DiagnosticsResult, FilterRule, MangleRule, NatRule,
    RouteEntry, RoutingTable,
};
