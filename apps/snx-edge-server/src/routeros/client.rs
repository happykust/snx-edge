use reqwest::Client;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::config::RouterOsConfig;
use crate::error::AppError;

/// HTTP client for RouterOS REST API.
///
/// RouterOS 7.1+ exposes REST at `https://<host>/rest/`.
/// Authentication is HTTP Basic Auth.
///
/// Cloning is cheap — `reqwest::Client` is internally `Arc`-based and the
/// remaining fields are short strings. The cache in `AppState` clones the
/// stored value on every lookup.
#[derive(Clone)]
pub struct RouterOsClient {
    client: Client,
    base_url: String,
    username: String,
    password: String,
    pub comment_tag: String,
}

impl RouterOsClient {
    pub fn new(config: &RouterOsConfig) -> Result<Self, AppError> {
        let host = std::env::var(&config.host_env)
            .map_err(|_| AppError::Internal(format!("env {} not set", config.host_env)))?;
        let username = std::env::var(&config.user_env)
            .map_err(|_| AppError::Internal(format!("env {} not set", config.user_env)))?;
        let password = std::env::var(&config.password_env)
            .map_err(|_| AppError::Internal(format!("env {} not set", config.password_env)))?;

        let client = Client::builder()
            .danger_accept_invalid_certs(config.tls_skip_verify)
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| AppError::Internal(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            client,
            base_url: format!("https://{host}/rest"),
            username,
            password,
            comment_tag: config.comment_tag.clone(),
        })
    }

    /// Test-only constructor that takes the base URL, credentials and
    /// `comment_tag` directly instead of resolving them from environment
    /// variables. Used by integration tests that point the client at a
    /// `wiremock::MockServer` URL.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn for_tests(
        base_url: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        comment_tag: impl Into<String>,
    ) -> Self {
        Self {
            client: Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .expect("test client build"),
            base_url: base_url.into(),
            username: username.into(),
            password: password.into(),
            comment_tag: comment_tag.into(),
        }
    }

    /// Variant of [`for_tests`] visible to integration tests living under
    /// `tests/`. Behaves identically; only `cfg` gating differs. The
    /// production binary never calls this constructor — `#[allow(dead_code)]`
    /// silences the unused-function warning that would otherwise fire when
    /// the binary target is compiled without `cfg(test)`.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn for_integration_tests(
        base_url: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        comment_tag: impl Into<String>,
    ) -> Self {
        Self {
            client: Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .expect("test client build"),
            base_url: base_url.into(),
            username: username.into(),
            password: password.into(),
            comment_tag: comment_tag.into(),
        }
    }

    /// GET a list of resources.
    pub async fn list<T: DeserializeOwned>(&self, path: &str) -> Result<Vec<T>, AppError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .get(&url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await
            .map_err(|e| AppError::BadGateway(format!("RouterOS unreachable: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::BadGateway(format!(
                "RouterOS returned {status}: {body}"
            )));
        }

        resp.json()
            .await
            .map_err(|e| AppError::Internal(format!("failed to parse RouterOS response: {e}")))
    }

    /// PUT — create a new resource (RouterOS uses PUT for creation).
    pub async fn create<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, AppError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .put(&url)
            .basic_auth(&self.username, Some(&self.password))
            .json(body)
            .send()
            .await
            .map_err(|e| AppError::BadGateway(format!("RouterOS unreachable: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::BadGateway(format!(
                "RouterOS returned {status}: {body}"
            )));
        }

        resp.json()
            .await
            .map_err(|e| AppError::Internal(format!("failed to parse RouterOS response: {e}")))
    }

    /// DELETE a resource by its .id.
    pub async fn delete(&self, path: &str, id: &str) -> Result<(), AppError> {
        if !id.starts_with('*') || id.len() < 2 || !id[1..].chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AppError::BadRequest(format!("invalid RouterOS ID: {id}")));
        }
        let url = format!("{}{}/{}", self.base_url, path, id);
        let resp = self
            .client
            .delete(&url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await
            .map_err(|e| AppError::BadGateway(format!("RouterOS unreachable: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::BadGateway(format!(
                "RouterOS returned {status}: {body}"
            )));
        }

        Ok(())
    }

    /// List entries from an address-list, filtered by list name and optionally by managed tag.
    pub async fn list_address_list(
        &self,
        list_name: &str,
    ) -> Result<Vec<super::models::AddressListEntry>, AppError> {
        let all: Vec<super::models::AddressListEntry> =
            self.list("/ip/firewall/address-list").await?;
        Ok(all.into_iter().filter(|e| e.list == list_name).collect())
    }

    /// Add an address to an address-list.
    ///
    /// `kind` is the structured-comment label (e.g. `"vpn-client"`,
    /// `"vpn-bypass"`) written as `<comment_tag>;kind=<kind>`. This is
    /// **mandatory**: the legacy-object sweep in [`Provisioner::setup`]
    /// (see `migrate_legacy_objects`) deletes every managed object whose
    /// comment lacks a `;kind=` field. Writing a bare `managed-by=snx-edge`
    /// comment here would make operator-added entries look legacy and get
    /// wiped on the next `setup` (bug P0-7). An optional free-text `comment`
    /// is appended as `;note=<comment>` so it survives the same way.
    pub async fn add_address(
        &self,
        list_name: &str,
        address: &str,
        kind: &str,
        comment: Option<&str>,
        disabled: Option<bool>,
    ) -> Result<super::models::AddressListEntry, AppError> {
        // Check for duplicates
        let existing = self.list_address_list(list_name).await?;
        if existing.iter().any(|e| e.address == address) {
            return Err(AppError::Conflict(format!(
                "address '{address}' already in list '{list_name}'"
            )));
        }

        let tagged = format!("{};kind={kind}", self.comment_tag);
        let tagged = match comment {
            Some(c) => format!("{tagged};note={c}"),
            None => tagged,
        };

        let mut body = serde_json::json!({
            "list": list_name,
            "address": address,
            "comment": tagged,
        });

        // RouterOS expects "disabled" as a string "true"/"false"
        if let Some(dis) = disabled {
            body["disabled"] = serde_json::Value::String(dis.to_string());
        }

        self.create("/ip/firewall/address-list", &body).await
    }

    /// Remove an address from an address-list by its .id.
    pub async fn remove_address(&self, id: &str) -> Result<(), AppError> {
        self.delete("/ip/firewall/address-list", id).await
    }

    /// List all managed entries (tagged with comment_tag).
    pub async fn list_managed<T: DeserializeOwned + HasComment>(
        &self,
        path: &str,
    ) -> Result<Vec<T>, AppError> {
        let all: Vec<T> = self.list(path).await?;
        Ok(all
            .into_iter()
            .filter(|e| {
                e.comment()
                    .map(|c| comment_matches_tag(c, &self.comment_tag))
                    .unwrap_or(false)
            })
            .collect())
    }

    /// Delete all managed entries from a path.
    pub async fn delete_managed(&self, path: &str) -> Result<usize, AppError> {
        #[derive(serde::Deserialize)]
        struct IdEntry {
            #[serde(rename = ".id")]
            id: String,
            #[serde(default)]
            comment: Option<String>,
        }

        let all: Vec<IdEntry> = self.list(path).await?;
        let managed: Vec<_> = all
            .into_iter()
            .filter(|e| {
                e.comment
                    .as_ref()
                    .map(|c| comment_matches_tag(c, &self.comment_tag))
                    .unwrap_or(false)
            })
            .collect();

        let count = managed.len();
        for entry in managed {
            self.delete(path, &entry.id).await?;
        }

        Ok(count)
    }

    /// List all entries with a legacy (untagged-kind) managed comment.
    ///
    /// Used by the migration pass in [`Provisioner::setup`] to detect objects
    /// from the pre-`kind=` era so they can be removed and recreated with the
    /// new structured comment.
    pub async fn list_legacy_managed(&self, path: &str) -> Result<Vec<String>, AppError> {
        #[derive(serde::Deserialize)]
        struct IdEntry {
            #[serde(rename = ".id")]
            id: String,
            #[serde(default)]
            comment: Option<String>,
        }

        let all: Vec<IdEntry> = self.list(path).await?;
        Ok(all
            .into_iter()
            .filter(|e| {
                e.comment
                    .as_ref()
                    .map(|c| comment_is_legacy(c, &self.comment_tag))
                    .unwrap_or(false)
            })
            .map(|e| e.id)
            .collect())
    }
}

/// Match a RouterOS object's comment against our managed `tag_prefix`.
///
/// We require either:
///   - The exact `tag_prefix` to be a `;`-separated key=value field
///     (e.g. `managed-by=snx-edge;kind=routing-table` matches `managed-by=snx-edge`), or
///   - The comment to start with `tag_prefix` (covers legacy comments that were
///     just the bare `managed-by=snx-edge` string with no `;kind=`).
///
/// Rationale: `comment.contains(tag_prefix)` from the prior implementation
/// false-matches any user-authored comment that mentions `managed-by=snx-edge`
/// in arbitrary positions (e.g. `"see managed-by=snx-edge docs"`).  Since
/// `Provisioner` always emits the prefix as the *first* segment, anchoring the
/// match avoids those false positives without changing semantics for the
/// objects we own.
pub(crate) fn comment_matches_tag(comment: &str, tag_prefix: &str) -> bool {
    if let Some(rest) = comment.strip_prefix(tag_prefix) {
        // Either bare prefix, or prefix immediately followed by `;`
        // (structured form).
        if rest.is_empty() || rest.starts_with(';') {
            return true;
        }
    }
    comment.split(';').any(|kv| kv.trim() == tag_prefix)
}

/// Check whether `comment` is a legacy managed tag — i.e. matches our
/// `tag_prefix` but does **not** carry the new `kind=` field.
pub(crate) fn comment_is_legacy(comment: &str, tag_prefix: &str) -> bool {
    comment_matches_tag(comment, tag_prefix)
        && !comment.split(';').any(|kv| kv.trim().starts_with("kind="))
}

/// Match an object's comment against `tag_prefix` *and* a specific `kind`.
///
/// Used by the per-step `ensure_*` idempotency checks so two managed rules
/// with the same `kind` but different specs can be distinguished.
pub(crate) fn comment_matches_kind(comment: &str, tag_prefix: &str, kind: &str) -> bool {
    if !comment_matches_tag(comment, tag_prefix) {
        return false;
    }
    let needle = format!("kind={kind}");
    comment.split(';').any(|kv| kv.trim() == needle)
}

/// Trait for types that have an optional comment field.
pub trait HasComment {
    fn comment(&self) -> Option<&str>;
}

// Implement for all RouterOS model types
macro_rules! impl_has_comment {
    ($($ty:ty),*) => {
        $(
            impl HasComment for $ty {
                fn comment(&self) -> Option<&str> {
                    self.comment.as_deref()
                }
            }
        )*
    };
}

impl_has_comment!(
    super::models::AddressListEntry,
    super::models::MangleRule,
    super::models::RouteEntry,
    super::models::NatRule,
    super::models::FilterRule,
    super::models::RoutingTable
);

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "managed-by=snx-edge";

    #[test]
    fn tag_prefix_matches_structured_comment() {
        assert!(comment_matches_tag(
            "managed-by=snx-edge;kind=routing-table",
            PREFIX
        ));
        assert!(comment_matches_tag(
            "managed-by=snx-edge;kind=mangle-conn-mark;profile=p1",
            PREFIX
        ));
        // Bare legacy prefix still matches (backwards compat for teardown).
        assert!(comment_matches_tag("managed-by=snx-edge", PREFIX));
    }

    #[test]
    fn tag_prefix_does_not_match_user_comment_containing_tag() {
        // The old `comment.contains(tag)` would match these — we must not.
        assert!(!comment_matches_tag("see managed-by=snx-edge docs", PREFIX));
        assert!(!comment_matches_tag("X managed-by=snx-edge Y", PREFIX));
        // A user key whose value happens to embed our prefix as a substring.
        assert!(!comment_matches_tag(
            "owner=team-managed-by=snx-edge-ops",
            PREFIX
        ));
        // Empty / unrelated.
        assert!(!comment_matches_tag("", PREFIX));
        assert!(!comment_matches_tag("kind=routing-table", PREFIX));
    }

    #[test]
    fn kind_specific_match_distinguishes_kinds() {
        let c = "managed-by=snx-edge;kind=routing-table";
        assert!(comment_matches_kind(c, PREFIX, "routing-table"));
        assert!(!comment_matches_kind(c, PREFIX, "mangle-conn-mark"));
        // Legacy comments (no kind=) never match a specific kind.
        assert!(!comment_matches_kind(
            "managed-by=snx-edge",
            PREFIX,
            "routing-table"
        ));
        // User comment that happens to mention the prefix is still rejected.
        assert!(!comment_matches_kind(
            "see managed-by=snx-edge;kind=routing-table in wiki",
            PREFIX,
            "routing-table"
        ));
    }

    #[test]
    fn legacy_detection() {
        assert!(comment_is_legacy("managed-by=snx-edge", PREFIX));
        assert!(!comment_is_legacy(
            "managed-by=snx-edge;kind=routing-table",
            PREFIX
        ));
        assert!(!comment_is_legacy("user note", PREFIX));
    }

    proptest::proptest! {
        /// `comment_matches_tag` runs on raw RouterOS comment strings, which
        /// are operator-controlled and may contain anything. We assert that
        /// it returns a bool for any input — no panics on garbage, even when
        /// the input contains `;`, `=`, or other separator characters that
        /// could break a naive split-based implementation.
        #[test]
        fn comment_match_no_panic_on_garbage(
            s in ".*",
            tag in r"managed-by=[a-z]+",
        ) {
            let _ = comment_matches_tag(&s, &tag);
            let _ = comment_is_legacy(&s, &tag);
            let _ = comment_matches_kind(&s, &tag, "some-kind");
        }
    }
}

// NOTE: Per-task `TunnelManager` proptest is intentionally omitted.
// `TunnelManager::new` wires `CheckPointTunnelConnectorFactory` directly
// (see `apps/snx-edge-server/src/tunnel.rs`); there is no `MockFactory` in
// the codebase and exposing one would require generic-ising the manager
// across every call site. That is a larger refactor than the audit task
// scopes; the existing `tunnel.rs` unit tests already cover the
// failure-recovery / state-reset path the proptest would exercise.
