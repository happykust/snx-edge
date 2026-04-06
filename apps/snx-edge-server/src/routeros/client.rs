use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::config::RouterOsConfig;
use crate::error::AppError;

/// HTTP client for RouterOS REST API.
///
/// RouterOS 7.1+ exposes REST at `https://<host>/rest/`.
/// Authentication is HTTP Basic Auth.
pub struct RouterOsClient {
    client: Client,
    base_url: String,
    username: String,
    password: String,
    pub comment_tag: String,
}

impl RouterOsClient {
    pub fn new(config: &RouterOsConfig) -> Result<Self, AppError> {
        let host = std::env::var(&config.host_env).map_err(|_| {
            AppError::Internal(format!("env {} not set", config.host_env))
        })?;
        let username = std::env::var(&config.user_env).map_err(|_| {
            AppError::Internal(format!("env {} not set", config.user_env))
        })?;
        let password = std::env::var(&config.password_env).map_err(|_| {
            AppError::Internal(format!("env {} not set", config.password_env))
        })?;

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
    pub async fn add_address(
        &self,
        list_name: &str,
        address: &str,
        comment: Option<&str>,
    ) -> Result<super::models::AddressListEntry, AppError> {
        // Check for duplicates
        let existing = self.list_address_list(list_name).await?;
        if existing.iter().any(|e| e.address == address) {
            return Err(AppError::Conflict(format!(
                "address '{address}' already in list '{list_name}'"
            )));
        }

        let body = serde_json::json!({
            "list": list_name,
            "address": address,
            "comment": comment.unwrap_or(&self.comment_tag),
        });

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
                    .map(|c| c.contains(&self.comment_tag))
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
                    .map(|c| c.contains(&self.comment_tag))
                    .unwrap_or(false)
            })
            .collect();

        let count = managed.len();
        for entry in managed {
            self.delete(path, &entry.id).await?;
        }

        Ok(count)
    }
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
