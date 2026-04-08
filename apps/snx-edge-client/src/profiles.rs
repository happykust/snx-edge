use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::ApiClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub config: Value,
    #[serde(default)]
    pub enabled: bool,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: "Default".to_string(),
            config: Value::Object(serde_json::Map::new()),
            enabled: true,
        }
    }
}

/// Cached profile store that syncs with the server via API calls.
#[allow(dead_code)]
pub struct ProfileStore {
    profiles: RwLock<Vec<Profile>>,
    connected_profile_id: RwLock<Option<String>>,
}

impl ProfileStore {
    pub fn new() -> Self {
        Self {
            profiles: RwLock::new(vec![]),
            connected_profile_id: RwLock::new(None),
        }
    }

    pub fn all(&self) -> Vec<Profile> {
        self.profiles.read().unwrap().clone()
    }

    pub fn get(&self, id: &str) -> Option<Profile> {
        self.profiles.read().unwrap().iter().find(|p| p.id == id).cloned()
    }

    pub fn set_profiles(&self, profiles: Vec<Profile>) {
        *self.profiles.write().unwrap() = profiles;
    }

    pub fn connected_profile_id(&self) -> Option<String> {
        self.connected_profile_id.read().unwrap().clone()
    }

    pub fn set_connected(&self, id: Option<String>) {
        *self.connected_profile_id.write().unwrap() = id;
    }

    pub fn get_connected(&self) -> Option<Profile> {
        let id = self.connected_profile_id.read().unwrap().clone()?;
        self.get(&id)
    }
}

/// Load profiles from the server and update the store.
pub async fn load_profiles(api: &ApiClient, store: &Arc<ProfileStore>) -> anyhow::Result<Vec<Profile>> {
    let values = api.list_profiles().await?;
    let profiles: Vec<Profile> = values
        .into_iter()
        .map(|v| Profile {
            id: v["id"].as_str().unwrap_or_default().to_string(),
            name: v["name"].as_str().unwrap_or("Unnamed").to_string(),
            config: v.get("config").cloned().unwrap_or(Value::Object(serde_json::Map::new())),
            enabled: v["enabled"].as_bool().unwrap_or(true),
        })
        .collect();
    store.set_profiles(profiles.clone());
    Ok(profiles)
}

pub async fn save_profile(api: &ApiClient, profile: &Profile) -> anyhow::Result<Value> {
    let body = serde_json::json!({
        "name": profile.name,
        "config": profile.config,
        "enabled": profile.enabled,
    });
    api.update_profile(&profile.id, &body).await
}

pub async fn create_profile(api: &ApiClient, name: &str, config: &Value) -> anyhow::Result<Value> {
    api.create_profile(name, config).await
}

pub async fn delete_profile(api: &ApiClient, id: &str) -> anyhow::Result<()> {
    api.delete_profile(id).await
}
