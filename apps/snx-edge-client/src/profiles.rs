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
        self.profiles
            .read()
            .unwrap()
            .iter()
            .find(|p| p.id == id)
            .cloned()
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
pub async fn load_profiles(
    api: &ApiClient,
    store: &Arc<ProfileStore>,
) -> anyhow::Result<Vec<Profile>> {
    let values = api.list_profiles().await?;
    let profiles: Vec<Profile> = values
        .into_iter()
        .map(|v| Profile {
            id: v["id"].as_str().unwrap_or_default().to_string(),
            name: v["name"].as_str().unwrap_or("Unnamed").to_string(),
            config: v
                .get("config")
                .cloned()
                .unwrap_or(Value::Object(serde_json::Map::new())),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_profile_round_trips_through_serialize() {
        // Build a profile, push it through `set_profiles`, serialize the
        // value, and confirm round-trip equality. Catches a regression
        // where a `#[serde(default)]` change on a field would silently
        // drop data on read.
        let store = ProfileStore::new();
        let p = Profile {
            id: "abc-123".into(),
            name: "Work VPN".into(),
            config: serde_json::json!({"server": "vpn.example.com"}),
            enabled: true,
        };
        store.set_profiles(vec![p.clone()]);

        let fetched = store.get(&p.id).expect("profile must be retrievable");
        let json = serde_json::to_string(&fetched).expect("serialise");
        let de: Profile = serde_json::from_str(&json).expect("deserialise");

        assert_eq!(de.id, p.id);
        assert_eq!(de.name, p.name);
        assert_eq!(de.enabled, p.enabled);
        assert_eq!(de.config, p.config);
    }

    #[test]
    fn unique_id_per_profile() {
        let store = ProfileStore::new();
        let a = Profile {
            id: "id-a".into(),
            name: "A".into(),
            ..Profile::default()
        };
        let b = Profile {
            id: "id-b".into(),
            name: "B".into(),
            ..Profile::default()
        };
        store.set_profiles(vec![a.clone(), b.clone()]);

        assert_eq!(store.all().len(), 2);
        assert_eq!(store.get("id-a").map(|p| p.name), Some("A".to_string()));
        assert_eq!(store.get("id-b").map(|p| p.name), Some("B".to_string()));
        assert!(store.get("missing").is_none());
    }

    #[test]
    fn connected_state_round_trips() {
        let store = ProfileStore::new();
        store.set_profiles(vec![Profile {
            id: "p1".into(),
            name: "X".into(),
            ..Profile::default()
        }]);
        assert!(store.get_connected().is_none());
        store.set_connected(Some("p1".into()));
        assert_eq!(store.get_connected().map(|p| p.id), Some("p1".to_string()));
        store.set_connected(None);
        assert!(store.get_connected().is_none());
    }
}
