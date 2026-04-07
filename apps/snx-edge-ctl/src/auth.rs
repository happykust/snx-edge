//! Keyring-based token storage, compatible with snx-edge-client (GUI).
//!
//! Service name: "snx-edge"
//! Key: server URL

/// Save a refresh token to the system keyring.
pub fn save_refresh_token(server_url: &str, token: &str) {
    if let Ok(entry) = keyring::Entry::new("snx-edge", server_url) {
        let _ = entry.set_password(token);
    }
}

/// Load a saved refresh token from the system keyring.
pub fn load_refresh_token(server_url: &str) -> Option<String> {
    let entry = keyring::Entry::new("snx-edge", server_url).ok()?;
    entry.get_password().ok()
}

/// Delete the saved refresh token from the system keyring.
pub fn delete_refresh_token(server_url: &str) {
    if let Ok(entry) = keyring::Entry::new("snx-edge", server_url) {
        let _ = entry.delete_credential();
    }
}
