use axum::extract::{Multipart, Path, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};

use crate::api::auth::{Claims, has_permission};
use crate::db::Profile;
use crate::error::AppError;
use crate::state::{AppState, ServerEvent};

const SECRET_MASK: &str = "***";

/// Profile response with secrets masked.
#[derive(Serialize)]
struct ProfileResponse {
    id: String,
    name: String,
    config: serde_json::Value,
    enabled: bool,
    created_at: String,
    updated_at: String,
}

fn mask_secrets(mut config: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = config.as_object_mut() {
        for key in ["password", "cert_password"] {
            if let Some(val) = obj.get(key)
                && val.is_string()
                && !val.as_str().unwrap_or("").is_empty()
            {
                obj.insert(key.to_string(), serde_json::json!(SECRET_MASK));
            }
        }
    }
    config
}

fn profile_to_response(p: Profile) -> ProfileResponse {
    ProfileResponse {
        id: p.id,
        name: p.name,
        config: mask_secrets(p.config),
        enabled: p.enabled,
        created_at: p.created_at.to_rfc3339(),
        updated_at: p.updated_at.to_rfc3339(),
    }
}

#[derive(Deserialize)]
pub struct CreateProfileRequest {
    pub name: String,
    pub config: serde_json::Value,
}

#[derive(Deserialize)]
pub struct UpdateProfileRequest {
    pub name: Option<String>,
    pub config: Option<serde_json::Value>,
    pub enabled: Option<bool>,
}

/// GET /api/v1/profiles
async fn list_profiles(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<ProfileResponse>>, AppError> {
    if !has_permission(&claims, "profiles.read") {
        return Err(AppError::Forbidden(
            "permission 'profiles.read' required".to_string(),
        ));
    }

    let profiles = state.db.list_profiles().await?;
    Ok(Json(
        profiles.into_iter().map(profile_to_response).collect(),
    ))
}

/// POST /api/v1/profiles
async fn create_profile(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateProfileRequest>,
) -> Result<(StatusCode, Json<ProfileResponse>), AppError> {
    if !has_permission(&claims, "profiles.write") {
        return Err(AppError::Forbidden(
            "permission 'profiles.write' required".to_string(),
        ));
    }

    // Validate required fields
    if let Some(obj) = req.config.as_object() {
        if obj
            .get("server")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .is_empty()
        {
            return Err(AppError::BadRequest(
                "config.server is required".to_string(),
            ));
        }
    } else {
        return Err(AppError::BadRequest("config must be an object".to_string()));
    }

    let profile = state.db.create_profile(&req.name, &req.config).await?;
    let _ = state.event_tx.send(ServerEvent::ConfigChanged);
    Ok((StatusCode::CREATED, Json(profile_to_response(profile))))
}

/// GET /api/v1/profiles/{id}
async fn get_profile(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<ProfileResponse>, AppError> {
    if !has_permission(&claims, "profiles.read") {
        return Err(AppError::Forbidden(
            "permission 'profiles.read' required".to_string(),
        ));
    }

    let profile = state.db.get_profile(&id).await?;
    Ok(Json(profile_to_response(profile)))
}

/// PUT /api/v1/profiles/{id}
async fn update_profile(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(req): Json<UpdateProfileRequest>,
) -> Result<Json<ProfileResponse>, AppError> {
    if !has_permission(&claims, "profiles.write") {
        return Err(AppError::Forbidden(
            "permission 'profiles.write' required".to_string(),
        ));
    }

    // Handle secret fields: if "***" keep current value
    let final_config = if let Some(mut new_cfg) = req.config {
        if let Some(obj) = new_cfg.as_object_mut() {
            let existing_config_str = state.db.get_profile_config(&id).await?;
            let existing: serde_json::Value =
                serde_json::from_str(&existing_config_str).unwrap_or_default();

            for key in ["password", "cert_password"] {
                if let Some(val) = obj.get(key)
                    && val.as_str() == Some(SECRET_MASK)
                {
                    // Keep existing secret
                    if let Some(existing_val) = existing.get(key) {
                        obj.insert(key.to_string(), existing_val.clone());
                    }
                }
            }
        }
        Some(new_cfg)
    } else {
        None
    };

    let profile = state
        .db
        .update_profile(&id, req.name.as_deref(), final_config.as_ref(), req.enabled)
        .await?;
    let _ = state.event_tx.send(ServerEvent::ConfigChanged);
    Ok(Json(profile_to_response(profile)))
}

/// POST /api/v1/profiles/{id}/certs — upload certificate files for a profile.
///
/// Accepted fields: `cert` (client cert), `ca_cert` (CA cert).
/// Files saved to /etc/snx-edge/certs/{profile_id}/.
/// Profile config updated with paths automatically.
async fn upload_certs(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    mut multipart: Multipart,
) -> Result<Json<ProfileResponse>, AppError> {
    if !has_permission(&claims, "profiles.write") {
        return Err(AppError::Forbidden(
            "permission 'profiles.write' required".to_string(),
        ));
    }

    // Verify profile exists
    let profile = state.db.get_profile(&id).await?;

    let certs_dir = std::path::PathBuf::from("/etc/snx-edge/certs").join(&id);
    std::fs::create_dir_all(&certs_dir)
        .map_err(|e| AppError::Internal(format!("failed to create certs dir: {e}")))?;

    let mut config = profile.config.clone();
    let obj = config
        .as_object_mut()
        .ok_or_else(|| AppError::Internal("profile config is not an object".to_string()))?;

    let mut uploaded = Vec::new();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("multipart error: {e}")))?
    {
        let field_name = field.name().unwrap_or("unknown").to_string();
        let raw_name = field.file_name().unwrap_or("cert.pem").to_string();
        let file_name = std::path::Path::new(&raw_name)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "cert.pem".to_string());

        let data = field
            .bytes()
            .await
            .map_err(|e| AppError::BadRequest(format!("failed to read field: {e}")))?;

        if data.len() > 1_048_576 {
            return Err(AppError::BadRequest(
                "certificate file too large (max 1MB)".to_string(),
            ));
        }

        let dest = certs_dir.join(&file_name);
        std::fs::write(&dest, &data)
            .map_err(|e| AppError::Internal(format!("failed to write cert: {e}")))?;

        let dest_str = dest.to_string_lossy().to_string();

        match field_name.as_str() {
            "cert" => {
                obj.insert("cert_path".to_string(), serde_json::json!(dest_str));
            }
            "ca_cert" => {
                let ca_list = obj
                    .entry("ca_cert")
                    .or_insert_with(|| serde_json::json!([]));
                if let Some(arr) = ca_list.as_array_mut()
                    && !arr.iter().any(|v| v.as_str() == Some(&dest_str))
                {
                    arr.push(serde_json::json!(dest_str));
                }
            }
            _ => {}
        }

        uploaded.push(file_name);
    }

    if uploaded.is_empty() {
        return Err(AppError::BadRequest("no files uploaded".to_string()));
    }

    // Save updated config
    let updated = state
        .db
        .update_profile(&id, None, Some(&config), None)
        .await?;

    Ok(Json(profile_to_response(updated)))
}

/// GET /api/v1/profiles/{id}/export — export profile as TOML (secrets stripped).
async fn export_profile(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    if !has_permission(&claims, "profiles.read") {
        return Err(AppError::Forbidden(
            "permission 'profiles.read' required".to_string(),
        ));
    }

    let profile = state.db.get_profile(&id).await?;
    let config = profile.config;

    // Convert JSON config to toml::Value
    let mut toml_value: toml::Value = serde_json::from_value(config)
        .map_err(|e| AppError::Internal(format!("failed to convert config to TOML: {e}")))?;

    // Strip secrets for export
    if let Some(table) = toml_value.as_table_mut() {
        for key in ["password", "cert_password"] {
            table.remove(key);
        }
    }

    let toml_string = toml::to_string_pretty(&toml_value)
        .map_err(|e| AppError::Internal(format!("failed to serialize TOML: {e}")))?;

    let filename = format!("{}.conf", profile.name.replace(' ', "_"));

    Ok((
        [
            (header::CONTENT_TYPE, "application/toml".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        toml_string,
    ))
}

/// POST /api/v1/profiles/import — import profile from TOML.
async fn import_profile(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    body: String,
) -> Result<(StatusCode, Json<ProfileResponse>), AppError> {
    if !has_permission(&claims, "profiles.write") {
        return Err(AppError::Forbidden(
            "permission 'profiles.write' required".to_string(),
        ));
    }

    // Parse TOML input
    let toml_value: toml::Value = body
        .parse()
        .map_err(|e| AppError::BadRequest(format!("invalid TOML: {e}")))?;

    // Convert TOML to JSON
    let config: serde_json::Value = serde_json::to_value(&toml_value)
        .map_err(|e| AppError::Internal(format!("failed to convert TOML to JSON: {e}")))?;

    // Extract profile name from TOML or use filename-derived default
    let name = config
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("imported")
        .to_string();

    // Remove the "name" key from config since it's stored separately
    let config = if let serde_json::Value::Object(mut map) = config {
        map.remove("name");
        serde_json::Value::Object(map)
    } else {
        config
    };

    let profile = state.db.create_profile(&name, &config).await?;
    Ok((StatusCode::CREATED, Json(profile_to_response(profile))))
}

/// DELETE /api/v1/profiles/{id}
async fn delete_profile(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    if !has_permission(&claims, "profiles.write") {
        return Err(AppError::Forbidden(
            "permission 'profiles.write' required".to_string(),
        ));
    }

    state.db.delete_profile(&id).await?;
    let _ = state.event_tx.send(ServerEvent::ConfigChanged);
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/profiles", get(list_profiles).post(create_profile))
        .route("/profiles/import", post(import_profile))
        .route(
            "/profiles/{id}",
            get(get_profile).put(update_profile).delete(delete_profile),
        )
        .route("/profiles/{id}/certs", post(upload_certs))
        .route("/profiles/{id}/export", get(export_profile))
}
