use std::{cell::RefCell, rc::Rc, sync::Arc};

use gtk4::{
    Align, Orientation, ResponseType, Window,
    glib::{self, clone},
    prelude::*,
};
use serde_json::Value;
use tokio::sync::mpsc::Sender;
use tracing::warn;

use crate::{
    api::ApiClient,
    auth::AuthManager,
    client_settings::{ClientSettings, ServerConnection},
    get_window,
    profiles::{self, ProfileStore},
    set_window,
    tray::TrayCommand,
};

// ── Helper: get StringList from DropDown ──────────────────────────────────────

fn get_string_list(dropdown: &gtk4::DropDown) -> gtk4::StringList {
    dropdown
        .model()
        .and_then(|model| model.downcast::<gtk4::StringList>().ok())
        .unwrap_or_default()
}

// ── VPN profile config widgets ───────────────────────────────────────────────

struct ProfileConfigWidgets {
    // Basic
    server_addr: gtk4::Entry,
    username: gtk4::Entry,
    password: gtk4::PasswordEntry,
    login_type: gtk4::DropDown,
    cert_type: gtk4::DropDown,
    cert_path: gtk4::Entry,
    cert_browse: gtk4::Button,
    cert_password: gtk4::PasswordEntry,
    // Certificate-only rows (hidden when login_type != certificate)
    cert_type_row: gtk4::Box,
    cert_path_row: gtk4::Box,
    cert_password_row: gtk4::Box,

    // DNS
    no_dns: gtk4::Switch,
    dns_servers: gtk4::Entry,
    ignored_dns_servers: gtk4::Entry,
    search_domains: gtk4::Entry,
    ignored_search_domains: gtk4::Entry,
    search_domains_as_routes: gtk4::Switch,

    // Routing
    no_routing: gtk4::Switch,
    default_route: gtk4::Switch,
    add_routes: gtk4::Entry,
    ignored_routes: gtk4::Entry,
    no_ipv6: gtk4::Switch,

    // Certificates (CA)
    ca_cert: gtk4::Entry,
    no_cert_check: gtk4::Switch,

    // Other
    password_factor: gtk4::SpinButton,
    ike_lifetime: gtk4::SpinButton,
    ike_persist: gtk4::Switch,
    no_keepalive: gtk4::Switch,
    port_knock: gtk4::Switch,
    ip_lease_duration: gtk4::SpinButton,
    mtu: gtk4::SpinButton,
    transport_type: gtk4::DropDown,

    // Save / Reset
    save_profile_btn: gtk4::Button,
    reset_defaults_btn: gtk4::Button,

    // Container for the whole profile form (to show/hide)
    container: gtk4::Notebook,
}

impl ProfileConfigWidgets {
    fn new() -> Self {
        let login_type = gtk4::DropDown::builder()
            .model(&gtk4::StringList::new(&["password", "certificate"]))
            .build();

        let cert_type = gtk4::DropDown::builder()
            .model(&gtk4::StringList::new(&["pkcs12", "pkcs8", "pkcs11"]))
            .build();

        let transport_type = gtk4::DropDown::builder()
            .model(&gtk4::StringList::new(&["auto", "udp", "tcpt"]))
            .build();

        let password_factor = gtk4::SpinButton::with_range(1.0, 10.0, 1.0);
        password_factor.set_value(1.0);

        let ike_lifetime = gtk4::SpinButton::with_range(3600.0, 86400.0, 3600.0);
        ike_lifetime.set_value(28800.0);

        let ip_lease_duration = gtk4::SpinButton::with_range(0.0, 604800.0, 60.0);
        ip_lease_duration.set_value(0.0);

        let mtu = gtk4::SpinButton::with_range(576.0, 9000.0, 1.0);
        mtu.set_value(1350.0);

        Self {
            server_addr: gtk4::Entry::builder()
                .hexpand(true)
                .placeholder_text("vpn.example.com")
                .build(),
            username: gtk4::Entry::builder()
                .hexpand(true)
                .placeholder_text("vpn_user")
                .build(),
            password: gtk4::PasswordEntry::builder()
                .hexpand(true)
                .show_peek_icon(true)
                .build(),
            login_type,
            cert_type,
            cert_path: gtk4::Entry::builder()
                .hexpand(true)
                .placeholder_text("/path/to/cert.p12")
                .build(),
            cert_browse: gtk4::Button::with_label("Browse..."),
            cert_password: gtk4::PasswordEntry::builder()
                .hexpand(true)
                .show_peek_icon(true)
                .build(),
            cert_type_row: gtk4::Box::default(),
            cert_path_row: gtk4::Box::default(),
            cert_password_row: gtk4::Box::default(),

            no_dns: gtk4::Switch::builder().halign(Align::Start).build(),
            dns_servers: gtk4::Entry::builder()
                .hexpand(true)
                .placeholder_text("8.8.8.8, 1.1.1.1")
                .build(),
            ignored_dns_servers: gtk4::Entry::builder()
                .hexpand(true)
                .placeholder_text("10.0.0.1")
                .build(),
            search_domains: gtk4::Entry::builder()
                .hexpand(true)
                .placeholder_text("corp.local, internal")
                .build(),
            ignored_search_domains: gtk4::Entry::builder()
                .hexpand(true)
                .placeholder_text("home.local")
                .build(),
            search_domains_as_routes: gtk4::Switch::builder().halign(Align::Start).build(),

            no_routing: gtk4::Switch::builder().halign(Align::Start).build(),
            default_route: gtk4::Switch::builder().halign(Align::Start).build(),
            add_routes: gtk4::Entry::builder()
                .hexpand(true)
                .placeholder_text("10.0.0.0/8, 172.16.0.0/12")
                .build(),
            ignored_routes: gtk4::Entry::builder()
                .hexpand(true)
                .placeholder_text("192.168.1.0/24")
                .build(),
            no_ipv6: gtk4::Switch::builder().halign(Align::Start).build(),

            ca_cert: gtk4::Entry::builder()
                .hexpand(true)
                .placeholder_text("/path/to/ca.pem")
                .build(),
            no_cert_check: gtk4::Switch::builder().halign(Align::Start).build(),

            password_factor,
            ike_lifetime,
            ike_persist: gtk4::Switch::builder().halign(Align::Start).build(),
            no_keepalive: gtk4::Switch::builder().halign(Align::Start).build(),
            port_knock: gtk4::Switch::builder().halign(Align::Start).build(),
            ip_lease_duration,
            mtu,
            transport_type,

            save_profile_btn: gtk4::Button::builder()
                .label("Save Profile")
                .css_classes(vec!["suggested-action".to_string()])
                .sensitive(false)
                .build(),
            reset_defaults_btn: gtk4::Button::with_label("Reset to Defaults"),

            container: gtk4::Notebook::new(),
        }
    }

    /// Load values from a JSON config object into the widgets.
    fn load_from_json(&self, config: &Value) {
        let obj = config.as_object();
        let get_str = |key: &str| -> String {
            obj.and_then(|o| o.get(key))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        let get_str_opt = |key: &str| -> String {
            obj.and_then(|o| o.get(key))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        let get_bool = |key: &str| -> bool {
            obj.and_then(|o| o.get(key))
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        };
        let get_u32 = |key: &str, default: u32| -> u32 {
            obj.and_then(|o| o.get(key))
                .and_then(|v| v.as_u64())
                .map(|v| v as u32)
                .unwrap_or(default)
        };
        let get_u16 = |key: &str, default: u16| -> u16 {
            obj.and_then(|o| o.get(key))
                .and_then(|v| v.as_u64())
                .map(|v| v as u16)
                .unwrap_or(default)
        };
        let get_str_vec = |key: &str| -> String {
            obj.and_then(|o| o.get(key))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default()
        };

        // Basic
        self.server_addr.set_text(&get_str("server"));
        self.username.set_text(&get_str("username"));
        let pw = get_str_opt("password");
        self.password.set_text(&pw);

        let login_type_str = get_str("login_type");
        self.login_type.set_selected(match login_type_str.as_str() {
            "certificate" => 1,
            _ => 0,
        });

        let cert_type_str = get_str("cert_type");
        self.cert_type.set_selected(match cert_type_str.as_str() {
            "pkcs8" => 1,
            "pkcs11" => 2,
            _ => 0,
        });

        self.cert_path.set_text(&get_str_opt("cert_path"));
        self.cert_password.set_text(&get_str_opt("cert_password"));

        // Update cert row visibility
        self.update_cert_visibility();

        // DNS
        self.no_dns.set_active(get_bool("no_dns"));
        self.dns_servers.set_text(&get_str_vec("dns_servers"));
        self.ignored_dns_servers.set_text(&get_str_vec("ignored_dns_servers"));
        self.search_domains.set_text(&get_str_vec("search_domains"));
        self.ignored_search_domains.set_text(&get_str_vec("ignored_search_domains"));
        self.search_domains_as_routes.set_active(get_bool("search_domains_as_routes"));

        // Routing
        self.no_routing.set_active(get_bool("no_routing"));
        self.default_route.set_active(get_bool("default_route"));
        self.add_routes.set_text(&get_str_vec("add_routes"));
        self.ignored_routes.set_text(&get_str_vec("ignored_routes"));
        self.no_ipv6.set_active(get_bool("no_ipv6"));

        // Certificates (CA)
        self.ca_cert.set_text(&get_str_vec("ca_cert"));
        self.no_cert_check.set_active(get_bool("no_cert_check"));

        // Other
        self.password_factor.set_value(get_u32("password_factor", 1) as f64);
        self.ike_lifetime.set_value(get_u32("ike_lifetime", 28800) as f64);
        self.ike_persist.set_active(get_bool("ike_persist"));
        self.no_keepalive.set_active(get_bool("no_keepalive"));
        self.port_knock.set_active(get_bool("port_knock"));

        let lease = obj
            .and_then(|o| o.get("ip_lease_duration"))
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .unwrap_or(0);
        self.ip_lease_duration.set_value(lease as f64);

        self.mtu.set_value(get_u16("mtu", 1350) as f64);

        let transport = get_str("transport_type");
        self.transport_type.set_selected(match transport.as_str() {
            "udp" => 1,
            "tcpt" => 2,
            _ => 0,
        });
    }

    /// Collect all widget values into a JSON object.
    fn to_json(&self) -> Value {
        let mut map = serde_json::Map::new();

        // Basic
        let server = self.server_addr.text().to_string();
        if !server.is_empty() {
            map.insert("server".into(), Value::String(server));
        }

        let username = self.username.text().to_string();
        if !username.is_empty() {
            map.insert("username".into(), Value::String(username));
        }

        let password = self.password.text().to_string();
        if !password.is_empty() {
            map.insert("password".into(), Value::String(password));
        }

        let login_type = match self.login_type.selected() {
            1 => "certificate",
            _ => "password",
        };
        map.insert("login_type".into(), Value::String(login_type.into()));

        let cert_type = match self.cert_type.selected() {
            1 => "pkcs8",
            2 => "pkcs11",
            _ => "pkcs12",
        };
        map.insert("cert_type".into(), Value::String(cert_type.into()));

        let cert_path = self.cert_path.text().to_string();
        if !cert_path.is_empty() {
            map.insert("cert_path".into(), Value::String(cert_path));
        }

        let cert_password = self.cert_password.text().to_string();
        if !cert_password.is_empty() {
            map.insert("cert_password".into(), Value::String(cert_password));
        }

        // DNS
        map.insert("no_dns".into(), Value::Bool(self.no_dns.is_active()));

        let dns_servers = parse_comma_list(&self.dns_servers.text());
        if !dns_servers.is_empty() {
            map.insert("dns_servers".into(), str_vec_to_json(&dns_servers));
        }
        let ignored_dns = parse_comma_list(&self.ignored_dns_servers.text());
        if !ignored_dns.is_empty() {
            map.insert("ignored_dns_servers".into(), str_vec_to_json(&ignored_dns));
        }
        let search_domains = parse_comma_list(&self.search_domains.text());
        if !search_domains.is_empty() {
            map.insert("search_domains".into(), str_vec_to_json(&search_domains));
        }
        let ignored_search = parse_comma_list(&self.ignored_search_domains.text());
        if !ignored_search.is_empty() {
            map.insert("ignored_search_domains".into(), str_vec_to_json(&ignored_search));
        }
        map.insert(
            "search_domains_as_routes".into(),
            Value::Bool(self.search_domains_as_routes.is_active()),
        );

        // Routing
        map.insert("no_routing".into(), Value::Bool(self.no_routing.is_active()));
        map.insert("default_route".into(), Value::Bool(self.default_route.is_active()));

        let add_routes = parse_comma_list(&self.add_routes.text());
        if !add_routes.is_empty() {
            map.insert("add_routes".into(), str_vec_to_json(&add_routes));
        }
        let ignored_routes = parse_comma_list(&self.ignored_routes.text());
        if !ignored_routes.is_empty() {
            map.insert("ignored_routes".into(), str_vec_to_json(&ignored_routes));
        }
        map.insert("no_ipv6".into(), Value::Bool(self.no_ipv6.is_active()));

        // Certificates (CA)
        let ca_cert = parse_comma_list(&self.ca_cert.text());
        if !ca_cert.is_empty() {
            map.insert("ca_cert".into(), str_vec_to_json(&ca_cert));
        }
        map.insert("no_cert_check".into(), Value::Bool(self.no_cert_check.is_active()));

        // Other
        map.insert(
            "password_factor".into(),
            Value::Number(serde_json::Number::from(self.password_factor.value() as u32)),
        );
        map.insert(
            "ike_lifetime".into(),
            Value::Number(serde_json::Number::from(self.ike_lifetime.value() as u32)),
        );
        map.insert("ike_persist".into(), Value::Bool(self.ike_persist.is_active()));
        map.insert("no_keepalive".into(), Value::Bool(self.no_keepalive.is_active()));
        map.insert("port_knock".into(), Value::Bool(self.port_knock.is_active()));

        let lease = self.ip_lease_duration.value() as u32;
        if lease > 0 {
            map.insert(
                "ip_lease_duration".into(),
                Value::Number(serde_json::Number::from(lease)),
            );
        }

        map.insert(
            "mtu".into(),
            Value::Number(serde_json::Number::from(self.mtu.value() as u16)),
        );

        let transport = match self.transport_type.selected() {
            1 => "udp",
            2 => "tcpt",
            _ => "auto",
        };
        map.insert("transport_type".into(), Value::String(transport.into()));

        Value::Object(map)
    }

    /// Reset all fields to default values.
    fn reset_defaults(&self) {
        self.server_addr.set_text("");
        self.username.set_text("");
        self.password.set_text("");
        self.login_type.set_selected(0);
        self.cert_type.set_selected(0);
        self.cert_path.set_text("");
        self.cert_password.set_text("");

        self.no_dns.set_active(false);
        self.dns_servers.set_text("");
        self.ignored_dns_servers.set_text("");
        self.search_domains.set_text("");
        self.ignored_search_domains.set_text("");
        self.search_domains_as_routes.set_active(false);

        self.no_routing.set_active(false);
        self.default_route.set_active(false);
        self.add_routes.set_text("");
        self.ignored_routes.set_text("");
        self.no_ipv6.set_active(false);

        self.ca_cert.set_text("");
        self.no_cert_check.set_active(false);

        self.password_factor.set_value(1.0);
        self.ike_lifetime.set_value(28800.0);
        self.ike_persist.set_active(false);
        self.no_keepalive.set_active(false);
        self.port_knock.set_active(false);
        self.ip_lease_duration.set_value(0.0);
        self.mtu.set_value(1350.0);
        self.transport_type.set_selected(0);

        self.update_cert_visibility();
    }

    /// Show/hide certificate-related rows based on login_type selection.
    fn update_cert_visibility(&self) {
        let is_cert = self.login_type.selected() == 1;
        self.cert_type_row.set_visible(is_cert);
        self.cert_path_row.set_visible(is_cert);
        self.cert_password_row.set_visible(is_cert);
    }

    /// Set sensitivity on all profile config widgets (for role-based access).
    fn set_all_sensitive(&self, sensitive: bool) {
        self.server_addr.set_sensitive(sensitive);
        self.username.set_sensitive(sensitive);
        self.password.set_sensitive(sensitive);
        self.login_type.set_sensitive(sensitive);
        self.cert_type.set_sensitive(sensitive);
        self.cert_path.set_sensitive(sensitive);
        self.cert_browse.set_sensitive(sensitive);
        self.cert_password.set_sensitive(sensitive);

        self.no_dns.set_sensitive(sensitive);
        self.dns_servers.set_sensitive(sensitive);
        self.ignored_dns_servers.set_sensitive(sensitive);
        self.search_domains.set_sensitive(sensitive);
        self.ignored_search_domains.set_sensitive(sensitive);
        self.search_domains_as_routes.set_sensitive(sensitive);

        self.no_routing.set_sensitive(sensitive);
        self.default_route.set_sensitive(sensitive);
        self.add_routes.set_sensitive(sensitive);
        self.ignored_routes.set_sensitive(sensitive);
        self.no_ipv6.set_sensitive(sensitive);

        self.ca_cert.set_sensitive(sensitive);
        self.no_cert_check.set_sensitive(sensitive);

        self.password_factor.set_sensitive(sensitive);
        self.ike_lifetime.set_sensitive(sensitive);
        self.ike_persist.set_sensitive(sensitive);
        self.no_keepalive.set_sensitive(sensitive);
        self.port_knock.set_sensitive(sensitive);
        self.ip_lease_duration.set_sensitive(sensitive);
        self.mtu.set_sensitive(sensitive);
        self.transport_type.set_sensitive(sensitive);

        self.save_profile_btn.set_visible(sensitive);
        self.reset_defaults_btn.set_sensitive(sensitive);
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn parse_comma_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn str_vec_to_json(v: &[String]) -> Value {
    Value::Array(v.iter().map(|s| Value::String(s.clone())).collect())
}

// ── Main dialog struct ───────────────────────────────────────────────────────

struct SettingsDialog {
    window: Window,
    widgets: Rc<MyWidgets>,
    response_rx: async_channel::Receiver<ResponseType>,
}

struct MyWidgets {
    // Server connection
    server_url: gtk4::Entry,
    server_name: gtk4::Entry,

    // Profile management
    profile_select: gtk4::DropDown,
    profile_new: gtk4::Button,
    profile_rename: gtk4::Button,
    profile_delete: gtk4::Button,

    // Profile config editing
    profile_config: ProfileConfigWidgets,

    // Icon theme
    icon_theme: gtk4::DropDown,

    // Auto-connect
    auto_connect: gtk4::Switch,

    // Error display
    error: gtk4::Label,

    // Buttons
    button_box: gtk4::Box,

    // State
    profile_ids: RefCell<Vec<String>>,
    dirty: RefCell<bool>,
    api: ApiClient,
    #[allow(dead_code)]
    auth: AuthManager,
    profile_store: Arc<ProfileStore>,
    user_role: RefCell<Option<String>>,
}

impl MyWidgets {
    fn validate(&self) -> anyhow::Result<()> {
        if self.server_url.text().is_empty() {
            anyhow::bail!("Server URL is required");
        }
        Ok(())
    }

    fn mark_dirty(&self) {
        *self.dirty.borrow_mut() = true;
        self.profile_config.save_profile_btn.set_sensitive(true);
    }

    fn clear_dirty(&self) {
        *self.dirty.borrow_mut() = false;
        self.profile_config.save_profile_btn.set_sensitive(false);
    }

    fn on_profile_changed(&self) {
        if let Some(id) = profile_active_id(self) {
            self.profile_delete.set_sensitive(true);
            self.profile_rename.set_sensitive(true);
            self.profile_config.container.set_visible(true);

            // Load profile config from store
            if let Some(profile) = self.profile_store.get(&id) {
                self.profile_config.load_from_json(&profile.config);
            } else {
                self.profile_config.reset_defaults();
            }

            self.clear_dirty();

            // Apply role-based access
            self.apply_role_restrictions();
        } else {
            self.profile_delete.set_sensitive(false);
            self.profile_rename.set_sensitive(false);
            self.profile_config.container.set_visible(false);
        }
    }

    fn apply_role_restrictions(&self) {
        let role = self.user_role.borrow();
        let is_admin = role.as_deref() == Some("admin") || role.is_none();
        self.profile_config.set_all_sensitive(is_admin);
    }

    async fn save_profile_config(&self) {
        let id = match profile_active_id(self) {
            Some(id) => id,
            None => return,
        };

        let config = self.profile_config.to_json();
        let api = self.api.clone();
        let id_clone = id.clone();
        let store = self.profile_store.clone();

        let body = serde_json::json!({ "config": config });

        let (tx, rx) = async_channel::bounded(1);
        tokio::spawn(async move {
            let result = api.update_profile(&id_clone, &body).await;
            let _ = tx.send(result).await;
        });

        match rx.recv().await {
            Ok(Ok(resp)) => {
                // Update local store
                if let Some(mut profile) = store.get(&id) {
                    let new_config = resp
                        .get("config")
                        .cloned()
                        .unwrap_or(Value::Object(serde_json::Map::new()));
                    profile.config = new_config;

                    let mut all = store.all();
                    if let Some(pos) = all.iter().position(|p| p.id == id) {
                        all[pos] = profile;
                        store.set_profiles(all);
                    }
                }
                self.clear_dirty();
            }
            Ok(Err(e)) => {
                warn!("Failed to save profile config: {}", e);
                self.error.set_text(&format!("Save failed: {}", e));
                self.error.set_visible(true);
            }
            Err(e) => {
                warn!("Channel error saving profile: {}", e);
            }
        }
    }

    async fn on_profile_delete(&self, parent: &Window) {
        let alert = gtk4::AlertDialog::builder()
            .message("Delete this profile?")
            .buttons(["Cancel", "OK"].as_slice())
            .cancel_button(0)
            .default_button(0)
            .build();
        if let Ok(1) = alert.choose_future(Some(parent)).await
            && let Some(id) = profile_active_id(self)
        {
            let api = self.api.clone();
            let id_clone = id.clone();
            let (tx, rx) = async_channel::bounded(1);
            tokio::spawn(async move {
                let result = profiles::delete_profile(&api, &id_clone).await;
                let _ = tx.send(result).await;
            });
            if let Ok(Ok(())) = rx.recv().await {
                let active = self.profile_select.selected();
                get_string_list(&self.profile_select).splice(active, 1, &[]);
                self.profile_ids.borrow_mut().remove(active as usize);
                if self.profile_ids.borrow().is_empty() {
                    self.profile_delete.set_sensitive(false);
                    self.profile_rename.set_sensitive(false);
                    self.profile_config.container.set_visible(false);
                } else {
                    self.profile_select.set_selected(0);
                }
            }
        }
    }

    async fn on_profile_new(&self, parent: &Window) {
        let name = show_entry_dialog(parent, "New Profile", "Profile name:", "").await;
        if let Some(name) = name {
            let api = self.api.clone();
            let name_clone = name.clone();
            // Create with a minimal config containing just the server address
            let config = serde_json::json!({
                "server": "",
                "login_type": "password",
                "mtu": 1350,
                "ike_lifetime": 28800,
                "password_factor": 1,
                "transport_type": "auto",
            });
            let (tx, rx) = async_channel::bounded(1);
            tokio::spawn(async move {
                let result = profiles::create_profile(&api, &name_clone, &config).await;
                let _ = tx.send(result).await;
            });
            if let Ok(Ok(value)) = rx.recv().await {
                let id = value["id"].as_str().unwrap_or_default().to_string();

                // Also update the local store
                let new_config = value
                    .get("config")
                    .cloned()
                    .unwrap_or(Value::Object(serde_json::Map::new()));
                let profile = profiles::Profile {
                    id: id.clone(),
                    name: name.clone(),
                    config: new_config,
                    enabled: true,
                };
                let mut all = self.profile_store.all();
                all.push(profile);
                self.profile_store.set_profiles(all);

                get_string_list(&self.profile_select).append(&name);
                self.profile_ids.borrow_mut().push(id);
                self.profile_select
                    .set_selected((self.profile_ids.borrow().len() - 1) as u32);
            }
        }
    }

    async fn on_profile_rename(&self, parent: &Window) {
        let active_text = {
            let active = self.profile_select.selected();
            get_string_list(&self.profile_select)
                .string(active)
                .map(|s| s.to_string())
                .unwrap_or_default()
        };
        let name = show_entry_dialog(parent, "Rename Profile", "Profile name:", &active_text).await;
        if let Some(name) = name
            && let Some(id) = profile_active_id(self)
        {
            let active = self.profile_select.selected();
            get_string_list(&self.profile_select).splice(active, 1, &[name.as_str()]);
            self.profile_select.set_selected(active);

            if let Some(mut profile) = self.profile_store.get(&id) {
                profile.name = name;
                let api = self.api.clone();
                tokio::spawn(async move {
                    let _ = profiles::save_profile(&api, &profile).await;
                });
            }
        }
    }
}

fn profile_active_id(widgets: &MyWidgets) -> Option<String> {
    let sel = widgets.profile_select.selected();
    if sel == gtk4::INVALID_LIST_POSITION {
        None
    } else {
        widgets.profile_ids.borrow().get(sel as usize).cloned()
    }
}

impl SettingsDialog {
    pub fn new<W: IsA<Window>>(
        parent: W,
        api: ApiClient,
        auth: AuthManager,
        profile_store: Arc<ProfileStore>,
    ) -> Self {
        let (response_tx, response_rx) = async_channel::unbounded::<ResponseType>();

        let window = Window::builder()
            .title("SNX Edge - Settings")
            .transient_for(&parent)
            .modal(true)
            .build();

        let button_box = gtk4::Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(6)
            .margin_top(6)
            .homogeneous(true)
            .halign(Align::End)
            .build();

        let ok_button = gtk4::Button::with_label("OK");
        let apply_button = gtk4::Button::with_label("Apply");
        let cancel_button = gtk4::Button::with_label("Cancel");
        button_box.append(&ok_button);
        button_box.append(&apply_button);
        button_box.append(&cancel_button);

        let settings = ClientSettings::load();

        let server_url = gtk4::Entry::builder()
            .hexpand(true)
            .placeholder_text("https://server:8443")
            .text(settings.active_server_url().unwrap_or_default())
            .build();

        let server_name = gtk4::Entry::builder()
            .hexpand(true)
            .placeholder_text("My VPN Server")
            .text(
                settings
                    .active_server()
                    .map(|s| s.name.as_str())
                    .unwrap_or_default(),
            )
            .build();

        let profile_select = gtk4::DropDown::builder().model(&gtk4::StringList::new(&[])).build();
        let profile_new = gtk4::Button::with_label("New");
        let profile_rename = gtk4::Button::with_label("Rename");
        let profile_delete = gtk4::Button::with_label("Delete");

        let icon_theme = gtk4::DropDown::builder().build();
        let auto_connect = gtk4::Switch::builder().halign(Align::Start).build();

        let error = gtk4::Label::new(None);
        error.set_visible(false);
        error.add_css_class("error");

        auto_connect.set_active(
            settings
                .active_server()
                .map(|s| s.auto_connect)
                .unwrap_or(false),
        );

        let profile_config = ProfileConfigWidgets::new();

        let widgets = Rc::new(MyWidgets {
            server_url,
            server_name,
            profile_select,
            profile_new,
            profile_rename,
            profile_delete,
            profile_config,
            icon_theme,
            auto_connect,
            error,
            button_box,
            profile_ids: RefCell::new(vec![]),
            dirty: RefCell::new(false),
            api: api.clone(),
            auth: auth.clone(),
            profile_store: profile_store.clone(),
            user_role: RefCell::new(None),
        });

        // Populate profiles from the store
        for profile in profile_store.all() {
            get_string_list(&widgets.profile_select).append(&profile.name);
            widgets.profile_ids.borrow_mut().push(profile.id.clone());
        }
        if !widgets.profile_ids.borrow().is_empty() {
            widgets.profile_select.set_selected(0);
        }

        // Fetch user role asynchronously
        {
            let widgets_weak = Rc::downgrade(&widgets);
            let auth_clone = auth.clone();
            glib::spawn_future_local(async move {
                let role = auth_clone.role().await;
                if let Some(widgets) = widgets_weak.upgrade() {
                    *widgets.user_role.borrow_mut() = role;
                    widgets.apply_role_restrictions();
                }
            });
        }

        // ── Button callbacks ─────────────────────────────────────────────

        let tx_ok = response_tx.clone();
        ok_button.connect_clicked(clone!(
            #[weak]
            widgets,
            #[weak]
            window,
            move |_| {
                match widgets.validate() {
                    Ok(()) => {
                        let _ = tx_ok.try_send(ResponseType::Ok);
                    }
                    Err(e) => {
                        glib::spawn_future_local(clone!(
                            #[weak]
                            window,
                            async move {
                                let alert = gtk4::AlertDialog::builder()
                                    .message(e.to_string())
                                    .buttons(["OK"].as_slice())
                                    .default_button(0)
                                    .build();
                                alert.choose_future(Some(&window)).await.ok();
                            }
                        ));
                    }
                }
            }
        ));

        let tx_apply = response_tx.clone();
        apply_button.connect_clicked(clone!(
            #[weak]
            widgets,
            #[weak]
            window,
            move |_| {
                match widgets.validate() {
                    Ok(()) => {
                        let _ = tx_apply.try_send(ResponseType::Apply);
                    }
                    Err(e) => {
                        glib::spawn_future_local(clone!(
                            #[weak]
                            window,
                            async move {
                                let alert = gtk4::AlertDialog::builder()
                                    .message(e.to_string())
                                    .buttons(["OK"].as_slice())
                                    .default_button(0)
                                    .build();
                                alert.choose_future(Some(&window)).await.ok();
                            }
                        ));
                    }
                }
            }
        ));

        let tx_cancel = response_tx.clone();
        cancel_button.connect_clicked(move |_| {
            let _ = tx_cancel.try_send(ResponseType::Cancel);
        });

        let tx_close = response_tx.clone();
        window.connect_close_request(move |_| {
            let _ = tx_close.try_send(ResponseType::Cancel);
            glib::Propagation::Proceed
        });

        {
            let key_controller = gtk4::EventControllerKey::new();
            key_controller.connect_key_pressed(clone!(
                #[weak]
                window,
                #[upgrade_or]
                glib::Propagation::Proceed,
                move |_, key, _, _| {
                    if key == gtk4::gdk::Key::Escape {
                        window.close();
                        glib::Propagation::Stop
                    } else {
                        glib::Propagation::Proceed
                    }
                }
            ));
            window.add_controller(key_controller);
        }

        // ── Profile management callbacks ─────────────────────────────────

        widgets.profile_select.connect_selected_notify(clone!(
            #[weak]
            widgets,
            move |_| widgets.on_profile_changed()
        ));

        widgets.profile_delete.connect_clicked(clone!(
            #[weak]
            widgets,
            #[weak]
            window,
            move |_| {
                glib::spawn_future_local(clone!(
                    #[weak]
                    widgets,
                    async move { widgets.on_profile_delete(&window).await }
                ));
            }
        ));

        widgets.profile_new.connect_clicked(clone!(
            #[weak]
            widgets,
            #[weak]
            window,
            move |_| {
                glib::spawn_future_local(clone!(
                    #[weak]
                    widgets,
                    async move { widgets.on_profile_new(&window).await }
                ));
            }
        ));

        widgets.profile_rename.connect_clicked(clone!(
            #[weak]
            widgets,
            #[weak]
            window,
            move |_| {
                glib::spawn_future_local(clone!(
                    #[weak]
                    widgets,
                    async move { widgets.on_profile_rename(&window).await }
                ));
            }
        ));

        // ── Profile config change tracking (dirty state) ─────────────────

        // Connect login_type change to update cert visibility + dirty
        widgets.profile_config.login_type.connect_selected_notify(clone!(
            #[weak]
            widgets,
            move |_| {
                widgets.profile_config.update_cert_visibility();
                widgets.mark_dirty();
            }
        ));

        // Connect all Entry widgets to mark dirty on change
        {
            let entries: Vec<&gtk4::Entry> = vec![
                &widgets.profile_config.server_addr,
                &widgets.profile_config.username,
                &widgets.profile_config.cert_path,
                &widgets.profile_config.dns_servers,
                &widgets.profile_config.ignored_dns_servers,
                &widgets.profile_config.search_domains,
                &widgets.profile_config.ignored_search_domains,
                &widgets.profile_config.add_routes,
                &widgets.profile_config.ignored_routes,
                &widgets.profile_config.ca_cert,
            ];
            for entry in entries {
                entry.connect_changed(clone!(
                    #[weak]
                    widgets,
                    move |_| widgets.mark_dirty()
                ));
            }
        }

        // PasswordEntry changed
        widgets.profile_config.password.connect_changed(clone!(
            #[weak]
            widgets,
            move |_| widgets.mark_dirty()
        ));
        widgets.profile_config.cert_password.connect_changed(clone!(
            #[weak]
            widgets,
            move |_| widgets.mark_dirty()
        ));

        // DropDown changes
        widgets.profile_config.cert_type.connect_selected_notify(clone!(
            #[weak]
            widgets,
            move |_| widgets.mark_dirty()
        ));
        widgets.profile_config.transport_type.connect_selected_notify(clone!(
            #[weak]
            widgets,
            move |_| widgets.mark_dirty()
        ));

        // Switch changes
        {
            let switches: Vec<&gtk4::Switch> = vec![
                &widgets.profile_config.no_dns,
                &widgets.profile_config.search_domains_as_routes,
                &widgets.profile_config.no_routing,
                &widgets.profile_config.default_route,
                &widgets.profile_config.no_ipv6,
                &widgets.profile_config.no_cert_check,
                &widgets.profile_config.ike_persist,
                &widgets.profile_config.no_keepalive,
                &widgets.profile_config.port_knock,
            ];
            for switch in switches {
                switch.connect_active_notify(clone!(
                    #[weak]
                    widgets,
                    move |_| widgets.mark_dirty()
                ));
            }
        }

        // SpinButton changes
        {
            let spins: Vec<&gtk4::SpinButton> = vec![
                &widgets.profile_config.password_factor,
                &widgets.profile_config.ike_lifetime,
                &widgets.profile_config.ip_lease_duration,
                &widgets.profile_config.mtu,
            ];
            for spin in spins {
                spin.connect_value_changed(clone!(
                    #[weak]
                    widgets,
                    move |_| widgets.mark_dirty()
                ));
            }
        }

        // Save profile button
        widgets.profile_config.save_profile_btn.connect_clicked(clone!(
            #[weak]
            widgets,
            move |_| {
                glib::spawn_future_local(clone!(
                    #[weak]
                    widgets,
                    async move { widgets.save_profile_config().await }
                ));
            }
        ));

        // Reset to defaults button
        widgets.profile_config.reset_defaults_btn.connect_clicked(clone!(
            #[weak]
            widgets,
            move |_| {
                widgets.profile_config.reset_defaults();
                widgets.mark_dirty();
            }
        ));

        // Browse for certificate file
        widgets.profile_config.cert_browse.connect_clicked(clone!(
            #[weak]
            widgets,
            #[weak]
            window,
            move |_| {
                glib::spawn_future_local(clone!(
                    #[weak]
                    widgets,
                    #[weak]
                    window,
                    async move {
                        let dialog = gtk4::FileDialog::builder()
                            .title("Select Certificate File")
                            .modal(true)
                            .build();
                        if let Ok(file) = dialog.open_future(Some(&window)).await {
                            if let Some(path) = file.path() {
                                widgets
                                    .profile_config
                                    .cert_path
                                    .set_text(&path.to_string_lossy());
                            }
                        }
                    }
                ));
            }
        ));

        let mut result = Self {
            window,
            widgets,
            response_rx,
        };

        result.create_layout();

        // Trigger initial profile load
        result.widgets.on_profile_changed();

        result
    }

    pub async fn run(&self) -> ResponseType {
        set_window("settings", Some(self.window.clone()));
        self.window.present();
        let result = self.response_rx.recv().await.unwrap_or(ResponseType::Cancel);
        set_window("settings", None::<Window>);
        result
    }

    pub fn save(&mut self) -> anyhow::Result<()> {
        let mut settings = ClientSettings::load();

        let url = self.widgets.server_url.text().to_string();
        let name = self.widgets.server_name.text().to_string();
        let auto_connect = self.widgets.auto_connect.is_active();

        let icon_theme_idx = self.widgets.icon_theme.selected();
        settings.icon_theme = match icon_theme_idx {
            1 => "dark".to_string(),
            2 => "light".to_string(),
            _ => "system".to_string(),
        };

        let last_profile_id = profile_active_id(&self.widgets);

        // Update or add server
        if let Some(idx) = settings.active_server {
            if let Some(server) = settings.servers.get_mut(idx) {
                server.url = url.clone();
                server.name = name;
                server.auto_connect = auto_connect;
                server.last_profile_id = last_profile_id;
            }
        } else {
            settings.servers.push(ServerConnection {
                name,
                url: url.clone(),
                auto_connect,
                last_profile_id,
                insecure: false,
            });
            settings.active_server = Some(settings.servers.len() - 1);
        }

        settings.save()?;

        // Update the API base URL
        let api = self.widgets.api.clone();
        tokio::spawn(async move {
            api.set_base_url(&url).await;
        });

        Ok(())
    }

    fn form_row(&self, label: &str) -> gtk4::Box {
        let row = gtk4::Box::builder()
            .orientation(Orientation::Horizontal)
            .homogeneous(true)
            .spacing(6)
            .build();

        row.append(
            &gtk4::Label::builder()
                .label(label)
                .halign(Align::Start)
                .build(),
        );
        row
    }

    fn server_section(&self) -> gtk4::Box {
        let section = gtk4::Box::builder()
            .orientation(Orientation::Vertical)
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(6)
            .margin_end(6)
            .spacing(12)
            .build();

        let url_box = self.form_row("Server URL:");
        url_box.append(&self.widgets.server_url);
        section.append(&url_box);

        let name_box = self.form_row("Server Name:");
        name_box.append(&self.widgets.server_name);
        section.append(&name_box);

        section
    }

    fn profile_section(&self) -> gtk4::Box {
        let section = gtk4::Box::builder()
            .orientation(Orientation::Vertical)
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(6)
            .margin_end(6)
            .spacing(12)
            .build();

        let profile_box = self.form_row("Connection Profile:");
        self.widgets.profile_select.set_hexpand(true);
        let btn_box = gtk4::Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(2)
            .homogeneous(false)
            .build();
        btn_box.append(&self.widgets.profile_select);
        btn_box.append(&self.widgets.profile_new);
        btn_box.append(&self.widgets.profile_rename);
        btn_box.append(&self.widgets.profile_delete);
        profile_box.append(&btn_box);
        section.append(&profile_box);

        section
    }

    fn ui_section(&self) -> gtk4::Box {
        let section = gtk4::Box::builder()
            .orientation(Orientation::Vertical)
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(6)
            .margin_end(6)
            .spacing(12)
            .build();

        let icon_theme_box = self.form_row("Icon Theme:");
        let model = gtk4::StringList::new(&["Auto-detect", "Dark", "Light"]);
        self.widgets.icon_theme.set_model(Some(&model));
        let settings = ClientSettings::load();
        let idx = match settings.icon_theme.as_str() {
            "dark" => 1u32,
            "light" => 2,
            _ => 0,
        };
        self.widgets.icon_theme.set_selected(idx);
        icon_theme_box.append(&self.widgets.icon_theme);
        section.append(&icon_theme_box);

        let auto_connect_box = self.form_row("Auto-connect:");
        auto_connect_box.append(&self.widgets.auto_connect);
        section.append(&auto_connect_box);

        section
    }

    /// Build the "Basic" tab of the profile config editor.
    fn profile_basic_tab(&self) -> gtk4::Box {
        let page = gtk4::Box::builder()
            .orientation(Orientation::Vertical)
            .margin_top(8)
            .margin_bottom(8)
            .margin_start(8)
            .margin_end(8)
            .spacing(8)
            .build();

        // Server address
        let row = self.form_row("Server address:");
        row.append(&self.widgets.profile_config.server_addr);
        page.append(&row);

        // Username
        let row = self.form_row("Username:");
        row.append(&self.widgets.profile_config.username);
        page.append(&row);

        // Password
        let row = self.form_row("Password:");
        row.append(&self.widgets.profile_config.password);
        page.append(&row);

        // Login type
        let row = self.form_row("Login type:");
        row.append(&self.widgets.profile_config.login_type);
        page.append(&row);

        // Certificate type (conditional)
        let cert_type_row = self.form_row("Certificate type:");
        cert_type_row.append(&self.widgets.profile_config.cert_type);
        page.append(&cert_type_row);
        // Store the row reference for visibility toggling
        // We need to re-parent -- the ProfileConfigWidgets already has a default Box.
        // We replace the placeholder with the real row:
        self.widgets.profile_config.cert_type_row.set_visible(false);
        // Actually, since we can't re-assign RefCell fields on Rc, we use the
        // built-in box as a wrapper. Let's use the row directly.
        // We'll control visibility on cert_type_row Box via the parent row we just created.
        // Instead, let's just use the row we built as the container:
        // We stored placeholder Boxes in ProfileConfigWidgets, but it's cleaner to
        // just control the real rows. We'll swap them.

        // Certificate path (conditional)
        let cert_path_row = self.form_row("Certificate path:");
        let cert_path_box = gtk4::Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(4)
            .build();
        self.widgets.profile_config.cert_path.set_hexpand(true);
        cert_path_box.append(&self.widgets.profile_config.cert_path);
        cert_path_box.append(&self.widgets.profile_config.cert_browse);
        cert_path_row.append(&cert_path_box);
        page.append(&cert_path_row);

        // Certificate password (conditional)
        let cert_password_row = self.form_row("Certificate password:");
        cert_password_row.append(&self.widgets.profile_config.cert_password);
        page.append(&cert_password_row);

        // Now we need to wire the visibility of the actual rows. Since the
        // placeholder Boxes in ProfileConfigWidgets are not the real rows, we
        // need to bind to the real ones. We'll re-use the placeholders by
        // making cert_type_row/cert_path_row/cert_password_row the actual widgets.
        // But we can't mutate through Rc. Instead, we bind properties:
        //
        // We can bind visible property from the placeholder to the real row.
        // The placeholder is toggled by update_cert_visibility().
        self.widgets
            .profile_config
            .cert_type_row
            .bind_property("visible", &cert_type_row, "visible")
            .sync_create()
            .build();
        self.widgets
            .profile_config
            .cert_path_row
            .bind_property("visible", &cert_path_row, "visible")
            .sync_create()
            .build();
        self.widgets
            .profile_config
            .cert_password_row
            .bind_property("visible", &cert_password_row, "visible")
            .sync_create()
            .build();

        // Initialize visibility
        self.widgets.profile_config.update_cert_visibility();

        page
    }

    /// Build the "Advanced" tab of the profile config editor.
    fn profile_advanced_tab(&self) -> gtk4::ScrolledWindow {
        let scrolled = gtk4::ScrolledWindow::builder()
            .hscrollbar_policy(gtk4::PolicyType::Never)
            .vscrollbar_policy(gtk4::PolicyType::Automatic)
            .build();

        let page = gtk4::Box::builder()
            .orientation(Orientation::Vertical)
            .margin_top(8)
            .margin_bottom(8)
            .margin_start(8)
            .margin_end(8)
            .spacing(12)
            .build();

        // ── DNS ──────────────────────────────────────────────────────────
        let dns_frame = gtk4::Frame::builder().label("DNS").build();
        let dns_box = gtk4::Box::builder()
            .orientation(Orientation::Vertical)
            .margin_top(8)
            .margin_bottom(8)
            .margin_start(8)
            .margin_end(8)
            .spacing(8)
            .build();

        let row = self.form_row("No DNS:");
        row.append(&self.widgets.profile_config.no_dns);
        dns_box.append(&row);

        let row = self.form_row("DNS servers:");
        row.append(&self.widgets.profile_config.dns_servers);
        dns_box.append(&row);

        let row = self.form_row("Ignored DNS servers:");
        row.append(&self.widgets.profile_config.ignored_dns_servers);
        dns_box.append(&row);

        let row = self.form_row("Search domains:");
        row.append(&self.widgets.profile_config.search_domains);
        dns_box.append(&row);

        let row = self.form_row("Ignored search domains:");
        row.append(&self.widgets.profile_config.ignored_search_domains);
        dns_box.append(&row);

        let row = self.form_row("Search domains as routes:");
        row.append(&self.widgets.profile_config.search_domains_as_routes);
        dns_box.append(&row);

        dns_frame.set_child(Some(&dns_box));
        page.append(&dns_frame);

        // ── Routing ──────────────────────────────────────────────────────
        let routing_frame = gtk4::Frame::builder().label("Routing").build();
        let routing_box = gtk4::Box::builder()
            .orientation(Orientation::Vertical)
            .margin_top(8)
            .margin_bottom(8)
            .margin_start(8)
            .margin_end(8)
            .spacing(8)
            .build();

        let row = self.form_row("No routing:");
        row.append(&self.widgets.profile_config.no_routing);
        routing_box.append(&row);

        let row = self.form_row("Default route:");
        row.append(&self.widgets.profile_config.default_route);
        routing_box.append(&row);

        let row = self.form_row("Additional routes:");
        row.append(&self.widgets.profile_config.add_routes);
        routing_box.append(&row);

        let row = self.form_row("Ignored routes:");
        row.append(&self.widgets.profile_config.ignored_routes);
        routing_box.append(&row);

        let row = self.form_row("No IPv6:");
        row.append(&self.widgets.profile_config.no_ipv6);
        routing_box.append(&row);

        routing_frame.set_child(Some(&routing_box));
        page.append(&routing_frame);

        // ── Certificates ─────────────────────────────────────────────────
        let certs_frame = gtk4::Frame::builder().label("Certificates").build();
        let certs_box = gtk4::Box::builder()
            .orientation(Orientation::Vertical)
            .margin_top(8)
            .margin_bottom(8)
            .margin_start(8)
            .margin_end(8)
            .spacing(8)
            .build();

        let row = self.form_row("CA certificates:");
        row.append(&self.widgets.profile_config.ca_cert);
        certs_box.append(&row);

        let row = self.form_row("No cert check:");
        let no_cert_inner = gtk4::Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(8)
            .build();
        no_cert_inner.append(&self.widgets.profile_config.no_cert_check);
        let unsafe_label = gtk4::Label::builder()
            .label("UNSAFE!")
            .css_classes(vec!["error".to_string()])
            .build();
        no_cert_inner.append(&unsafe_label);
        row.append(&no_cert_inner);
        certs_box.append(&row);

        certs_frame.set_child(Some(&certs_box));
        page.append(&certs_frame);

        // ── Other ────────────────────────────────────────────────────────
        let other_frame = gtk4::Frame::builder().label("Other").build();
        let other_box = gtk4::Box::builder()
            .orientation(Orientation::Vertical)
            .margin_top(8)
            .margin_bottom(8)
            .margin_start(8)
            .margin_end(8)
            .spacing(8)
            .build();

        let row = self.form_row("Password factor:");
        row.append(&self.widgets.profile_config.password_factor);
        other_box.append(&row);

        let row = self.form_row("IKE lifetime (sec):");
        row.append(&self.widgets.profile_config.ike_lifetime);
        other_box.append(&row);

        let row = self.form_row("IKE persist:");
        row.append(&self.widgets.profile_config.ike_persist);
        other_box.append(&row);

        let row = self.form_row("No keepalive:");
        row.append(&self.widgets.profile_config.no_keepalive);
        other_box.append(&row);

        let row = self.form_row("Port knock:");
        row.append(&self.widgets.profile_config.port_knock);
        other_box.append(&row);

        let row = self.form_row("IP lease duration:");
        row.append(&self.widgets.profile_config.ip_lease_duration);
        other_box.append(&row);

        let row = self.form_row("MTU:");
        row.append(&self.widgets.profile_config.mtu);
        other_box.append(&row);

        let row = self.form_row("Transport type:");
        row.append(&self.widgets.profile_config.transport_type);
        other_box.append(&row);

        other_frame.set_child(Some(&other_box));
        page.append(&other_frame);

        scrolled.set_child(Some(&page));
        scrolled
    }

    /// Build the profile config notebook (Basic + Advanced tabs).
    fn profile_config_section(&self) -> &gtk4::Notebook {
        let notebook = &self.widgets.profile_config.container;

        let basic_tab = self.profile_basic_tab();
        notebook.append_page(
            &basic_tab,
            Some(&gtk4::Label::new(Some("\u{041e}\u{0441}\u{043d}\u{043e}\u{0432}\u{043d}\u{044b}\u{0435}"))), // "Основные"
        );

        let advanced_tab = self.profile_advanced_tab();
        notebook.append_page(
            &advanced_tab,
            Some(&gtk4::Label::new(Some("\u{0414}\u{043e}\u{043f}\u{043e}\u{043b}\u{043d}\u{0438}\u{0442}\u{0435}\u{043b}\u{044c}\u{043d}\u{043e}"))), // "Дополнительно"
        );

        // Save / Reset buttons row
        let actions_box = gtk4::Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(6)
            .margin_top(4)
            .margin_bottom(4)
            .margin_start(8)
            .margin_end(8)
            .halign(Align::End)
            .build();
        actions_box.append(&self.widgets.profile_config.reset_defaults_btn);
        actions_box.append(&self.widgets.profile_config.save_profile_btn);
        notebook.append_page(
            &actions_box,
            None::<&gtk4::Label>,
        );

        // Actually we don't want the actions as a tab. Let's remove and place
        // them outside. We'll handle this in create_layout instead.
        notebook.remove_page(Some(2));

        notebook.set_visible(false); // Hidden until a profile is selected
        notebook
    }

    fn create_layout(&mut self) {
        let content_area = gtk4::Box::builder()
            .orientation(Orientation::Vertical)
            .margin_top(6)
            .margin_start(6)
            .margin_end(6)
            .margin_bottom(6)
            .build();
        self.window.set_child(Some(&content_area));

        let notebook = gtk4::Notebook::new();
        notebook.set_vexpand(true);
        content_area.append(&notebook);
        content_area.append(&self.widgets.error);
        content_area.append(&self.widgets.button_box);

        // General tab
        let general = gtk4::Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(6)
            .build();
        general.append(&self.server_section());
        general.append(&self.profile_section());
        general.append(&self.ui_section());

        notebook.append_page(&general, Some(&gtk4::Label::new(Some("General"))));

        // Profile Config tab with inner notebook
        let profile_page = gtk4::Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(6)
            .build();

        let config_notebook = self.profile_config_section();
        config_notebook.set_vexpand(true);
        profile_page.append(config_notebook);

        // Save/Reset row below the inner notebook
        let actions_box = gtk4::Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(6)
            .margin_top(4)
            .margin_bottom(4)
            .margin_start(8)
            .margin_end(8)
            .halign(Align::End)
            .build();
        actions_box.append(&self.widgets.profile_config.reset_defaults_btn);
        actions_box.append(&self.widgets.profile_config.save_profile_btn);
        profile_page.append(&actions_box);

        notebook.append_page(&profile_page, Some(&gtk4::Label::new(Some("Profile Config"))));

        self.window.set_default_size(600, 550);
    }
}

impl Drop for SettingsDialog {
    fn drop(&mut self) {
        self.window.close();
    }
}

pub fn start_settings_dialog<W: IsA<Window>>(
    parent: W,
    sender: Sender<TrayCommand>,
    api: ApiClient,
    auth: AuthManager,
    profile_store: Arc<ProfileStore>,
) {
    if let Some(window) = get_window("settings") {
        window.present();
        return;
    }

    let mut dialog = SettingsDialog::new(parent, api, auth, profile_store);
    let sender = sender.clone();
    glib::spawn_future_local(async move {
        loop {
            let response = dialog.run().await;

            match response {
                ResponseType::Ok | ResponseType::Apply => {
                    if let Err(e) = dialog.save() {
                        warn!("{}", e);
                    } else {
                        let _ = sender.send(TrayCommand::Update(None)).await;
                    }
                }
                _ => {}
            }
            if response != ResponseType::Apply {
                break;
            }
        }
    });
}

async fn show_entry_dialog(parent: &Window, title: &str, label: &str, value: &str) -> Option<String> {
    let window = Window::builder().title(title).transient_for(parent).modal(true).build();

    let ok = gtk4::Button::builder().label("OK").build();
    ok.set_sensitive(!value.trim().is_empty());

    let cancel = gtk4::Button::builder().label("Cancel").build();

    let button_box = gtk4::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(6)
        .margin_top(6)
        .margin_start(6)
        .margin_end(6)
        .margin_bottom(6)
        .homogeneous(true)
        .halign(Align::End)
        .valign(Align::End)
        .build();

    button_box.append(&ok);
    button_box.append(&cancel);

    let content = gtk4::Box::builder().orientation(Orientation::Vertical).build();
    window.set_child(Some(&content));
    window.set_default_widget(Some(&ok));

    let inner = gtk4::Box::builder()
        .orientation(Orientation::Vertical)
        .margin_bottom(6)
        .margin_top(6)
        .margin_start(6)
        .margin_end(6)
        .spacing(6)
        .build();

    inner.append(&gtk4::Label::builder().label(label).halign(Align::Start).build());

    let entry = gtk4::Entry::builder()
        .name("entry")
        .activates_default(true)
        .text(value)
        .build();

    entry.connect_changed(clone!(
        #[weak]
        ok,
        move |entry| {
            ok.set_sensitive(!entry.text().trim().is_empty());
        }
    ));

    inner.append(&entry);
    content.append(&inner);
    content.append(&button_box);

    let (tx, rx) = async_channel::bounded::<bool>(1);

    let tx_ok = tx.clone();
    ok.connect_clicked(clone!(
        #[weak]
        window,
        #[weak]
        entry,
        move |_| {
            if !entry.text().trim().is_empty() {
                let _ = tx_ok.try_send(true);
                window.close();
            }
        }
    ));

    let tx_cancel = tx.clone();
    cancel.connect_clicked(clone!(
        #[weak]
        window,
        move |_| {
            let _ = tx_cancel.try_send(false);
            window.close();
        }
    ));

    let tx_entry = tx.clone();
    entry.connect_activate(clone!(
        #[weak]
        window,
        #[weak]
        entry,
        move |_| {
            if !entry.text().trim().is_empty() {
                let _ = tx_entry.try_send(true);
                window.close();
            }
        }
    ));

    window.connect_close_request(move |_| {
        let _ = tx.try_send(false);
        glib::Propagation::Proceed
    });

    {
        let key_controller = gtk4::EventControllerKey::new();
        key_controller.connect_key_pressed(clone!(
            #[weak]
            window,
            #[upgrade_or]
            glib::Propagation::Proceed,
            move |_, key, _, _| {
                if key == gtk4::gdk::Key::Escape {
                    window.close();
                    glib::Propagation::Stop
                } else {
                    glib::Propagation::Proceed
                }
            }
        ));
        window.add_controller(key_controller);
    }

    window.present();
    let current_size = window.default_size();
    let new_width = current_size.0.max(400);
    window.set_default_size(new_width, current_size.1);

    let ok_clicked = rx.recv().await.unwrap_or(false);
    if ok_clicked { Some(entry.text().into()) } else { None }
}
