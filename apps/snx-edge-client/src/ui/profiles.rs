use gtk4::prelude::*;
use libadwaita as adw;
use adw::prelude::*;

// ---------------------------------------------------------------------------
// Widget names used to locate fields inside the window via `widget_name()`.
// ---------------------------------------------------------------------------

const W_SERVER: &str = "field_server";
const W_LOGIN_TYPE: &str = "field_login_type";
const W_USERNAME: &str = "field_username";
const W_PASSWORD: &str = "field_password";

const W_CERT_TYPE: &str = "field_cert_type";
const W_CERT_FILE: &str = "field_cert_file";
const W_CERT_PASSWORD: &str = "field_cert_password";

const W_NO_DNS: &str = "field_no_dns";
const W_DNS_SERVERS: &str = "field_dns_servers";
const W_IGNORED_DNS_SERVERS: &str = "field_ignored_dns_servers";
const W_SEARCH_DOMAINS: &str = "field_search_domains";
const W_IGNORED_SEARCH_DOMAINS: &str = "field_ignored_search_domains";
const W_SEARCH_DOMAINS_AS_ROUTES: &str = "field_search_domains_as_routes";

const W_NO_ROUTING: &str = "field_no_routing";
const W_DEFAULT_ROUTE: &str = "field_default_route";
const W_ADD_ROUTES: &str = "field_add_routes";
const W_IGNORED_ROUTES: &str = "field_ignored_routes";
const W_DISABLE_IPV6: &str = "field_disable_ipv6";

const W_NO_CERT_CHECK: &str = "field_no_cert_check";
const W_CA_CERTS: &str = "field_ca_certs";

const W_PASSWORD_FACTOR: &str = "field_password_factor";
const W_IKE_LIFETIME: &str = "field_ike_lifetime";
const W_IKE_PERSIST: &str = "field_ike_persist";
const W_NO_KEEPALIVE: &str = "field_no_keepalive";
const W_PORT_KNOCK: &str = "field_port_knock";
const W_MTU: &str = "field_mtu";
const W_TRANSPORT: &str = "field_transport";

const W_PROFILE_LIST: &str = "field_profile_list";
const W_SAVE_BTN: &str = "field_save_btn";
const W_DISCARD_BTN: &str = "field_discard_btn";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Recursively find the first descendant with the given widget name.
fn find_widget_by_name<W: IsA<gtk4::Widget>>(root: &gtk4::Widget, name: &str) -> Option<W> {
    if root.widget_name() == name {
        return root.clone().downcast::<W>().ok();
    }
    let mut child = root.first_child();
    while let Some(c) = child {
        if let Some(found) = find_widget_by_name::<W>(&c, name) {
            return Some(found);
        }
        child = c.next_sibling();
    }
    None
}

/// Convenience: build a `gtk4::StringList` from a slice of display labels.
fn string_list(items: &[&str]) -> gtk4::StringList {
    let list = gtk4::StringList::new(&[]);
    for item in items {
        list.append(item);
    }
    list
}

// ---------------------------------------------------------------------------
// Basic tab
// ---------------------------------------------------------------------------

fn build_basic_page() -> adw::PreferencesPage {
    let page = adw::PreferencesPage::new();
    page.set_title("Basic");
    page.set_icon_name(Some("network-server-symbolic"));

    // -- Connection group ---------------------------------------------------
    let conn_group = adw::PreferencesGroup::new();
    conn_group.set_title("Connection");

    let server_row = adw::EntryRow::new();
    server_row.set_title("VPN Server");
    server_row.set_widget_name(W_SERVER);
    conn_group.add(&server_row);

    let login_type_row = adw::ComboRow::new();
    login_type_row.set_title("Login Type");
    login_type_row.set_widget_name(W_LOGIN_TYPE);
    login_type_row.set_model(Some(&string_list(&["password", "certificate"])));
    conn_group.add(&login_type_row);

    let username_row = adw::EntryRow::new();
    username_row.set_title("Username");
    username_row.set_widget_name(W_USERNAME);
    conn_group.add(&username_row);

    let password_row = adw::PasswordEntryRow::new();
    password_row.set_title("Password");
    password_row.set_widget_name(W_PASSWORD);
    conn_group.add(&password_row);

    page.add(&conn_group);

    // -- Certificate group --------------------------------------------------
    let cert_group = adw::PreferencesGroup::new();
    cert_group.set_title("Certificate");

    let cert_type_row = adw::ComboRow::new();
    cert_type_row.set_title("Certificate Type");
    cert_type_row.set_widget_name(W_CERT_TYPE);
    cert_type_row.set_model(Some(&string_list(&["pkcs12", "pkcs8", "pkcs11"])));
    cert_group.add(&cert_type_row);

    let cert_file_row = adw::ActionRow::new();
    cert_file_row.set_title("Certificate File");
    cert_file_row.set_widget_name(W_CERT_FILE);
    let cert_file_btn = gtk4::Button::builder()
        .label("Browse...")
        .valign(gtk4::Align::Center)
        .build();
    cert_file_btn.connect_clicked(|btn| {
        let Some(root) = btn.root() else { return };
        let Some(window) = root.downcast_ref::<gtk4::Window>() else { return };

        let filter = gtk4::FileFilter::new();
        filter.set_name(Some("Certificates"));
        filter.add_pattern("*.p12");
        filter.add_pattern("*.pfx");
        filter.add_pattern("*.pem");
        filter.add_pattern("*.crt");
        filter.add_pattern("*.key");
        filter.add_pattern("*");

        let filter_store = gtk4::gio::ListStore::new::<gtk4::FileFilter>();
        filter_store.append(&filter);

        let dialog = gtk4::FileDialog::builder()
            .title("Select Certificate File")
            .filters(&filter_store)
            .build();

        let win = window.clone();
        let win2 = window.clone();
        dialog.open(Some(&win), None::<&gtk4::gio::Cancellable>, move |result| {
            if let Ok(file) = result {
                if let Some(path) = file.path() {
                    // Walk up to find the ActionRow and set subtitle with the path
                    if let Some(row) = find_widget_by_name::<adw::ActionRow>(
                        win2.upcast_ref::<gtk4::Widget>(),
                        W_CERT_FILE,
                    ) {
                        row.set_subtitle(&path.to_string_lossy());
                    }
                }
            }
        });
    });
    cert_file_row.add_suffix(&cert_file_btn);
    cert_file_row.set_activatable_widget(Some(&cert_file_btn));
    cert_group.add(&cert_file_row);

    let cert_pass_row = adw::PasswordEntryRow::new();
    cert_pass_row.set_title("Certificate Password");
    cert_pass_row.set_widget_name(W_CERT_PASSWORD);
    cert_group.add(&cert_pass_row);

    page.add(&cert_group);

    page
}

// ---------------------------------------------------------------------------
// Advanced tab
// ---------------------------------------------------------------------------

fn build_advanced_page() -> adw::PreferencesPage {
    let page = adw::PreferencesPage::new();
    page.set_title("Advanced");
    page.set_icon_name(Some("emblem-system-symbolic"));

    // -- DNS group ----------------------------------------------------------
    let dns_group = adw::PreferencesGroup::new();
    dns_group.set_title("DNS");

    let no_dns = adw::SwitchRow::new();
    no_dns.set_title("Don't modify DNS");
    no_dns.set_widget_name(W_NO_DNS);
    dns_group.add(&no_dns);

    let dns_servers = adw::EntryRow::new();
    dns_servers.set_title("DNS Servers");
    dns_servers.set_widget_name(W_DNS_SERVERS);
    dns_group.add(&dns_servers);

    let ignored_dns = adw::EntryRow::new();
    ignored_dns.set_title("Ignored DNS Servers");
    ignored_dns.set_widget_name(W_IGNORED_DNS_SERVERS);
    dns_group.add(&ignored_dns);

    let search_domains = adw::EntryRow::new();
    search_domains.set_title("Search Domains");
    search_domains.set_widget_name(W_SEARCH_DOMAINS);
    dns_group.add(&search_domains);

    let ignored_search = adw::EntryRow::new();
    ignored_search.set_title("Ignored Search Domains");
    ignored_search.set_widget_name(W_IGNORED_SEARCH_DOMAINS);
    dns_group.add(&ignored_search);

    let search_as_routes = adw::SwitchRow::new();
    search_as_routes.set_title("Search domains as routes");
    search_as_routes.set_widget_name(W_SEARCH_DOMAINS_AS_ROUTES);
    dns_group.add(&search_as_routes);

    page.add(&dns_group);

    // -- Routing group ------------------------------------------------------
    let routing_group = adw::PreferencesGroup::new();
    routing_group.set_title("Routing");

    let no_routing = adw::SwitchRow::new();
    no_routing.set_title("Ignore all routes");
    no_routing.set_widget_name(W_NO_ROUTING);
    routing_group.add(&no_routing);

    let default_route = adw::SwitchRow::new();
    default_route.set_title("Default route through tunnel");
    default_route.set_widget_name(W_DEFAULT_ROUTE);
    routing_group.add(&default_route);

    let add_routes = adw::EntryRow::new();
    add_routes.set_title("Additional Routes");
    add_routes.set_widget_name(W_ADD_ROUTES);
    routing_group.add(&add_routes);

    let ignored_routes = adw::EntryRow::new();
    ignored_routes.set_title("Ignored Routes");
    ignored_routes.set_widget_name(W_IGNORED_ROUTES);
    routing_group.add(&ignored_routes);

    let disable_ipv6 = adw::SwitchRow::new();
    disable_ipv6.set_title("Disable IPv6");
    disable_ipv6.set_widget_name(W_DISABLE_IPV6);
    routing_group.add(&disable_ipv6);

    page.add(&routing_group);

    // -- Security group -----------------------------------------------------
    let security_group = adw::PreferencesGroup::new();
    security_group.set_title("Security");

    let no_cert_check = adw::SwitchRow::new();
    no_cert_check.set_title("Skip TLS verification");
    no_cert_check.set_subtitle("Warning: disabling certificate verification is insecure");
    no_cert_check.set_widget_name(W_NO_CERT_CHECK);
    security_group.add(&no_cert_check);

    let ca_certs = adw::EntryRow::new();
    ca_certs.set_title("CA Certificates");
    ca_certs.set_widget_name(W_CA_CERTS);
    security_group.add(&ca_certs);

    page.add(&security_group);

    // -- Advanced group -----------------------------------------------------
    let adv_group = adw::PreferencesGroup::new();
    adv_group.set_title("Advanced");

    let password_factor = adw::SpinRow::new(
        Some(&gtk4::Adjustment::new(1.0, 1.0, 10.0, 1.0, 1.0, 0.0)),
        1.0,
        0,
    );
    password_factor.set_title("Password Factor");
    password_factor.set_widget_name(W_PASSWORD_FACTOR);
    adv_group.add(&password_factor);

    let ike_lifetime = adw::SpinRow::new(
        Some(&gtk4::Adjustment::new(28800.0, 300.0, 86400.0, 100.0, 1000.0, 0.0)),
        100.0,
        0,
    );
    ike_lifetime.set_title("IKE Lifetime (sec)");
    ike_lifetime.set_widget_name(W_IKE_LIFETIME);
    adv_group.add(&ike_lifetime);

    let ike_persist = adw::SwitchRow::new();
    ike_persist.set_title("IKE Persist");
    ike_persist.set_widget_name(W_IKE_PERSIST);
    adv_group.add(&ike_persist);

    let no_keepalive = adw::SwitchRow::new();
    no_keepalive.set_title("No Keepalive");
    no_keepalive.set_widget_name(W_NO_KEEPALIVE);
    adv_group.add(&no_keepalive);

    let port_knock = adw::SwitchRow::new();
    port_knock.set_title("Port Knocking");
    port_knock.set_widget_name(W_PORT_KNOCK);
    adv_group.add(&port_knock);

    let mtu = adw::SpinRow::new(
        Some(&gtk4::Adjustment::new(1350.0, 576.0, 9000.0, 1.0, 10.0, 0.0)),
        1.0,
        0,
    );
    mtu.set_title("MTU");
    mtu.set_widget_name(W_MTU);
    adv_group.add(&mtu);

    let transport = adw::ComboRow::new();
    transport.set_title("Transport");
    transport.set_widget_name(W_TRANSPORT);
    transport.set_model(Some(&string_list(&["auto", "udp", "tcpt"])));
    adv_group.add(&transport);

    page.add(&adv_group);

    page
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Build the VPN profile editor window.
///
/// The returned `adw::Window` is transient for `parent` and contains a
/// split-pane layout: profile list on the left, tabbed editor on the right.
pub fn build_profiles_window(parent: &impl IsA<gtk4::Window>) -> adw::Window {
    let window = adw::Window::builder()
        .title("VPN Profiles")
        .default_width(900)
        .default_height(700)
        .transient_for(parent)
        .modal(true)
        .build();

    // ---- Left pane: profile list ------------------------------------------

    let profile_list = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::Single)
        .css_classes(vec!["navigation-sidebar".to_string()])
        .vexpand(true)
        .build();
    profile_list.set_widget_name(W_PROFILE_LIST);

    let add_btn = gtk4::Button::builder()
        .label("Add")
        .css_classes(vec!["flat".to_string()])
        .hexpand(true)
        .build();

    let delete_btn = gtk4::Button::builder()
        .label("Delete")
        .css_classes(vec!["flat".to_string(), "destructive-action".to_string()])
        .hexpand(true)
        .build();

    let btn_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(6)
        .margin_top(6)
        .margin_bottom(6)
        .margin_start(6)
        .margin_end(6)
        .halign(gtk4::Align::Center)
        .build();
    btn_box.append(&add_btn);
    btn_box.append(&delete_btn);

    let left_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .width_request(220)
        .build();

    let scrolled_list = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .build();
    scrolled_list.set_child(Some(&profile_list));

    left_box.append(&scrolled_list);
    left_box.append(&btn_box);

    // ---- Right pane: tabbed editor ----------------------------------------

    let view_stack = adw::ViewStack::new();

    let basic_page = build_basic_page();
    let basic_scrolled = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .hexpand(true)
        .build();
    basic_scrolled.set_child(Some(&basic_page));
    view_stack.add_titled_with_icon(&basic_scrolled, Some("basic"), "Basic", "network-server-symbolic");

    let advanced_page = build_advanced_page();
    let advanced_scrolled = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .hexpand(true)
        .build();
    advanced_scrolled.set_child(Some(&advanced_page));
    view_stack.add_titled_with_icon(&advanced_scrolled, Some("advanced"), "Advanced", "emblem-system-symbolic");

    let view_switcher = adw::ViewSwitcher::builder()
        .stack(&view_stack)
        .policy(adw::ViewSwitcherPolicy::Wide)
        .build();

    // ---- Bottom bar -------------------------------------------------------

    let save_btn = gtk4::Button::builder()
        .label("Save")
        .css_classes(vec!["suggested-action".to_string()])
        .build();
    save_btn.set_widget_name(W_SAVE_BTN);

    let discard_btn = gtk4::Button::builder()
        .label("Discard")
        .css_classes(vec!["destructive-action".to_string()])
        .visible(false)
        .build();
    discard_btn.set_widget_name(W_DISCARD_BTN);

    let bottom_bar = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .margin_top(6)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .halign(gtk4::Align::End)
        .build();
    bottom_bar.append(&discard_btn);
    bottom_bar.append(&save_btn);

    // ---- Right-side vertical layout: switcher + stack + bar ---------------

    let right_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .hexpand(true)
        .build();

    let switcher_bar = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .halign(gtk4::Align::Center)
        .margin_top(6)
        .margin_bottom(6)
        .build();
    switcher_bar.append(&view_switcher);

    right_box.append(&switcher_bar);
    right_box.append(&gtk4::Separator::new(gtk4::Orientation::Horizontal));
    right_box.append(&view_stack);
    right_box.append(&gtk4::Separator::new(gtk4::Orientation::Horizontal));
    right_box.append(&bottom_bar);

    // ---- Assemble panes ---------------------------------------------------

    let paned = gtk4::Paned::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .start_child(&left_box)
        .end_child(&right_box)
        .position(220)
        .shrink_start_child(false)
        .shrink_end_child(false)
        .vexpand(true)
        .build();

    // Wrap in a header bar + toolbarview for proper adw styling
    let header = adw::HeaderBar::new();
    header.set_title_widget(Some(&gtk4::Label::new(Some("VPN Profiles"))));

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&paned));

    window.set_content(Some(&toolbar_view));

    // ---- Wire up Add / Delete buttons (skeleton signals) ------------------

    {
        let profile_list = profile_list.clone();
        add_btn.connect_clicked(move |_| {
            let row = gtk4::Label::new(Some("New Profile"));
            row.set_halign(gtk4::Align::Start);
            row.set_margin_top(6);
            row.set_margin_bottom(6);
            row.set_margin_start(12);
            row.set_margin_end(12);
            profile_list.append(&row);
            // Select the newly added row
            if let Some(last) = profile_list.last_child() {
                if let Some(list_row) = last.downcast_ref::<gtk4::ListBoxRow>() {
                    profile_list.select_row(Some(list_row));
                }
            }
        });
    }

    {
        let profile_list = profile_list.clone();
        delete_btn.connect_clicked(move |_| {
            if let Some(selected) = profile_list.selected_row() {
                profile_list.remove(&selected);
            }
        });
    }

    window
}

// ---------------------------------------------------------------------------
// populate_profile — fill all editor fields from a JSON value
// ---------------------------------------------------------------------------

/// Populate every editor field in the profiles window from a profile JSON
/// object.  Keys match the `serde_json::Value` field names produced by the
/// server API (snake_case).
pub fn populate_profile(window: &adw::Window, profile: &serde_json::Value) {
    let root = window.upcast_ref::<gtk4::Widget>();

    // --- Basic tab ---------------------------------------------------------

    if let Some(v) = profile.get("server").and_then(|v| v.as_str()) {
        if let Some(w) = find_widget_by_name::<adw::EntryRow>(root, W_SERVER) {
            w.set_text(v);
        }
    }

    if let Some(v) = profile.get("login_type").and_then(|v| v.as_str()) {
        if let Some(w) = find_widget_by_name::<adw::ComboRow>(root, W_LOGIN_TYPE) {
            let idx = match v {
                "certificate" => 1,
                _ => 0, // "password" or fallback
            };
            w.set_selected(idx);
        }
    }

    if let Some(v) = profile.get("username").and_then(|v| v.as_str()) {
        if let Some(w) = find_widget_by_name::<adw::EntryRow>(root, W_USERNAME) {
            w.set_text(v);
        }
    }

    if let Some(v) = profile.get("password").and_then(|v| v.as_str()) {
        if let Some(w) = find_widget_by_name::<adw::PasswordEntryRow>(root, W_PASSWORD) {
            w.set_text(v);
        }
    }

    // Certificate
    if let Some(v) = profile.get("cert_type").and_then(|v| v.as_str()) {
        if let Some(w) = find_widget_by_name::<adw::ComboRow>(root, W_CERT_TYPE) {
            let idx = match v {
                "pkcs8" => 1,
                "pkcs11" => 2,
                _ => 0, // "pkcs12"
            };
            w.set_selected(idx);
        }
    }

    if let Some(v) = profile.get("cert_file").and_then(|v| v.as_str()) {
        if let Some(w) = find_widget_by_name::<adw::ActionRow>(root, W_CERT_FILE) {
            w.set_subtitle(v);
        }
    }

    if let Some(v) = profile.get("cert_password").and_then(|v| v.as_str()) {
        if let Some(w) = find_widget_by_name::<adw::PasswordEntryRow>(root, W_CERT_PASSWORD) {
            w.set_text(v);
        }
    }

    // --- Advanced tab: DNS -------------------------------------------------

    if let Some(v) = profile.get("no_dns").and_then(|v| v.as_bool()) {
        if let Some(w) = find_widget_by_name::<adw::SwitchRow>(root, W_NO_DNS) {
            w.set_active(v);
        }
    }

    if let Some(v) = profile.get("dns_servers").and_then(|v| v.as_str()) {
        if let Some(w) = find_widget_by_name::<adw::EntryRow>(root, W_DNS_SERVERS) {
            w.set_text(v);
        }
    }

    if let Some(v) = profile.get("ignored_dns_servers").and_then(|v| v.as_str()) {
        if let Some(w) = find_widget_by_name::<adw::EntryRow>(root, W_IGNORED_DNS_SERVERS) {
            w.set_text(v);
        }
    }

    if let Some(v) = profile.get("search_domains").and_then(|v| v.as_str()) {
        if let Some(w) = find_widget_by_name::<adw::EntryRow>(root, W_SEARCH_DOMAINS) {
            w.set_text(v);
        }
    }

    if let Some(v) = profile.get("ignored_search_domains").and_then(|v| v.as_str()) {
        if let Some(w) = find_widget_by_name::<adw::EntryRow>(root, W_IGNORED_SEARCH_DOMAINS) {
            w.set_text(v);
        }
    }

    if let Some(v) = profile.get("search_domains_as_routes").and_then(|v| v.as_bool()) {
        if let Some(w) = find_widget_by_name::<adw::SwitchRow>(root, W_SEARCH_DOMAINS_AS_ROUTES) {
            w.set_active(v);
        }
    }

    // --- Advanced tab: Routing ---------------------------------------------

    if let Some(v) = profile.get("no_routing").and_then(|v| v.as_bool()) {
        if let Some(w) = find_widget_by_name::<adw::SwitchRow>(root, W_NO_ROUTING) {
            w.set_active(v);
        }
    }

    if let Some(v) = profile.get("default_route").and_then(|v| v.as_bool()) {
        if let Some(w) = find_widget_by_name::<adw::SwitchRow>(root, W_DEFAULT_ROUTE) {
            w.set_active(v);
        }
    }

    if let Some(v) = profile.get("add_routes").and_then(|v| v.as_str()) {
        if let Some(w) = find_widget_by_name::<adw::EntryRow>(root, W_ADD_ROUTES) {
            w.set_text(v);
        }
    }

    if let Some(v) = profile.get("ignored_routes").and_then(|v| v.as_str()) {
        if let Some(w) = find_widget_by_name::<adw::EntryRow>(root, W_IGNORED_ROUTES) {
            w.set_text(v);
        }
    }

    if let Some(v) = profile.get("disable_ipv6").and_then(|v| v.as_bool()) {
        if let Some(w) = find_widget_by_name::<adw::SwitchRow>(root, W_DISABLE_IPV6) {
            w.set_active(v);
        }
    }

    // --- Advanced tab: Security --------------------------------------------

    if let Some(v) = profile.get("no_cert_check").and_then(|v| v.as_bool()) {
        if let Some(w) = find_widget_by_name::<adw::SwitchRow>(root, W_NO_CERT_CHECK) {
            w.set_active(v);
        }
    }

    if let Some(v) = profile.get("ca_certs").and_then(|v| v.as_str()) {
        if let Some(w) = find_widget_by_name::<adw::EntryRow>(root, W_CA_CERTS) {
            w.set_text(v);
        }
    }

    // --- Advanced tab: Advanced --------------------------------------------

    if let Some(v) = profile.get("password_factor").and_then(|v| v.as_f64()) {
        if let Some(w) = find_widget_by_name::<adw::SpinRow>(root, W_PASSWORD_FACTOR) {
            w.set_value(v);
        }
    }

    if let Some(v) = profile.get("ike_lifetime").and_then(|v| v.as_f64()) {
        if let Some(w) = find_widget_by_name::<adw::SpinRow>(root, W_IKE_LIFETIME) {
            w.set_value(v);
        }
    }

    if let Some(v) = profile.get("ike_persist").and_then(|v| v.as_bool()) {
        if let Some(w) = find_widget_by_name::<adw::SwitchRow>(root, W_IKE_PERSIST) {
            w.set_active(v);
        }
    }

    if let Some(v) = profile.get("no_keepalive").and_then(|v| v.as_bool()) {
        if let Some(w) = find_widget_by_name::<adw::SwitchRow>(root, W_NO_KEEPALIVE) {
            w.set_active(v);
        }
    }

    if let Some(v) = profile.get("port_knock").and_then(|v| v.as_bool()) {
        if let Some(w) = find_widget_by_name::<adw::SwitchRow>(root, W_PORT_KNOCK) {
            w.set_active(v);
        }
    }

    if let Some(v) = profile.get("mtu").and_then(|v| v.as_f64()) {
        if let Some(w) = find_widget_by_name::<adw::SpinRow>(root, W_MTU) {
            w.set_value(v);
        }
    }

    if let Some(v) = profile.get("transport").and_then(|v| v.as_str()) {
        if let Some(w) = find_widget_by_name::<adw::ComboRow>(root, W_TRANSPORT) {
            let idx = match v {
                "udp" => 1,
                "tcpt" => 2,
                _ => 0, // "auto"
            };
            w.set_selected(idx);
        }
    }
}

// ---------------------------------------------------------------------------
// collect_profile — read all editor fields into a JSON object
// ---------------------------------------------------------------------------

/// Read every editor field and return a `serde_json::Value::Object` suitable
/// for sending back to the server API.
pub fn collect_profile(window: &adw::Window) -> serde_json::Value {
    let root = window.upcast_ref::<gtk4::Widget>();
    let mut map = serde_json::Map::new();

    // --- Basic tab ---------------------------------------------------------

    if let Some(w) = find_widget_by_name::<adw::EntryRow>(root, W_SERVER) {
        map.insert("server".into(), serde_json::Value::String(w.text().to_string()));
    }

    if let Some(w) = find_widget_by_name::<adw::ComboRow>(root, W_LOGIN_TYPE) {
        let val = match w.selected() {
            1 => "certificate",
            _ => "password",
        };
        map.insert("login_type".into(), serde_json::Value::String(val.into()));
    }

    if let Some(w) = find_widget_by_name::<adw::EntryRow>(root, W_USERNAME) {
        map.insert("username".into(), serde_json::Value::String(w.text().to_string()));
    }

    if let Some(w) = find_widget_by_name::<adw::PasswordEntryRow>(root, W_PASSWORD) {
        map.insert("password".into(), serde_json::Value::String(w.text().to_string()));
    }

    // Certificate
    if let Some(w) = find_widget_by_name::<adw::ComboRow>(root, W_CERT_TYPE) {
        let val = match w.selected() {
            1 => "pkcs8",
            2 => "pkcs11",
            _ => "pkcs12",
        };
        map.insert("cert_type".into(), serde_json::Value::String(val.into()));
    }

    if let Some(w) = find_widget_by_name::<adw::ActionRow>(root, W_CERT_FILE) {
        let subtitle = w.subtitle().map(|s| s.to_string()).unwrap_or_default();
        map.insert("cert_file".into(), serde_json::Value::String(subtitle));
    }

    if let Some(w) = find_widget_by_name::<adw::PasswordEntryRow>(root, W_CERT_PASSWORD) {
        map.insert("cert_password".into(), serde_json::Value::String(w.text().to_string()));
    }

    // --- Advanced tab: DNS -------------------------------------------------

    if let Some(w) = find_widget_by_name::<adw::SwitchRow>(root, W_NO_DNS) {
        map.insert("no_dns".into(), serde_json::Value::Bool(w.is_active()));
    }

    if let Some(w) = find_widget_by_name::<adw::EntryRow>(root, W_DNS_SERVERS) {
        map.insert("dns_servers".into(), serde_json::Value::String(w.text().to_string()));
    }

    if let Some(w) = find_widget_by_name::<adw::EntryRow>(root, W_IGNORED_DNS_SERVERS) {
        map.insert("ignored_dns_servers".into(), serde_json::Value::String(w.text().to_string()));
    }

    if let Some(w) = find_widget_by_name::<adw::EntryRow>(root, W_SEARCH_DOMAINS) {
        map.insert("search_domains".into(), serde_json::Value::String(w.text().to_string()));
    }

    if let Some(w) = find_widget_by_name::<adw::EntryRow>(root, W_IGNORED_SEARCH_DOMAINS) {
        map.insert(
            "ignored_search_domains".into(),
            serde_json::Value::String(w.text().to_string()),
        );
    }

    if let Some(w) = find_widget_by_name::<adw::SwitchRow>(root, W_SEARCH_DOMAINS_AS_ROUTES) {
        map.insert("search_domains_as_routes".into(), serde_json::Value::Bool(w.is_active()));
    }

    // --- Advanced tab: Routing ---------------------------------------------

    if let Some(w) = find_widget_by_name::<adw::SwitchRow>(root, W_NO_ROUTING) {
        map.insert("no_routing".into(), serde_json::Value::Bool(w.is_active()));
    }

    if let Some(w) = find_widget_by_name::<adw::SwitchRow>(root, W_DEFAULT_ROUTE) {
        map.insert("default_route".into(), serde_json::Value::Bool(w.is_active()));
    }

    if let Some(w) = find_widget_by_name::<adw::EntryRow>(root, W_ADD_ROUTES) {
        map.insert("add_routes".into(), serde_json::Value::String(w.text().to_string()));
    }

    if let Some(w) = find_widget_by_name::<adw::EntryRow>(root, W_IGNORED_ROUTES) {
        map.insert("ignored_routes".into(), serde_json::Value::String(w.text().to_string()));
    }

    if let Some(w) = find_widget_by_name::<adw::SwitchRow>(root, W_DISABLE_IPV6) {
        map.insert("disable_ipv6".into(), serde_json::Value::Bool(w.is_active()));
    }

    // --- Advanced tab: Security --------------------------------------------

    if let Some(w) = find_widget_by_name::<adw::SwitchRow>(root, W_NO_CERT_CHECK) {
        map.insert("no_cert_check".into(), serde_json::Value::Bool(w.is_active()));
    }

    if let Some(w) = find_widget_by_name::<adw::EntryRow>(root, W_CA_CERTS) {
        map.insert("ca_certs".into(), serde_json::Value::String(w.text().to_string()));
    }

    // --- Advanced tab: Advanced --------------------------------------------

    if let Some(w) = find_widget_by_name::<adw::SpinRow>(root, W_PASSWORD_FACTOR) {
        map.insert("password_factor".into(), serde_json::json!(w.value() as u32));
    }

    if let Some(w) = find_widget_by_name::<adw::SpinRow>(root, W_IKE_LIFETIME) {
        map.insert("ike_lifetime".into(), serde_json::json!(w.value() as u32));
    }

    if let Some(w) = find_widget_by_name::<adw::SwitchRow>(root, W_IKE_PERSIST) {
        map.insert("ike_persist".into(), serde_json::Value::Bool(w.is_active()));
    }

    if let Some(w) = find_widget_by_name::<adw::SwitchRow>(root, W_NO_KEEPALIVE) {
        map.insert("no_keepalive".into(), serde_json::Value::Bool(w.is_active()));
    }

    if let Some(w) = find_widget_by_name::<adw::SwitchRow>(root, W_PORT_KNOCK) {
        map.insert("port_knock".into(), serde_json::Value::Bool(w.is_active()));
    }

    if let Some(w) = find_widget_by_name::<adw::SpinRow>(root, W_MTU) {
        map.insert("mtu".into(), serde_json::json!(w.value() as u32));
    }

    if let Some(w) = find_widget_by_name::<adw::ComboRow>(root, W_TRANSPORT) {
        let val = match w.selected() {
            1 => "udp",
            2 => "tcpt",
            _ => "auto",
        };
        map.insert("transport".into(), serde_json::Value::String(val.into()));
    }

    serde_json::Value::Object(map)
}

// ---------------------------------------------------------------------------
// set_readonly — toggle editability for viewer/operator roles
// ---------------------------------------------------------------------------

/// Enable or disable editing of all profile fields. When `readonly` is `true`,
/// all input widgets and action buttons become insensitive so the window acts
/// as a read-only viewer (useful for viewer/operator roles).
pub fn set_readonly(window: &adw::Window, readonly: bool) {
    let sensitive = !readonly;
    let root = window.upcast_ref::<gtk4::Widget>();

    // Entry rows
    for name in [
        W_SERVER,
        W_USERNAME,
        W_DNS_SERVERS,
        W_IGNORED_DNS_SERVERS,
        W_SEARCH_DOMAINS,
        W_IGNORED_SEARCH_DOMAINS,
        W_ADD_ROUTES,
        W_IGNORED_ROUTES,
        W_CA_CERTS,
    ] {
        if let Some(w) = find_widget_by_name::<adw::EntryRow>(root, name) {
            w.set_sensitive(sensitive);
        }
    }

    // Password entry rows
    for name in [W_PASSWORD, W_CERT_PASSWORD] {
        if let Some(w) = find_widget_by_name::<adw::PasswordEntryRow>(root, name) {
            w.set_sensitive(sensitive);
        }
    }

    // Combo rows
    for name in [W_LOGIN_TYPE, W_CERT_TYPE, W_TRANSPORT] {
        if let Some(w) = find_widget_by_name::<adw::ComboRow>(root, name) {
            w.set_sensitive(sensitive);
        }
    }

    // Switch rows
    for name in [
        W_NO_DNS,
        W_SEARCH_DOMAINS_AS_ROUTES,
        W_NO_ROUTING,
        W_DEFAULT_ROUTE,
        W_DISABLE_IPV6,
        W_NO_CERT_CHECK,
        W_IKE_PERSIST,
        W_NO_KEEPALIVE,
        W_PORT_KNOCK,
    ] {
        if let Some(w) = find_widget_by_name::<adw::SwitchRow>(root, name) {
            w.set_sensitive(sensitive);
        }
    }

    // Spin rows
    for name in [W_PASSWORD_FACTOR, W_IKE_LIFETIME, W_MTU] {
        if let Some(w) = find_widget_by_name::<adw::SpinRow>(root, name) {
            w.set_sensitive(sensitive);
        }
    }

    // Certificate file action row
    if let Some(w) = find_widget_by_name::<adw::ActionRow>(root, W_CERT_FILE) {
        w.set_sensitive(sensitive);
    }

    // Bottom buttons
    if let Some(w) = find_widget_by_name::<gtk4::Button>(root, W_SAVE_BTN) {
        w.set_sensitive(sensitive);
    }
    if let Some(w) = find_widget_by_name::<gtk4::Button>(root, W_DISCARD_BTN) {
        w.set_sensitive(sensitive);
    }

    // Profile list buttons (Add / Delete are inside the left pane)
    // We disable the whole profile list box so the user cannot switch or
    // modify profiles when in read-only mode.
    if let Some(w) = find_widget_by_name::<gtk4::ListBox>(root, W_PROFILE_LIST) {
        w.set_sensitive(sensitive);
    }
}
