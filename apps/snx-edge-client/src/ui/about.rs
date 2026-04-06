use adw::prelude::*;
use gtk4::prelude::*;
use libadwaita as adw;

/// Show the About dialog for SNX Edge Client.
///
/// Uses `adw::AboutWindow` with application metadata sourced from
/// `Cargo.toml` (version via `env!`) and project constants.
pub fn show_about_dialog(parent: &impl IsA<gtk4::Window>) {
    let dialog = adw::AboutWindow::builder()
        .application_name("SNX Edge Client")
        .version(env!("CARGO_PKG_VERSION"))
        .developer_name("SNX Edge contributors")
        .license_type(gtk4::License::Agpl30)
        .website("https://github.com/happykust/snx-edge-proxy")
        .issue_url("https://github.com/happykust/snx-edge-proxy/issues")
        .application_icon("network-vpn-symbolic")
        .comments("Remote management client for snx-edge-server.\nManage VPN tunnels, routing, users, and logs from your desktop.")
        .transient_for(parent)
        .modal(true)
        .build();

    dialog.present();
}
