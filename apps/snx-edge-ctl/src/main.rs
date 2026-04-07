mod api;
mod auth;
mod models;
mod output;
mod servers;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use reqwest_eventsource::{Event, EventSource};

use crate::api::ApiClient;
use crate::output::OutputMode;
use crate::servers::ClientSettings;

// ============================================================
// CLI structure
// ============================================================

#[derive(Parser)]
#[command(
    name = "snx-edge-ctl",
    about = "CLI client for remote management of snx-edge-server",
    version
)]
struct Cli {
    /// Server URL or name from servers.toml
    #[arg(long, short = 's', global = true)]
    server: Option<String>,

    /// JWT access token (overrides keyring)
    #[arg(long, global = true)]
    token: Option<String>,

    /// Output as JSON
    #[arg(long, global = true)]
    json: bool,

    /// Suppress output (exit code only)
    #[arg(long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate with the server
    Login,
    /// Remove saved credentials
    Logout,
    /// Manage configured servers
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },
    /// Connect to VPN tunnel
    Connect {
        /// Profile ID or name
        #[arg(long, short)]
        profile: Option<String>,
    },
    /// Disconnect VPN tunnel
    Disconnect,
    /// Reconnect VPN tunnel
    Reconnect {
        /// Profile ID or name
        #[arg(long, short)]
        profile: Option<String>,
    },
    /// Show VPN tunnel status
    Status,
    /// Manage VPN profiles
    Profiles {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Manage RouterOS routing
    Routing {
        #[command(subcommand)]
        action: RoutingAction,
    },
    /// Manage users
    Users {
        #[command(subcommand)]
        action: UserAction,
    },
    /// View server logs
    Logs {
        /// Fetch last N log entries (history mode)
        #[arg(long)]
        history: Option<usize>,

        /// Filter by log level
        #[arg(long)]
        level: Option<String>,
    },
    /// Show VPN server info
    Info,
    /// Check server health (no auth required)
    Health,
}

#[derive(Subcommand)]
enum ServerAction {
    /// List configured servers
    List,
    /// Add a new server
    Add {
        /// Friendly name
        name: String,
        /// Server URL (e.g. https://vpn.example.com:8443)
        url: String,
    },
    /// Remove a server
    Remove {
        /// Server name
        name: String,
    },
    /// Set the default server
    SetDefault {
        /// Server name
        name: String,
    },
}

#[derive(Subcommand)]
enum ProfileAction {
    /// List all profiles
    List,
    /// Show a single profile
    Show {
        /// Profile ID
        id: String,
    },
    /// Create a new profile
    Create {
        /// Profile name
        name: String,
        /// TOML config file path
        #[arg(long)]
        file: Option<String>,
    },
    /// Update a profile from a TOML file
    Update {
        /// Profile ID
        id: String,
        /// TOML config file path
        #[arg(long)]
        file: String,
    },
    /// Delete a profile
    Delete {
        /// Profile ID
        id: String,
    },
    /// Import a profile from a TOML file
    Import {
        /// Path to TOML file
        file: String,
    },
    /// Export a profile as TOML
    Export {
        /// Profile ID
        id: String,
        /// Output file (stdout if omitted)
        output: Option<String>,
    },
}

#[derive(Subcommand)]
enum RoutingAction {
    /// Manage VPN client addresses
    Clients {
        #[command(subcommand)]
        action: Option<ClientAction>,
    },
    /// Manage bypass addresses
    Bypass {
        #[command(subcommand)]
        action: Option<BypassAction>,
    },
    /// Setup PBR rules on RouterOS
    Setup,
    /// Remove PBR rules from RouterOS
    Teardown,
    /// Run routing diagnostics
    Diagnostics,
}

#[derive(Subcommand)]
enum ClientAction {
    /// Add a client address
    Add {
        /// IP address or CIDR
        address: String,
        /// Comment
        #[arg(long)]
        comment: Option<String>,
    },
    /// Remove a client by RouterOS ID
    Remove {
        /// RouterOS entry ID
        id: String,
    },
}

#[derive(Subcommand)]
enum BypassAction {
    /// Add a bypass address
    Add {
        /// IP address or CIDR
        address: String,
        /// Comment
        #[arg(long)]
        comment: Option<String>,
    },
    /// Remove a bypass by RouterOS ID
    Remove {
        /// RouterOS entry ID
        id: String,
    },
}

#[derive(Subcommand)]
enum UserAction {
    /// List all users
    List,
    /// Create a new user
    Create {
        /// Username
        username: String,
        /// Role (admin, operator, viewer)
        #[arg(long)]
        role: String,
        /// Password (will prompt if not provided)
        #[arg(long)]
        password: Option<String>,
        /// Comment
        #[arg(long, default_value = "")]
        comment: String,
    },
    /// Update a user
    Update {
        /// User ID
        id: String,
        /// New role
        #[arg(long)]
        role: Option<String>,
        /// New comment
        #[arg(long)]
        comment: Option<String>,
        /// Enable or disable
        #[arg(long)]
        enabled: Option<bool>,
    },
    /// Delete a user
    Delete {
        /// User ID
        id: String,
    },
    /// Change a user's password
    Passwd {
        /// User ID
        id: String,
    },
    /// List active sessions
    Sessions,
    /// Revoke a session
    Kick {
        /// Session ID
        session_id: String,
    },
    /// Show current user info
    Me,
}

// ============================================================
// Main
// ============================================================

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let mode = OutputMode::from_flags(cli.json, cli.quiet);

    if let Err(err) = run(cli, mode).await {
        output::print_error(mode, &err);
        std::process::exit(1);
    }
}

async fn run(cli: Cli, mode: OutputMode) -> anyhow::Result<()> {
    match &cli.command {
        Commands::Health => cmd_health(&cli, mode).await,
        Commands::Server { action } => cmd_server(action, mode).await,
        Commands::Login => cmd_login(&cli, mode).await,
        Commands::Logout => cmd_logout(&cli, mode).await,
        Commands::Connect { profile } => cmd_connect(&cli, mode, profile.as_deref()).await,
        Commands::Disconnect => cmd_disconnect(&cli, mode).await,
        Commands::Reconnect { profile } => cmd_reconnect(&cli, mode, profile.as_deref()).await,
        Commands::Status => cmd_status(&cli, mode).await,
        Commands::Info => cmd_info(&cli, mode).await,
        Commands::Profiles { action } => cmd_profiles(&cli, mode, action).await,
        Commands::Routing { action } => cmd_routing(&cli, mode, action).await,
        Commands::Users { action } => cmd_users(&cli, mode, action).await,
        Commands::Logs { history, level } => cmd_logs(&cli, mode, *history, level.as_deref()).await,
    }
}

// ============================================================
// Helpers
// ============================================================

/// Resolve the server URL from --server flag, servers.toml, or error.
fn resolve_server(cli: &Cli) -> anyhow::Result<String> {
    if let Some(server) = &cli.server {
        // Check if it's a name in servers.toml first
        let settings = ClientSettings::load();
        if let Some((_, entry)) = settings.find_by_name_or_url(server) {
            return Ok(entry.url.clone());
        }
        // Otherwise treat as a URL
        return Ok(server.clone());
    }

    let settings = ClientSettings::load();
    if let Some(entry) = settings.active() {
        return Ok(entry.url.clone());
    }

    bail!(
        "No server specified. Use --server <url|name> or add a server with:\n  \
         snx-edge-ctl server add <name> <url>"
    )
}

/// Build an authenticated ApiClient: --token flag > keyring refresh_token > error.
async fn ensure_auth(cli: &Cli) -> anyhow::Result<ApiClient> {
    let server_url = resolve_server(cli)?;
    let mut client = ApiClient::new(&server_url);

    if let Some(token) = &cli.token {
        client.set_token(token.clone());
        return Ok(client);
    }

    // Try refresh via keyring
    let refresh_token = auth::load_refresh_token(&server_url)
        .context("Not authenticated. Run: snx-edge-ctl login")?;

    let token_resp = client.refresh(&refresh_token).await?;

    // Save the new refresh token if provided
    if let Some(new_refresh) = &token_resp.refresh_token {
        auth::save_refresh_token(&server_url, new_refresh);
    }

    Ok(client)
}

/// Resolve a profile argument that may be a name or ID.
async fn resolve_profile_id(client: &ApiClient, profile: &str) -> anyhow::Result<String> {
    // If it looks like a UUID, use it directly
    if uuid::Uuid::parse_str(profile).is_ok() {
        return Ok(profile.to_string());
    }

    // Otherwise search by name
    let profiles = client.list_profiles().await?;
    let found = profiles
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case(profile));

    match found {
        Some(p) => Ok(p.id.clone()),
        None => bail!(
            "Profile '{}' not found. Use `profiles list` to see available profiles.",
            profile
        ),
    }
}

// ============================================================
// Command implementations
// ============================================================

async fn cmd_health(cli: &Cli, mode: OutputMode) -> anyhow::Result<()> {
    let server_url = resolve_server(cli)?;
    let client = ApiClient::new(&server_url);
    let health = client.health().await?;
    output::print_item(mode, &health);
    Ok(())
}

async fn cmd_server(action: &ServerAction, mode: OutputMode) -> anyhow::Result<()> {
    let mut settings = ClientSettings::load();

    match action {
        ServerAction::List => {
            if settings.servers.is_empty() {
                output::print_ok(mode, "No servers configured.");
                return Ok(());
            }
            let active_idx = settings.active_server;
            for (i, s) in settings.servers.iter().enumerate() {
                let marker = if Some(i) == active_idx { " *" } else { "" };
                if mode == OutputMode::Table {
                    println!(
                        "  {}{} -> {}{}",
                        s.name,
                        marker,
                        s.url,
                        if s.auto_connect {
                            " [auto-connect]"
                        } else {
                            ""
                        }
                    );
                }
            }
            if mode == OutputMode::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "servers": settings.servers,
                        "active": active_idx,
                    }))?
                );
            }
        }
        ServerAction::Add { name, url } => {
            settings.add(name, url)?;
            settings.save()?;
            output::print_ok(mode, &format!("Server '{}' added.", name));
        }
        ServerAction::Remove { name } => {
            let removed = settings.remove(name)?;
            // Also remove keyring entry
            auth::delete_refresh_token(&removed.url);
            settings.save()?;
            output::print_ok(mode, &format!("Server '{}' removed.", name));
        }
        ServerAction::SetDefault { name } => {
            settings.set_default(name)?;
            settings.save()?;
            output::print_ok(mode, &format!("Default server set to '{}'.", name));
        }
    }
    Ok(())
}

async fn cmd_login(cli: &Cli, mode: OutputMode) -> anyhow::Result<()> {
    let server_url = resolve_server(cli)?;
    let mut client = ApiClient::new(&server_url);

    let username = {
        eprint!("Username: ");
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .context("Failed to read username")?;
        input.trim().to_string()
    };

    let password =
        rpassword::prompt_password("Password: ").context("Failed to read password")?;

    let token_resp = client.login(&username, &password).await?;

    if let Some(refresh) = &token_resp.refresh_token {
        auth::save_refresh_token(&server_url, refresh);
    }

    output::print_ok(mode, "Login successful.");
    Ok(())
}

async fn cmd_logout(cli: &Cli, mode: OutputMode) -> anyhow::Result<()> {
    let server_url = resolve_server(cli)?;
    auth::delete_refresh_token(&server_url);
    output::print_ok(mode, "Logged out.");
    Ok(())
}

async fn cmd_connect(
    cli: &Cli,
    mode: OutputMode,
    profile: Option<&str>,
) -> anyhow::Result<()> {
    let client = ensure_auth(cli).await?;

    let profile_id = match profile {
        Some(p) => resolve_profile_id(&client, p).await?,
        None => {
            // Try to use last_profile_id from servers.toml
            let settings = ClientSettings::load();
            let server_url = resolve_server(cli)?;
            let last_id = settings
                .find_by_name_or_url(&server_url)
                .and_then(|(_, s)| s.last_profile_id.clone());
            match last_id {
                Some(id) => id,
                None => bail!(
                    "No profile specified. Use --profile <id|name> or set last_profile_id in servers.toml"
                ),
            }
        }
    };

    // Remember the profile for next time
    {
        let mut settings = ClientSettings::load();
        let server_url = resolve_server(cli)?;
        if let Some((idx, _)) = settings.find_by_name_or_url(&server_url) {
            settings.servers[idx].last_profile_id = Some(profile_id.clone());
            let _ = settings.save();
        }
    }

    let status = client.tunnel_connect(&profile_id).await?;
    output::print_item(mode, &status);
    Ok(())
}

async fn cmd_disconnect(cli: &Cli, mode: OutputMode) -> anyhow::Result<()> {
    let client = ensure_auth(cli).await?;
    let status = client.tunnel_disconnect().await?;
    output::print_item(mode, &status);
    Ok(())
}

async fn cmd_reconnect(
    cli: &Cli,
    mode: OutputMode,
    profile: Option<&str>,
) -> anyhow::Result<()> {
    let client = ensure_auth(cli).await?;

    let profile_id = match profile {
        Some(p) => resolve_profile_id(&client, p).await?,
        None => {
            let settings = ClientSettings::load();
            let server_url = resolve_server(cli)?;
            settings
                .find_by_name_or_url(&server_url)
                .and_then(|(_, s)| s.last_profile_id.clone())
                .context("No profile specified. Use --profile <id|name>")?
        }
    };

    let status = client.tunnel_reconnect(&profile_id).await?;
    output::print_item(mode, &status);
    Ok(())
}

async fn cmd_status(cli: &Cli, mode: OutputMode) -> anyhow::Result<()> {
    let client = ensure_auth(cli).await?;
    let status = client.tunnel_status().await?;
    output::print_item(mode, &status);
    Ok(())
}

async fn cmd_info(cli: &Cli, mode: OutputMode) -> anyhow::Result<()> {
    let client = ensure_auth(cli).await?;
    let info = client.server_info().await?;
    output::print_item(mode, &info);
    Ok(())
}

async fn cmd_profiles(
    cli: &Cli,
    mode: OutputMode,
    action: &ProfileAction,
) -> anyhow::Result<()> {
    let client = ensure_auth(cli).await?;

    match action {
        ProfileAction::List => {
            let profiles = client.list_profiles().await?;
            output::print_list(mode, &profiles);
        }
        ProfileAction::Show { id } => {
            let profile = client.get_profile(id).await?;
            output::print_item(mode, &profile);
        }
        ProfileAction::Create { name, file } => {
            let config = if let Some(path) = file {
                let content = std::fs::read_to_string(path)
                    .context(format!("Failed to read file: {}", path))?;
                let toml_val: toml::Value =
                    content.parse().context("Invalid TOML")?;
                serde_json::to_value(&toml_val)?
            } else {
                serde_json::json!({})
            };

            let profile = client.create_profile(name, &config).await?;
            output::print_item(mode, &profile);
        }
        ProfileAction::Update { id, file } => {
            let content = std::fs::read_to_string(file)
                .context(format!("Failed to read file: {}", file))?;
            let toml_val: toml::Value = content.parse().context("Invalid TOML")?;
            let config = serde_json::to_value(&toml_val)?;

            let body = serde_json::json!({ "config": config });
            let profile = client.update_profile(id, &body).await?;
            output::print_item(mode, &profile);
        }
        ProfileAction::Delete { id } => {
            client.delete_profile(id).await?;
            output::print_ok(mode, &format!("Profile {} deleted.", id));
        }
        ProfileAction::Import { file } => {
            let content = std::fs::read_to_string(file)
                .context(format!("Failed to read file: {}", file))?;
            let profile = client.import_profile(&content).await?;
            output::print_item(mode, &profile);
        }
        ProfileAction::Export {
            id,
            output: out_file,
        } => {
            let toml_str = client.export_profile(id).await?;
            if let Some(path) = out_file {
                std::fs::write(path, &toml_str)
                    .context(format!("Failed to write file: {}", path))?;
                output::print_ok(
                    mode,
                    &format!("Profile exported to {}", path),
                );
            } else {
                // Write to stdout regardless of mode
                println!("{}", toml_str);
            }
        }
    }
    Ok(())
}

async fn cmd_routing(
    cli: &Cli,
    mode: OutputMode,
    action: &RoutingAction,
) -> anyhow::Result<()> {
    let client = ensure_auth(cli).await?;

    match action {
        RoutingAction::Clients { action } => match action {
            None => {
                let clients = client.list_clients().await?;
                output::print_list(mode, &clients);
            }
            Some(ClientAction::Add { address, comment }) => {
                let entry =
                    client.add_client(address, comment.as_deref()).await?;
                output::print_item(mode, &entry);
            }
            Some(ClientAction::Remove { id }) => {
                client.remove_client(id).await?;
                output::print_ok(mode, &format!("Client {} removed.", id));
            }
        },
        RoutingAction::Bypass { action } => match action {
            None => {
                let entries = client.list_bypass().await?;
                output::print_list(mode, &entries);
            }
            Some(BypassAction::Add { address, comment }) => {
                let entry =
                    client.add_bypass(address, comment.as_deref()).await?;
                output::print_item(mode, &entry);
            }
            Some(BypassAction::Remove { id }) => {
                client.remove_bypass(id).await?;
                output::print_ok(mode, &format!("Bypass {} removed.", id));
            }
        },
        RoutingAction::Setup => {
            let result = client.routing_setup().await?;
            output::print_item(mode, &result);
        }
        RoutingAction::Teardown => {
            let result = client.routing_teardown().await?;
            output::print_item(mode, &result);
        }
        RoutingAction::Diagnostics => {
            let result = client.routing_diagnostics().await?;
            output::print_item(mode, &result);
        }
    }
    Ok(())
}

async fn cmd_users(
    cli: &Cli,
    mode: OutputMode,
    action: &UserAction,
) -> anyhow::Result<()> {
    let client = ensure_auth(cli).await?;

    match action {
        UserAction::List => {
            let users = client.list_users().await?;
            output::print_list(mode, &users);
        }
        UserAction::Create {
            username,
            role,
            password,
            comment,
        } => {
            let pw = match password {
                Some(p) => p.clone(),
                None => rpassword::prompt_password("Password: ")
                    .context("Failed to read password")?,
            };

            let user =
                client.create_user(username, &pw, role, comment).await?;
            output::print_item(mode, &user);
        }
        UserAction::Update {
            id,
            role,
            comment,
            enabled,
        } => {
            let user = client
                .update_user(
                    id,
                    role.as_deref(),
                    comment.as_deref(),
                    *enabled,
                )
                .await?;
            output::print_item(mode, &user);
        }
        UserAction::Delete { id } => {
            client.delete_user(id).await?;
            output::print_ok(mode, &format!("User {} deleted.", id));
        }
        UserAction::Passwd { id } => {
            let new_pw = rpassword::prompt_password("New password: ")
                .context("Failed to read password")?;
            let confirm = rpassword::prompt_password("Confirm password: ")
                .context("Failed to read password")?;
            if new_pw != confirm {
                bail!("Passwords do not match.");
            }
            client.change_password(id, &new_pw, None).await?;
            output::print_ok(mode, "Password changed.");
        }
        UserAction::Sessions => {
            let sessions = client.list_sessions().await?;
            output::print_list(mode, &sessions);
        }
        UserAction::Kick { session_id } => {
            client.kick_session(session_id).await?;
            output::print_ok(
                mode,
                &format!("Session {} revoked.", session_id),
            );
        }
        UserAction::Me => {
            let me = client.get_me().await?;
            output::print_item(mode, &me);
        }
    }
    Ok(())
}

async fn cmd_logs(
    cli: &Cli,
    mode: OutputMode,
    history: Option<usize>,
    level: Option<&str>,
) -> anyhow::Result<()> {
    let client = ensure_auth(cli).await?;

    if let Some(limit) = history {
        // History mode: fetch last N entries
        let entries = client.logs_history(limit, level).await?;
        if mode == OutputMode::Json {
            println!(
                "{}",
                serde_json::to_string_pretty(&entries)
                    .unwrap_or_else(|_| "[]".to_string())
            );
        } else if mode == OutputMode::Table {
            for entry in &entries {
                println!(
                    "[{}] {} {}",
                    entry.level, entry.timestamp, entry.message
                );
            }
        }
    } else {
        // Streaming mode: SSE
        let base_url = client.base_url().to_string();
        let token = client
            .token()
            .context("No auth token available for SSE")?
            .to_string();

        let url = format!("{}/api/v1/logs", base_url);
        let mut es = EventSource::new(
            client.raw_client().get(&url).bearer_auth(&token),
        )
        .context("Failed to create SSE connection")?;

        if mode != OutputMode::Quiet {
            eprintln!("Streaming logs (Ctrl+C to stop)...");
        }

        while let Some(event) = es.next().await {
            match event {
                Ok(Event::Open) => {}
                Ok(Event::Message(msg)) => {
                    if msg.event == "log" {
                        if mode == OutputMode::Json {
                            println!("{}", msg.data);
                        } else if mode == OutputMode::Table {
                            if let Ok(entry) =
                                serde_json::from_str::<models::LogEntry>(
                                    &msg.data,
                                )
                            {
                                let show = match level {
                                    Some(l) => {
                                        entry.level.eq_ignore_ascii_case(l)
                                    }
                                    None => true,
                                };
                                if show {
                                    println!(
                                        "[{}] {} {}",
                                        entry.level,
                                        entry.timestamp,
                                        entry.message
                                    );
                                }
                            }
                        }
                    }
                }
                Err(reqwest_eventsource::Error::StreamEnded) => break,
                Err(err) => {
                    bail!("SSE error: {}", err);
                }
            }
        }
    }
    Ok(())
}
