use std::{
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use anyhow::anyhow;
use futures_util::StreamExt;
use tracing::{debug, warn};
use zbus::Connection;

use crate::dbus::{DesktopSettingsProxy, session_connection};

static COLOR_THEME: AtomicU32 = AtomicU32::new(0);

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SystemColorTheme {
    #[default]
    NoPreference,
    Light,
    Dark,
}

impl SystemColorTheme {
    /// Returns true only when the system explicitly prefers a dark color
    /// scheme. `NoPreference` defaults to *light*: many desktops (XFCE,
    /// Cinnamon stock) report `NoPreference` even though their default
    /// theme is light, and choosing dark icons there is wrong.
    pub fn is_dark(self) -> bool {
        matches!(self, Self::Dark)
    }
}

impl TryFrom<u32> for SystemColorTheme {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SystemColorTheme::NoPreference),
            1 => Ok(SystemColorTheme::Dark),
            2 => Ok(SystemColorTheme::Light),
            _ => Err(anyhow!("Unknown color scheme: {}", value)),
        }
    }
}

pub fn system_color_theme() -> anyhow::Result<SystemColorTheme> {
    COLOR_THEME.load(Ordering::SeqCst).try_into()
}

/// Connect, fetch the initial color scheme, then return the proxy ready to
/// stream `SettingChanged` signals. Returns `Err` on any failure so the
/// outer retry loop can reschedule.
async fn fetch_initial_and_subscribe(
    connection: &Connection,
) -> anyhow::Result<DesktopSettingsProxy<'static>> {
    let proxy = DesktopSettingsProxy::new(connection).await?;
    let scheme = proxy
        .read_one("org.freedesktop.appearance", "color-scheme")
        .await?;
    let mut scheme = u32::try_from(scheme)?;
    if scheme == 0 && is_ubuntu() {
        scheme = 2;
    }
    COLOR_THEME.store(scheme, Ordering::SeqCst);
    debug!("System color scheme: {}", scheme);
    Ok(proxy)
}

pub async fn init_theme_monitoring() -> anyhow::Result<()> {
    let connection = session_connection().await?.clone();
    // First connect attempt happens up-front so the caller knows whether the
    // portal is reachable; failures inside the spawned loop are logged and
    // retried, never propagated.
    let _ = fetch_initial_and_subscribe(&connection).await?;

    tokio::spawn(async move {
        // Outer retry loop: any error in the inner loop logs and reconnects
        // after a backoff. Without this the monitor task silently dies on
        // the first transient D-Bus disconnect and live theme switching
        // stops working until the app is restarted.
        loop {
            match run_monitor(&connection).await {
                Ok(()) => {
                    // Stream ended cleanly — restart after short delay.
                    debug!("theme monitor stream ended, reconnecting");
                }
                Err(e) => {
                    warn!(error = %e, "theme monitor disconnected, retrying in 5s");
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    Ok(())
}

async fn run_monitor(connection: &Connection) -> anyhow::Result<()> {
    let proxy = fetch_initial_and_subscribe(connection).await?;
    let mut stream = proxy.receive_setting_changed().await?;
    while let Some(signal) = stream.next().await {
        let args = match signal.args() {
            Ok(a) => a,
            Err(e) => {
                warn!(error = %e, "failed to decode SettingChanged signal");
                continue;
            }
        };
        if args.namespace == "org.freedesktop.appearance" && args.key == "color-scheme" {
            match u32::try_from(args.value) {
                Ok(mut scheme) => {
                    if scheme == 0 && is_ubuntu() {
                        scheme = 2;
                    }
                    debug!("New system color scheme: {}", scheme);
                    COLOR_THEME.store(scheme, Ordering::SeqCst);
                }
                Err(e) => warn!(error = %e, "failed to decode color-scheme value"),
            }
        }
    }
    Ok(())
}

fn is_ubuntu() -> bool {
    std::env::var("XDG_CURRENT_DESKTOP").is_ok_and(|v| v == "ubuntu:GNOME")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_preference_defaults_to_light() {
        // Many desktops report `NoPreference` even when their visible theme
        // is light; treating that as "dark" picks the wrong tray icon set.
        assert!(!SystemColorTheme::NoPreference.is_dark());
    }

    #[test]
    fn dark_returns_true() {
        assert!(SystemColorTheme::Dark.is_dark());
    }

    #[test]
    fn light_returns_false() {
        assert!(!SystemColorTheme::Light.is_dark());
    }

    #[test]
    fn try_from_known_values() {
        assert_eq!(
            SystemColorTheme::try_from(0u32).unwrap(),
            SystemColorTheme::NoPreference
        );
        assert_eq!(
            SystemColorTheme::try_from(1u32).unwrap(),
            SystemColorTheme::Dark
        );
        assert_eq!(
            SystemColorTheme::try_from(2u32).unwrap(),
            SystemColorTheme::Light
        );
    }

    #[test]
    fn try_from_unknown_value_errors() {
        assert!(SystemColorTheme::try_from(99u32).is_err());
    }
}
