//! Container-local network plumbing: ip_forward + tagged NAT for the VPN egress.
//!
//! `apply_vpn_masquerade`, `clear_vpn_masquerade`, `masquerade_add_args`, and
//! `masquerade_delete_args` are pre-wired interface for the Task 1.3 reconciler.

use std::process::Command;

pub const MANAGED_TAG: &str = "managed-by=snx-edge";

fn base_masquerade(op: &str, iface: &str) -> Vec<String> {
    vec![
        "-t".into(),
        "nat".into(),
        op.into(),
        "POSTROUTING".into(),
        "-o".into(),
        iface.into(),
        "-j".into(),
        "MASQUERADE".into(),
        "-m".into(),
        "comment".into(),
        "--comment".into(),
        MANAGED_TAG.into(),
    ]
}

pub fn masquerade_add_args(iface: &str) -> Vec<String> {
    base_masquerade("-A", iface)
}

pub fn masquerade_delete_args(iface: &str) -> Vec<String> {
    base_masquerade("-D", iface)
}

fn masquerade_check_args(iface: &str) -> Vec<String> {
    base_masquerade("-C", iface)
}

pub fn enable_ip_forwarding() -> anyhow::Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    tracing::info!("ip_forward enabled");
    Ok(())
}

fn run_iptables(args: &[String]) -> std::io::Result<std::process::Output> {
    Command::new("iptables").args(args).output()
}

pub fn apply_vpn_masquerade(iface: &str) -> anyhow::Result<()> {
    if iface.is_empty() {
        anyhow::bail!("refusing to MASQUERADE on empty interface name");
    }
    // Idempotent: skip if the exact tagged rule already exists.
    if run_iptables(&masquerade_check_args(iface))
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return Ok(());
    }
    let out = run_iptables(&masquerade_add_args(iface))?;
    if !out.status.success() {
        anyhow::bail!(
            "iptables -A failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    tracing::info!(interface = iface, "VPN MASQUERADE applied");
    Ok(())
}

pub fn clear_vpn_masquerade(iface: &str) -> anyhow::Result<()> {
    // Delete repeatedly until no matching rule remains.
    loop {
        if !run_iptables(&masquerade_check_args(iface))
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            break;
        }
        let out = run_iptables(&masquerade_delete_args(iface))?;
        if !out.status.success() {
            break;
        }
    }
    tracing::info!(interface = iface, "VPN MASQUERADE cleared");
    Ok(())
}

pub fn cleanup_managed_iptables_rules() -> anyhow::Result<()> {
    use anyhow::Context as _;

    // List the current POSTROUTING nat rules and delete any that carry our
    // managed tag.  We use `iptables -S` output rather than re-deriving args
    // so that any historical variation in the rule spec (interface name,
    // ordering, etc.) is handled transparently.
    let output = Command::new("iptables")
        .args(["-t", "nat", "-S", "POSTROUTING"])
        .output()
        .with_context(|| "spawn iptables -S POSTROUTING")?;

    if !output.status.success() {
        anyhow::bail!(
            "iptables -S POSTROUTING failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut removed = 0usize;
    for line in stdout.lines() {
        if !line.contains(MANAGED_TAG) {
            continue;
        }
        // `iptables -S` prints rules as `-A POSTROUTING ...args`.
        // Convert to `-D POSTROUTING ...args` for deletion. Skip anything
        // that doesn't start with `-A ` defensively (policy lines, etc.).
        let Some(rest) = line.strip_prefix("-A ") else {
            continue;
        };
        let mut args: Vec<&str> = vec!["-t", "nat", "-D"];
        args.extend(rest.split_whitespace());
        match Command::new("iptables").args(&args).output() {
            Ok(o) if o.status.success() => {
                removed += 1;
                tracing::info!("removed managed iptables rule: {line}");
            }
            Ok(o) => {
                tracing::warn!(
                    "failed to delete managed iptables rule `{line}`: {}",
                    String::from_utf8_lossy(&o.stderr)
                );
            }
            Err(e) => {
                tracing::warn!("iptables -D spawn failed for `{line}`: {e}");
            }
        }
    }

    if removed > 0 {
        tracing::info!("removed {removed} managed iptables rule(s)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masquerade_add_args_targets_given_interface_and_tags_rule() {
        let args = masquerade_add_args("tun0");
        assert_eq!(
            args,
            vec![
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                "tun0",
                "-j",
                "MASQUERADE",
                "-m",
                "comment",
                "--comment",
                "managed-by=snx-edge",
            ]
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn masquerade_delete_mirrors_add_with_D() {
        let add = masquerade_add_args("snx-xfrm");
        let del = masquerade_delete_args("snx-xfrm");
        assert_eq!(del[2], "-D");
        assert_eq!(add[2], "-A");
        assert_eq!(&add[3..], &del[3..]);
    }
}
