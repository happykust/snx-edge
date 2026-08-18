//! Process-wide rustls crypto provider selection.

/// Install the process-wide rustls `CryptoProvider`.
///
/// Both `aws-lc-rs` and `ring` end up compiled into the dependency graph
/// (rustls' default features pull the former, reqwest's rustls stack the
/// latter), and rustls refuses to guess between them: every
/// `ServerConfig::builder()` call panics until a provider is installed.
/// `ring` is chosen because it cross-compiles to musl on all three RouterOS
/// container architectures without a C toolchain.
///
/// Idempotent: safe to call from `main` and from tests in the same process.
pub fn install_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // Err means another thread won the race — the invariant still holds.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_makes_a_default_provider_available() {
        install_crypto_provider();
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "no process-level CryptoProvider after install"
        );
    }

    #[test]
    fn install_is_idempotent_and_builder_does_not_panic() {
        // Two providers are compiled in (aws-lc-rs via rustls defaults, ring
        // via reqwest), so `builder()` panics unless one is installed first.
        // Calling install twice must not panic either — main and tests can
        // both reach it in the same process.
        install_crypto_provider();
        install_crypto_provider();
        let _ = rustls::ServerConfig::builder();
    }
}
