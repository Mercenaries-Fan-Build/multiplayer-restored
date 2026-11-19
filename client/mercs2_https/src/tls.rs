//! TLS client configuration (OpenSSL 3, statically linked via the `openssl` crate's `vendored` feature).
//!
//! Policy: TLS 1.2 minimum (OpenSSL negotiates 1.3 when the server offers it) with forward-secret AEAD cipher
//! suites only ([`TLS12_CIPHERS`], [`TLS13_CIPHERSUITES`]), SNI, certificate chain verification against
//! **only** the embedded Mozilla CA bundle, and hostname verification against the certificate's
//! subjectAltName only — never its subject CN (RFC 6125 §6.4.4; [`connect`]). The connector's default verify
//! paths are replaced, not extended, so no system or build-machine trust store is consulted.
//!
//! **CA bundle:** `ca/cacert.pem` is curl's extract of the Mozilla NSS root store
//! (<https://curl.se/docs/caextract.html>), "Certificate data from Mozilla as of
//! [`CA_BUNDLE_MOZILLA_DATE`]", SHA-256 [`CA_BUNDLE_SHA256`] (matches curl.se's published
//! `cacert.pem.sha256`, kept beside it). Refresh with `ca/refresh_cacert.sh`, then update both constants;
//! a test pins the embedded bytes to the recorded hash.

use std::io::{Read, Write};
use std::net::IpAddr;

use openssl::error::ErrorStack;
use openssl::ssl::{HandshakeError, SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion};
use openssl::x509::X509;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509CheckFlags;

pub const CA_BUNDLE: &[u8] = include_bytes!("../ca/cacert.pem");
pub const CA_BUNDLE_SHA256: &str = "a41b5d356aea97a529fe27e0f7316d2f9d946d75927476cf9cf1b90637d00505";
pub const CA_BUNDLE_MOZILLA_DATE: &str = "Fri Sep 25 03:12:01 2026 GMT";

/// TLS 1.2 cipher suites offered: ECDHE key exchange with AES-GCM or ChaCha20-Poly1305 only (no CBC, no static
/// RSA). Every one is also in Mozilla's "intermediate" server list, which the multiplayer server uses.
pub const TLS12_CIPHERS: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";

/// TLS 1.3 cipher suites offered (all of TLS 1.3's AEAD suites except the CCM ones).
pub const TLS13_CIPHERSUITES: &str = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";

/// Build a connector that trusts exactly the certificates in `roots_pem`. Connect with [`connect`], which adds
/// the hostname check.
pub fn connector(roots_pem: &[u8]) -> Result<SslConnector, ErrorStack> {
    let mut b = SslConnector::builder(SslMethod::tls_client())?;
    b.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    b.set_cipher_list(TLS12_CIPHERS)?;
    b.set_ciphersuites(TLS13_CIPHERSUITES)?;
    let mut store = X509StoreBuilder::new()?;
    for cert in X509::stack_from_pem(roots_pem)? {
        store.add_cert(cert)?;
    }
    b.set_cert_store(store.build());
    b.set_verify(SslVerifyMode::PEER);
    Ok(b.build())
}

/// The production connector: the embedded Mozilla bundle.
pub fn mozilla_connector() -> Result<SslConnector, ErrorStack> {
    connector(CA_BUNDLE)
}

/// TLS handshake with `host` (a DNS name or an IP address) over `stream`: SNI for a name, the connector's chain
/// verification, and a hostname check against the certificate's subjectAltName only. A certificate without a
/// matching DNS (or IP) SAN is refused even when its subject CN names `host`.
///
/// `SslConnector::connect` is not used: it sets the host flags to `NO_PARTIAL_WILDCARDS` alone for each
/// connection, which leaves OpenSSL's subject-CN fallback on.
pub fn connect<S: Read + Write>(
    connector: &SslConnector,
    host: &str,
    stream: S,
) -> Result<SslStream<S>, HandshakeError<S>> {
    let mut config = connector.configure()?;
    // Replaced below by the same name check with NEVER_CHECK_SUBJECT added.
    config.set_verify_hostname(false);
    let mut ssl = config.into_ssl(host)?;
    let param = ssl.param_mut();
    param.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS | X509CheckFlags::NEVER_CHECK_SUBJECT);
    match host.parse::<IpAddr>() {
        Ok(ip) => param.set_ip(ip)?,
        Err(_) => param.set_host(host)?,
    }
    ssl.connect(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_bundle_is_the_recorded_one() {
        use sha2::{Digest, Sha256};
        let hex: String = Sha256::digest(CA_BUNDLE).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, CA_BUNDLE_SHA256);
        let published = include_str!("../ca/cacert.pem.sha256");
        assert!(published.starts_with(CA_BUNDLE_SHA256), "{published}");
        let text = std::str::from_utf8(CA_BUNDLE).unwrap();
        assert!(text.contains(&format!("Certificate data from Mozilla as of: {CA_BUNDLE_MOZILLA_DATE}")));
    }

    #[test]
    fn bundle_loads_every_root() {
        let certs = X509::stack_from_pem(CA_BUNDLE).unwrap();
        let blocks = std::str::from_utf8(CA_BUNDLE).unwrap().matches("-----BEGIN CERTIFICATE-----").count();
        assert_eq!(certs.len(), blocks);
        assert!(certs.len() > 100);
        mozilla_connector().unwrap();
    }

    #[test]
    fn openssl_is_3x() {
        let v = openssl::version::number();
        assert_eq!(v >> 28, 3, "OpenSSL version number {v:#x} ({})", openssl::version::version());
    }
}
