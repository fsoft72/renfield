//! Mutual TLS 1.3 with peers pinned by the SHA-256 fingerprint of their certificate.

use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme};

use crate::error::RenfieldError;
use crate::identity::{Identity, fingerprint_of};

/// Marker placed in the TLS error raised when the server key differs from the pinned one.
const KEY_MISMATCH_MARKER: &str = "renfield-key-mismatch";
/// Name sent in every handshake; names are not verified, keys are.
const SERVER_NAME: &str = "renfield";

/// Decides which peers may complete the TLS handshake on the listening side.
pub trait PeerPolicy: Send + Sync {
    /// Tells whether a certificate fingerprint is authorized.
    fn is_authorized(&self, fingerprint: &str) -> bool;
    /// Tells whether unknown peers are currently allowed (pairing window open).
    fn pairing_open(&self) -> bool;
}

/// Returns the crypto provider used for every connection.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Splits an identity into the certificate chain and private key types rustls expects.
fn parts(id: &Identity) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = CertificateDer::from(id.cert_der.clone());
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(id.key_der.clone()));
    (vec![cert], key)
}

/// Accepts client certificates whose fingerprint the policy authorizes (or any, during pairing).
#[derive(Debug)]
struct PinnedClientVerifier {
    policy: Arc<dyn PeerPolicy>,
    algs: WebPkiSupportedAlgorithms,
}

impl std::fmt::Debug for dyn PeerPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PeerPolicy")
    }
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        let fp = fingerprint_of(end_entity.as_ref());
        if self.policy.is_authorized(&fp) || self.policy.pairing_open() {
            return Ok(ClientCertVerified::assertion());
        }
        Err(rustls::Error::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Accepts the server certificate whose fingerprint matches the pinned one (or any when unpinned).
#[derive(Debug)]
struct PinnedServerVerifier {
    expected: Option<String>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let Some(expected) = &self.expected else {
            return Ok(ServerCertVerified::assertion());
        };
        if fingerprint_of(end_entity.as_ref()) == *expected {
            return Ok(ServerCertVerified::assertion());
        }
        Err(rustls::Error::General(KEY_MISMATCH_MARKER.to_string()))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Builds the TLS server configuration for dest.
pub fn server_config(
    id: &Identity,
    policy: Arc<dyn PeerPolicy>,
) -> Result<Arc<rustls::ServerConfig>> {
    let provider = provider();
    let verifier = PinnedClientVerifier {
        policy,
        algs: provider.signature_verification_algorithms,
    };
    let (chain, key) = parts(id);
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS 1.3 is not available")?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(chain, key)
        .context("invalid identity certificate or key")?;
    Ok(Arc::new(config))
}

/// Builds the TLS client configuration; `expected_server_fp` pins dest, `None` accepts any (pairing only).
pub fn client_config(
    id: &Identity,
    expected_server_fp: Option<String>,
) -> Result<Arc<rustls::ClientConfig>> {
    let provider = provider();
    let verifier = PinnedServerVerifier {
        expected: expected_server_fp,
        algs: provider.signature_verification_algorithms,
    };
    let (chain, key) = parts(id);
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS 1.3 is not available")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(chain, key)
        .context("invalid identity certificate or key")?;
    Ok(Arc::new(config))
}

/// Returns the fingerprint of the certificate presented by the peer of a TLS connection.
pub fn peer_fingerprint(conn: &rustls::CommonState) -> Option<String> {
    let certs = conn.peer_certificates()?;
    certs.first().map(|c| fingerprint_of(c.as_ref()))
}

/// The fixed server name used in every handshake (names are not verified, keys are).
pub fn server_name() -> ServerName<'static> {
    ServerName::try_from(SERVER_NAME).expect("constant server name is valid")
}

/// Translates a connection I/O error into a renfield error naming the machine.
pub fn map_io_error(machine: &str, err: &std::io::Error) -> RenfieldError {
    let text = format!("{err} {err:?}").to_lowercase();
    if text.contains(KEY_MISMATCH_MARKER) {
        return RenfieldError::KeyMismatch(machine.to_string());
    }
    let rejected = text.contains("certificate") || text.contains("accessdenied");
    if text.contains("alert") && rejected {
        return RenfieldError::NotAuthorized(machine.to_string());
    }
    RenfieldError::Io(format!("connection with '{machine}' failed: {err}"))
}
