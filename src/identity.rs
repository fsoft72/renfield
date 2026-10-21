//! Long lived identity of a machine: a self signed Ed25519 certificate and its key.

use std::path::Path;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::home;

/// File name of the certificate (DER) inside the configuration directory.
pub const CERT_FILE: &str = "identity.crt";
/// File name of the private key (PKCS8 DER) inside the configuration directory.
pub const KEY_FILE: &str = "identity.key";

/// The certificate and private key of this machine.
#[derive(Clone)]
pub struct Identity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

impl Identity {
    /// Loads the identity from `dir`, generating and saving a new one when it does not exist.
    pub fn load_or_create(dir: &Path) -> Result<Identity> {
        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);
        if cert_path.exists() && key_path.exists() {
            let cert_der = std::fs::read(&cert_path)
                .with_context(|| format!("cannot read {}", cert_path.display()))?;
            let key_der = std::fs::read(&key_path)
                .with_context(|| format!("cannot read {}", key_path.display()))?;
            return Ok(Identity { cert_der, key_der });
        }
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .context("cannot generate Ed25519 key")?;
        let params = rcgen::CertificateParams::new(vec!["renfield".to_string()])
            .context("invalid certificate parameters")?;
        let cert = params
            .self_signed(&key)
            .context("cannot self sign certificate")?;
        let identity = Identity {
            cert_der: cert.der().to_vec(),
            key_der: key.serialize_der(),
        };
        std::fs::write(&key_path, &identity.key_der)
            .with_context(|| format!("cannot write {}", key_path.display()))?;
        home::restrict_permissions(&key_path)?;
        std::fs::write(&cert_path, &identity.cert_der)
            .with_context(|| format!("cannot write {}", cert_path.display()))?;
        Ok(identity)
    }

    /// Returns the lowercase hex SHA-256 fingerprint of this identity's certificate.
    pub fn fingerprint(&self) -> String {
        fingerprint_of(&self.cert_der)
    }
}

/// Returns the lowercase hex SHA-256 of a DER encoded certificate.
pub fn fingerprint_of(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_stable_across_loads() {
        let t = tempfile::tempdir().unwrap();
        let a = Identity::load_or_create(t.path()).unwrap();
        let b = Identity::load_or_create(t.path()).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn fingerprint_is_64_hex_chars() {
        let t = tempfile::tempdir().unwrap();
        let fp = Identity::load_or_create(t.path()).unwrap().fingerprint();
        assert_eq!(fp.len(), 64);
        assert!(
            fp.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
    }

    #[test]
    fn different_dirs_give_different_identities() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let fa = Identity::load_or_create(a.path()).unwrap().fingerprint();
        let fb = Identity::load_or_create(b.path()).unwrap().fingerprint();
        assert_ne!(fa, fb);
    }

    #[cfg(unix)]
    #[test]
    fn private_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        Identity::load_or_create(t.path()).unwrap();
        let mode = std::fs::metadata(t.path().join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
