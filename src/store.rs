//! Persistent stores: the registry of known machines and the list of authorized keys.

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// Reads a TOML file, returning the default value when the file does not exist.
fn load_toml<T: DeserializeOwned + Default>(path: &Path) -> Result<T> {
    if !path.exists() {
        return Ok(T::default());
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    toml::from_str(&text)
        .with_context(|| format!("{} is not valid, fix or delete it", path.display()))
}

/// Writes a value as TOML, replacing the file atomically.
fn save_toml<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let text = toml::to_string_pretty(value).context("cannot serialize store")?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text).with_context(|| format!("cannot write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))
}

/// File name of the registry inside the configuration directory.
pub const REGISTRY_FILE: &str = "registry.toml";
/// File name of the authorized keys inside the configuration directory.
pub const AUTHORIZED_FILE: &str = "authorized.toml";

/// A machine this host can command.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub addr: String,
    pub fingerprint: String,
}

/// Registry mapping machine names to address and pinned fingerprint.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default)]
    pub machine: Vec<Entry>,
}

impl Registry {
    /// Loads the registry from `dir`; a missing file gives an empty registry.
    pub fn load(dir: &Path) -> Result<Registry> {
        load_toml(&dir.join(REGISTRY_FILE))
    }

    /// Saves the registry into `dir`.
    pub fn save(&self, dir: &Path) -> Result<()> {
        save_toml(&dir.join(REGISTRY_FILE), self)
    }

    /// Adds an entry; fails when the name exists and `force` is false, otherwise replaces it.
    pub fn add(&mut self, entry: Entry, force: bool) -> Result<()> {
        if let Some(pos) = self.machine.iter().position(|e| e.name == entry.name) {
            if !force {
                bail!(
                    "machine '{}' is already registered, use --force to replace it",
                    entry.name
                );
            }
            self.machine[pos] = entry;
            return Ok(());
        }
        self.machine.push(entry);
        Ok(())
    }

    /// Returns the entry with the given name.
    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.machine.iter().find(|e| e.name == name)
    }

    /// Removes an entry; returns whether something was removed.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.machine.len();
        self.machine.retain(|e| e.name != name);
        self.machine.len() != before
    }
}

/// A key allowed to command this machine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizedKey {
    pub fingerprint: String,
    pub label: String,
}

/// Keys that are allowed to connect to this machine as a source.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Authorized {
    #[serde(default)]
    pub key: Vec<AuthorizedKey>,
}

impl Authorized {
    /// Loads the authorized keys from `dir`; a missing file gives an empty list.
    pub fn load(dir: &Path) -> Result<Authorized> {
        load_toml(&dir.join(AUTHORIZED_FILE))
    }

    /// Saves the authorized keys into `dir`.
    pub fn save(&self, dir: &Path) -> Result<()> {
        save_toml(&dir.join(AUTHORIZED_FILE), self)
    }

    /// Authorizes a fingerprint (no duplicate is created).
    pub fn add(&mut self, fingerprint: &str, label: &str) {
        if self.contains(fingerprint) {
            return;
        }
        self.key.push(AuthorizedKey {
            fingerprint: fingerprint.into(),
            label: label.into(),
        });
    }

    /// Returns the authorized key with this fingerprint.
    pub fn find(&self, fingerprint: &str) -> Option<&AuthorizedKey> {
        self.key.iter().find(|k| k.fingerprint == fingerprint)
    }

    /// Tells whether a fingerprint is authorized.
    pub fn contains(&self, fingerprint: &str) -> bool {
        self.key.iter().any(|k| k.fingerprint == fingerprint)
    }

    /// Revokes by fingerprint or label; returns whether something was removed.
    pub fn revoke(&mut self, fingerprint_or_label: &str) -> bool {
        let before = self.key.len();
        self.key
            .retain(|k| k.fingerprint != fingerprint_or_label && k.label != fingerprint_or_label);
        self.key.len() != before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str) -> Entry {
        Entry {
            name: name.into(),
            addr: "10.0.0.2:47822".into(),
            fingerprint: "ab".repeat(32),
        }
    }

    #[test]
    fn registry_roundtrip() {
        let t = tempfile::tempdir().unwrap();
        let mut r = Registry::load(t.path()).unwrap();
        assert!(r.machine.is_empty());
        r.add(entry("win-pc"), false).unwrap();
        r.save(t.path()).unwrap();
        let again = Registry::load(t.path()).unwrap();
        assert_eq!(again.get("win-pc"), Some(&entry("win-pc")));
    }

    #[test]
    fn registry_add_duplicate_without_force_fails() {
        let mut r = Registry::default();
        r.add(entry("a"), false).unwrap();
        let err = r.add(entry("a"), false).unwrap_err().to_string();
        assert!(err.contains("already"), "{err}");
        r.add(entry("a"), true).unwrap();
        assert_eq!(r.machine.len(), 1);
    }

    #[test]
    fn registry_remove() {
        let mut r = Registry::default();
        r.add(entry("a"), false).unwrap();
        assert!(r.remove("a"));
        assert!(!r.remove("a"));
    }

    #[test]
    fn authorized_contains_after_add_and_not_after_revoke() {
        let t = tempfile::tempdir().unwrap();
        let mut a = Authorized::load(t.path()).unwrap();
        a.add("f1", "laptop");
        a.add("f1", "laptop");
        assert_eq!(a.key.len(), 1);
        a.save(t.path()).unwrap();
        let mut again = Authorized::load(t.path()).unwrap();
        assert!(again.contains("f1"));
        assert!(again.revoke("laptop"));
        assert!(!again.contains("f1"));
        assert!(!again.revoke("laptop"));
    }
}
