//! Optional configuration file of a dest machine.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Port dest listens on when neither `--port` nor the configuration file set one.
pub const DEFAULT_PORT: u16 = 47822;
/// File name of the configuration inside the configuration directory.
pub const CONFIG_FILE: &str = "config.toml";

/// Settings a dest machine may read from its configuration file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// TCP port to listen on.
    pub port: Option<u16>,
    /// Working directory of commands when the caller gives none (default: the user's home).
    pub default_cwd: Option<String>,
    /// Hard upper bound, in seconds, for any command.
    pub max_timeout_secs: Option<u64>,
}

impl Config {
    /// Loads a configuration file; a missing file is an error only when `must_exist` is true.
    pub fn load(path: &Path, must_exist: bool) -> Result<Config> {
        if !path.exists() && !must_exist {
            return Ok(Config::default());
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config file {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("invalid config file {}", path.display()))
    }

    /// Loads `config.toml` from the configuration directory, if present.
    pub fn load_default(dir: &Path) -> Result<Config> {
        Config::load(&dir.join(CONFIG_FILE), false)
    }
}

/// Picks the listening port: command line first, then configuration file, then the default.
pub fn resolve_port(cli: Option<u16>, config: &Config) -> u16 {
    cli.or(config.port).unwrap_or(DEFAULT_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_default_file_gives_defaults() {
        let t = tempfile::tempdir().unwrap();
        let c = Config::load_default(t.path()).unwrap();
        assert_eq!(resolve_port(None, &c), DEFAULT_PORT);
    }

    #[test]
    fn file_values_are_read_and_cli_port_wins() {
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("c.toml");
        std::fs::write(
            &f,
            "port = 5000\ndefault_cwd = \"~/work\"\nmax_timeout_secs = 60\n",
        )
        .unwrap();
        let c = Config::load(&f, true).unwrap();
        assert_eq!(c.default_cwd.as_deref(), Some("~/work"));
        assert_eq!(c.max_timeout_secs, Some(60));
        assert_eq!(resolve_port(None, &c), 5000);
        assert_eq!(resolve_port(Some(6000), &c), 6000);
    }

    #[test]
    fn explicit_missing_file_is_an_error_naming_the_path() {
        let err = Config::load(std::path::Path::new("/no/such/renfield.toml"), true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("/no/such/renfield.toml"), "{err}");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("c.toml");
        std::fs::write(&f, "prot = 1\n").unwrap();
        assert!(Config::load(&f, true).is_err());
    }
}
