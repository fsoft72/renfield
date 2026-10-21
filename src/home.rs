//! Resolution of the renfield configuration directory.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Environment variable that overrides the configuration directory.
pub const HOME_ENV: &str = "RENFIELD_HOME";

/// Directory name used under the OS configuration directory.
const APP_DIR: &str = "renfield";

/// Returns the configuration directory, creating it when missing.
pub fn dir() -> Result<PathBuf> {
    let path = dir_from(std::env::var_os(HOME_ENV))?;
    std::fs::create_dir_all(&path)
        .with_context(|| format!("cannot create config directory {}", path.display()))?;
    Ok(path)
}

/// Computes the configuration directory from an optional override, without touching the disk.
pub fn dir_from(override_dir: Option<OsString>) -> Result<PathBuf> {
    if let Some(dir) = override_dir {
        return Ok(PathBuf::from(dir));
    }
    let base = dirs::config_dir()
        .context("cannot determine the OS configuration directory, set RENFIELD_HOME")?;
    Ok(base.join(APP_DIR))
}

/// Expands a user supplied path: `~` is the home directory and relative paths start from it.
pub fn expand(path: &str) -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    if path == "~" {
        return home;
    }
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        return home.join(rest);
    }
    let p = PathBuf::from(path);
    if p.is_absolute() { p } else { home.join(p) }
}

/// Restricts a file so that only its owner can read and write it (no-op on non unix systems).
pub fn restrict_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("cannot restrict permissions of {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_wins() {
        let p = dir_from(Some(OsString::from("/tmp/xyz"))).unwrap();
        assert_eq!(p, PathBuf::from("/tmp/xyz"));
    }

    #[test]
    fn default_ends_with_app_dir() {
        let p = dir_from(None).unwrap();
        assert!(p.ends_with("renfield"));
    }

    #[cfg(unix)]
    #[test]
    fn restrict_sets_0600() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("k");
        std::fs::write(&f, b"x").unwrap();
        restrict_permissions(&f).unwrap();
        let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn expand_tilde_relative_and_absolute() {
        let home = dirs::home_dir().unwrap();
        assert_eq!(expand("~"), home);
        assert_eq!(expand("~/proj"), home.join("proj"));
        assert_eq!(expand("proj/src"), home.join("proj/src"));
        let abs = std::env::temp_dir();
        assert_eq!(expand(abs.to_str().unwrap()), abs);
    }
}
