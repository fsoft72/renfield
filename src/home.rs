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

/// Writes a secret file that is owner-only from the moment it exists (no window with wider permissions).
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(data)
        .with_context(|| format!("cannot write {}", path.display()))?;
    // A file that already existed keeps its old mode: tighten it as well.
    restrict_permissions(path)
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

    #[cfg(unix)]
    #[test]
    fn write_private_creates_the_file_owner_only_even_with_a_permissive_umask() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("secret");
        // SAFETY: umask only changes the process file mode mask; restored right after.
        let old = unsafe { libc::umask(0) };
        let created = write_private(&f, b"key bytes");
        unsafe { libc::umask(old) };
        created.unwrap();
        let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(&f).unwrap(), b"key bytes");
    }

    #[cfg(unix)]
    #[test]
    fn write_private_tightens_an_existing_loose_file() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("secret");
        std::fs::write(&f, b"old").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&f, b"new").unwrap();
        let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(&f).unwrap(), b"new");
    }
}
