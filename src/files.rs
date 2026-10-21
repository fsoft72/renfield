//! Text file operations on the local machine, used by dest to serve remote file requests.

use std::fs::{self, Permissions};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result, bail};

use crate::home;
use crate::proto::{DirEntry, ListResult, ReadResult};

/// Largest amount of text returned by one read.
pub const MAX_READ_BYTES: usize = 1024 * 1024;
/// Largest file that can be read as text.
pub const MAX_READ_FILE: u64 = 64 * 1024 * 1024;
/// Largest number of entries returned by one listing.
pub const MAX_LIST_ENTRIES: usize = 10_000;
/// How many leading bytes are inspected to recognise a binary file.
const BINARY_SNIFF: usize = 8192;

/// Follows a symbolic link so that writes go through it instead of replacing it.
fn real_target(path: PathBuf) -> PathBuf {
    let is_link = fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink());
    if !is_link {
        return path;
    }
    fs::canonicalize(&path).unwrap_or(path)
}

/// Tells whether every line break of the data is CRLF (and there is at least one).
fn is_crlf(bytes: &[u8]) -> bool {
    let lf = bytes.iter().filter(|&&b| b == b'\n').count();
    let crlf = bytes.windows(2).filter(|w| w == b"\r\n").count();
    lf > 0 && lf == crlf
}

/// Reads a whole file as UTF-8 text, refusing binary or oversized files with a helpful message.
fn read_utf8(path: &Path, shown: &str) -> Result<String> {
    let meta = fs::metadata(path).with_context(|| format!("cannot read {shown}"))?;
    if meta.is_dir() {
        bail!("{shown} is a directory, use remote_list");
    }
    if meta.len() > MAX_READ_FILE {
        bail!(
            "{shown} is too large to read as text ({} bytes), use remote_get or run head/tail",
            meta.len()
        );
    }
    let bytes = fs::read(path).with_context(|| format!("cannot read {shown}"))?;
    let binary = bytes[..bytes.len().min(BINARY_SNIFF)].contains(&0);
    match String::from_utf8(bytes) {
        Ok(text) if !binary => Ok(text),
        _ => bail!("{shown} is not UTF-8 text, use remote_get to copy it"),
    }
}

/// Writes bytes to a temporary file next to the target and renames it into place.
fn write_atomic(target: &Path, data: &[u8], perms: Option<Permissions>) -> Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = target.with_file_name(format!(".{name}.renfield-tmp"));
    let result = (|| -> std::io::Result<()> {
        fs::write(&tmp, data)?;
        if let Some(p) = perms {
            fs::set_permissions(&tmp, p)?;
        }
        fs::rename(&tmp, target)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.with_context(|| format!("cannot write {}", target.display()))
}

/// Reads lines `offset..offset+limit` (1-based) of a UTF-8 text file.
pub fn read_text(path: &str, offset: Option<usize>, limit: Option<usize>) -> Result<ReadResult> {
    let text = read_utf8(&home::expand(path), path)?;
    let lines: Vec<&str> = text.lines().collect();
    let total_lines = lines.len();
    let first_line = offset.unwrap_or(1).max(1);
    let start = (first_line - 1).min(total_lines);
    let end = limit.map_or(total_lines, |l| (start + l).min(total_lines));
    let mut out = String::new();
    let mut truncated = false;
    for (i, line) in lines[start..end].iter().enumerate() {
        if out.len() + line.len() + 1 > MAX_READ_BYTES {
            truncated = true;
            break;
        }
        if i > 0 {
            out.push('\n');
        }
        out.push_str(line);
    }
    Ok(ReadResult {
        text: out,
        first_line,
        total_lines,
        truncated,
    })
}

/// Creates or overwrites a text file atomically, keeping CRLF endings of an existing file.
pub fn write_text(path: &str, content: &str) -> Result<usize> {
    let target = real_target(home::expand(path));
    let existing = fs::read(&target).ok();
    let data = match &existing {
        Some(old) if is_crlf(old) => content.replace("\r\n", "\n").replace('\n', "\r\n"),
        _ => content.to_string(),
    };
    let perms = fs::metadata(&target).ok().map(|m| m.permissions());
    write_atomic(&target, data.as_bytes(), perms)?;
    Ok(data.len())
}

/// Replaces `old` with `new`; fails when `old` is missing or ambiguous (unless `replace_all`).
pub fn edit_text(path: &str, old: &str, new: &str, replace_all: bool) -> Result<usize> {
    if old.is_empty() {
        bail!("old_string must not be empty");
    }
    if old == new {
        bail!("old_string and new_string are identical, nothing to change");
    }
    let target = real_target(home::expand(path));
    let text = read_utf8(&target, path)?;
    let crlf = is_crlf(text.as_bytes());
    let (work, old, new) = if crlf {
        (
            text.replace("\r\n", "\n"),
            old.replace("\r\n", "\n"),
            new.replace("\r\n", "\n"),
        )
    } else {
        (text, old.to_string(), new.to_string())
    };
    let found = work.matches(old.as_str()).count();
    if found == 0 {
        bail!("string not found in {path}");
    }
    if found > 1 && !replace_all {
        bail!(
            "found {found} matches of the string in {path}: add more context to make it unique, or use replace_all"
        );
    }
    let replaced = if replace_all {
        work.replace(old.as_str(), &new)
    } else {
        work.replacen(old.as_str(), &new, 1)
    };
    let out = if crlf {
        replaced.replace('\n', "\r\n")
    } else {
        replaced
    };
    let perms = fs::metadata(&target).ok().map(|m| m.permissions());
    write_atomic(&target, out.as_bytes(), perms)?;
    Ok(if replace_all { found } else { 1 })
}

/// Lists a directory, optionally recursively; hidden files are included.
pub fn list(path: &str, recursive: bool) -> Result<ListResult> {
    let root = home::expand(path);
    if !root.is_dir() {
        bail!("{path} is not a directory");
    }
    let mut entries = Vec::new();
    let truncated = walk(&root, "", recursive, &mut entries)?;
    Ok(ListResult { entries, truncated })
}

/// Appends the entries of `dir` (sorted by name); returns true when the entry cap was hit.
fn walk(dir: &Path, prefix: &str, recursive: bool, out: &mut Vec<DirEntry>) -> Result<bool> {
    let mut children: Vec<PathBuf> = fs::read_dir(dir)
        .with_context(|| format!("cannot list {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    children.sort();
    for child in children {
        if out.len() >= MAX_LIST_ENTRIES {
            return Ok(true);
        }
        let Ok(meta) = fs::symlink_metadata(&child) else {
            continue;
        };
        let file_type = meta.file_type();
        let kind = if file_type.is_symlink() {
            "symlink"
        } else if file_type.is_dir() {
            "dir"
        } else if file_type.is_file() {
            "file"
        } else {
            "other"
        };
        let name = format!(
            "{prefix}{}",
            child.file_name().unwrap_or_default().to_string_lossy()
        );
        let mtime_secs = meta
            .modified()
            .ok()
            .map(|t| match t.duration_since(UNIX_EPOCH) {
                Ok(d) => d.as_secs() as i64,
                Err(e) => -(e.duration().as_secs() as i64),
            })
            .unwrap_or(0);
        out.push(DirEntry {
            name: name.clone(),
            kind: kind.into(),
            size: meta.len(),
            mtime_secs,
        });
        if recursive && kind == "dir" && walk(&child, &format!("{name}/"), true, out)? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn p(dir: &tempfile::TempDir, name: &str) -> String {
        dir.path().join(name).to_string_lossy().into_owned()
    }

    #[test]
    fn edit_requires_unique_match() {
        let d = tmp();
        let f = p(&d, "a.txt");
        std::fs::write(&f, "foo bar foo\n").unwrap();
        let err = edit_text(&f, "foo", "baz", false).unwrap_err().to_string();
        assert!(err.contains("2 matches"), "{err}");
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "foo bar foo\n");
        assert_eq!(edit_text(&f, "bar", "baz", false).unwrap(), 1);
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "foo baz foo\n");
    }

    #[test]
    fn edit_replace_all_counts() {
        let d = tmp();
        let f = p(&d, "a.txt");
        std::fs::write(&f, "x x x\n").unwrap();
        assert_eq!(edit_text(&f, "x", "y", true).unwrap(), 3);
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "y y y\n");
    }

    #[test]
    fn edit_keeps_crlf_endings() {
        let d = tmp();
        let f = p(&d, "w.txt");
        std::fs::write(&f, "one\r\ntwo\r\nthree\r\n").unwrap();
        assert_eq!(edit_text(&f, "one\ntwo", "uno\ndue", false).unwrap(), 1);
        assert_eq!(std::fs::read(&f).unwrap(), b"uno\r\ndue\r\nthree\r\n");
    }

    #[test]
    fn edit_missing_string_errors_clearly() {
        let d = tmp();
        let f = p(&d, "a.txt");
        std::fs::write(&f, "hello\n").unwrap();
        let err = edit_text(&f, "nope", "x", false).unwrap_err().to_string();
        assert!(err.contains("not found") && err.contains("a.txt"), "{err}");
        assert!(edit_text(&f, "", "x", false).is_err());
        assert!(edit_text(&f, "hello", "hello", false).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn edit_keeps_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp();
        let f = p(&d, "run.sh");
        std::fs::write(&f, "echo a\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        edit_text(&f, "a", "b", false).unwrap();
        let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn write_creates_parents_and_keeps_crlf() {
        let d = tmp();
        let f = p(&d, "sub/dir/n.txt");
        assert_eq!(write_text(&f, "a\nb\n").unwrap(), 4);
        assert_eq!(std::fs::read(&f).unwrap(), b"a\nb\n");
        let w = p(&d, "w.txt");
        std::fs::write(&w, "x\r\ny\r\n").unwrap();
        write_text(&w, "new\nlines\n").unwrap();
        assert_eq!(std::fs::read(&w).unwrap(), b"new\r\nlines\r\n");
    }

    #[test]
    fn write_is_atomic_no_partial_file_on_error() {
        let d = tmp();
        let target = p(&d, "dir");
        std::fs::create_dir(&target).unwrap();
        assert!(write_text(&target, "data").is_err());
        let leftovers: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers.len(), 1, "temp file left behind: {leftovers:?}");
    }

    #[test]
    fn read_offset_limit_lines() {
        let d = tmp();
        let f = p(&d, "l.txt");
        std::fs::write(&f, "l1\nl2\r\nl3\nl4\n").unwrap();
        let all = read_text(&f, None, None).unwrap();
        assert_eq!(
            (all.first_line, all.total_lines, all.truncated),
            (1, 4, false)
        );
        assert_eq!(all.text, "l1\nl2\nl3\nl4");
        let part = read_text(&f, Some(2), Some(2)).unwrap();
        assert_eq!(part.text, "l2\nl3");
        assert_eq!(part.first_line, 2);
        let past = read_text(&f, Some(99), None).unwrap();
        assert_eq!(past.text, "");
    }

    #[test]
    fn read_binary_errors_pointing_to_remote_get() {
        let d = tmp();
        let f = p(&d, "b.bin");
        std::fs::write(&f, [0u8, 159, 146, 150]).unwrap();
        let err = read_text(&f, None, None).unwrap_err().to_string();
        assert!(err.contains("remote_get"), "{err}");
    }

    #[test]
    fn read_over_1mib_is_capped() {
        let d = tmp();
        let f = p(&d, "big.txt");
        let line = format!("{}\n", "x".repeat(99));
        std::fs::write(&f, line.repeat(30_000)).unwrap();
        let r = read_text(&f, None, None).unwrap();
        assert!(r.truncated);
        assert!(r.text.len() <= MAX_READ_BYTES);
        assert_eq!(r.total_lines, 30_000);
    }

    #[test]
    fn list_includes_hidden_and_metadata() {
        let d = tmp();
        std::fs::write(d.path().join(".hidden"), "abc").unwrap();
        std::fs::create_dir(d.path().join("sub")).unwrap();
        std::fs::write(d.path().join("sub/inner.txt"), "12345").unwrap();
        let flat = list(&p(&d, ""), false).unwrap();
        let names: Vec<_> = flat.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec![".hidden", "sub"]);
        assert_eq!(flat.entries[0].kind, "file");
        assert_eq!(flat.entries[0].size, 3);
        assert_eq!(flat.entries[1].kind, "dir");
        assert!(flat.entries[0].mtime_secs > 1_000_000_000);
        let deep = list(&p(&d, ""), true).unwrap();
        assert!(
            deep.entries
                .iter()
                .any(|e| e.name == "sub/inner.txt" && e.size == 5)
        );
    }

    #[test]
    fn paths_with_spaces_and_unicode_work() {
        let d = tmp();
        let f = p(&d, "my dir/caffè è.txt");
        write_text(&f, "ciao\n").unwrap();
        assert_eq!(read_text(&f, None, None).unwrap().text, "ciao");
        assert_eq!(edit_text(&f, "ciao", "ciào", false).unwrap(), 1);
        assert_eq!(
            list(&p(&d, "my dir"), false).unwrap().entries[0].name,
            "caffè è.txt"
        );
    }

    #[cfg(unix)]
    #[test]
    fn edit_writes_through_a_symlink() {
        let d = tmp();
        let real = p(&d, "real.txt");
        let link = p(&d, "link.txt");
        std::fs::write(&real, "alpha\n").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        edit_text(&link, "alpha", "beta", false).unwrap();
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the link was replaced"
        );
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "beta\n");
        write_text(&link, "gamma\n").unwrap();
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "gamma\n");
    }
}
