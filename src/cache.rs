//! A simple on-disk cache: one file per key, grouped in namespaces.
//!
//! Location (first that applies; empty variables are ignored):
//! 1. `$MENDR_CACHE_DIR`
//! 2. `$XDG_CACHE_HOME/mendr`
//! 3. `$HOME/.cache/mendr`
//! 4. `mendr-<uid>` (`mendr` off Unix) in the system temp directory
//!
//! Namespaces in use: `osv` (advisory records). Adapters should use their own
//! namespace (`cargo-index`, `crates-io`, `npm`, `pnpm`). Cache failures are never
//! fatal: reads return `None`, writes are best-effort.
//!
//! The root holds a `CACHEDIR.TAG` (<https://bford.info/cachedir/>), written
//! with the first entry. [`prune`] only touches tagged roots, so a mistyped
//! `MENDR_CACHE_DIR` never loses files.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

/// Entries not rewritten for this long are deleted by [`prune`].
const MAX_AGE: Duration = Duration::from_secs(30 * 86_400);
/// Temp files of interrupted writes older than this are deleted by [`prune`].
const TEMP_MAX_AGE: Duration = Duration::from_secs(3600);
const TAG_FILE: &str = "CACHEDIR.TAG";
const TAG_SIGNATURE: &str = "Signature: 8a477f597d28d172789f06886806bc55";

/// Root cache directory (not created until something is written).
pub fn cache_dir() -> PathBuf {
    cache_dir_from(|name| std::env::var_os(name))
}

fn cache_dir_from(var: impl Fn(&str) -> Option<OsString>) -> PathBuf {
    let var = |name: &str| var(name).filter(|v| !v.is_empty());
    if let Some(dir) = var("MENDR_CACHE_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(dir) = var("XDG_CACHE_HOME") {
        return PathBuf::from(dir).join("mendr");
    }
    if let Some(home) = var("HOME") {
        return PathBuf::from(home).join(".cache").join("mendr");
    }
    // Per user: the temp directory may be shared (`/tmp`), and another
    // user's cache must not feed us advisories.
    #[cfg(unix)]
    let name = format!("mendr-{}", unsafe { libc::getuid() });
    #[cfg(not(unix))]
    let name = "mendr".to_string();
    std::env::temp_dir().join(name)
}

/// Turn an arbitrary key into a safe file name (`[A-Za-z0-9._-]`, others
/// become `_`, plus a short hash when anything was replaced to avoid
/// collisions).
fn file_name(key: &str) -> String {
    let safe: String = key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if safe == key && !key.starts_with('.') {
        safe
    } else {
        // FNV-1a, stable across runs and platforms.
        let mut h: u64 = 0xcbf29ce484222325;
        for b in key.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        format!("{}-{:016x}", safe.trim_start_matches('.'), h)
    }
}

fn path_in(root: &Path, namespace: &str, key: &str) -> PathBuf {
    root.join(namespace).join(file_name(key))
}

/// Cached value, if present and (when `max_age` is given) younger than it.
pub fn read(namespace: &str, key: &str, max_age: Option<Duration>) -> Option<String> {
    read_in(&cache_dir(), namespace, key, max_age)
}

/// [`read`] with an explicit cache root.
pub fn read_in(
    root: &Path,
    namespace: &str,
    key: &str,
    max_age: Option<Duration>,
) -> Option<String> {
    let p = path_in(root, namespace, key);
    if let Some(max_age) = max_age {
        let modified = std::fs::metadata(&p).ok()?.modified().ok()?;
        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default();
        if age > max_age {
            return None;
        }
    }
    std::fs::read_to_string(p).ok()
}

/// Store a value (best-effort; errors are ignored).
pub fn write(namespace: &str, key: &str, value: &str) {
    write_in(&cache_dir(), namespace, key, value)
}

/// [`write`] with an explicit cache root.
pub fn write_in(root: &Path, namespace: &str, key: &str, value: &str) {
    let p = path_in(root, namespace, key);
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let tag = root.join(TAG_FILE);
    if !tag.exists() {
        let _ = std::fs::write(
            &tag,
            format!("{TAG_SIGNATURE}\n# This is a cache directory created by mendr.\n"),
        );
    }
    // Write to a temp file then rename, so readers never see partial data.
    // The name is unique per key, process and call: `with_extension` would cut
    // keys at their last dot and let concurrent writers share one temp file.
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let Some(name) = p.file_name() else { return };
    let tmp = p.with_file_name(format!(
        "{}.tmp{}.{}",
        name.to_string_lossy(),
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    if std::fs::write(&tmp, value).is_ok() && std::fs::rename(&tmp, &p).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Delete entries older than 30 days and temp files of interrupted writes
/// older than an hour. Call once at startup; best-effort, never fails.
pub fn prune() {
    prune_in(&cache_dir(), SystemTime::now());
}

fn prune_in(root: &Path, now: SystemTime) {
    let tagged =
        std::fs::read_to_string(root.join(TAG_FILE)).is_ok_and(|t| t.starts_with(TAG_SIGNATURE));
    if !tagged {
        return;
    }
    let Ok(namespaces) = std::fs::read_dir(root) else {
        return;
    };
    for ns in namespaces.flatten() {
        if !ns.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(ns.path()) else {
            continue;
        };
        for entry in entries.flatten() {
            // `DirEntry::metadata` does not follow symlinks.
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            let age = meta
                .modified()
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .unwrap_or_default();
            let limit = if is_temp_name(&entry.file_name().to_string_lossy()) {
                TEMP_MAX_AGE
            } else {
                MAX_AGE
            };
            if age > limit {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// Whether `name` is a temp file of [`write_in`]: `<name>.tmp<pid>.<n>`.
fn is_temp_name(name: &str) -> bool {
    let all_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    name.rsplit_once(".tmp")
        .and_then(|(_, rest)| rest.split_once('.'))
        .is_some_and(|(pid, n)| all_digits(pid) && all_digits(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_are_safe_and_distinct() {
        assert_eq!(file_name("RUSTSEC-2020-0001"), "RUSTSEC-2020-0001");
        let a = file_name("@scope/pkg");
        let b = file_name("_scope_pkg");
        assert_ne!(a, b);
        assert!(!a.contains('/'));
        assert!(!file_name("..").starts_with('.'));
    }

    #[test]
    fn concurrent_writes_of_dotted_keys_stay_separate() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let keys: Vec<String> = (0..16)
            .map(|i| format!("registry.npmjs.org/pkg{i}"))
            .collect();
        std::thread::scope(|s| {
            for k in &keys {
                s.spawn(move || write_in(root, "t", k, k));
            }
        });
        for k in &keys {
            assert_eq!(read_in(root, "t", k, None).as_deref(), Some(k.as_str()));
        }
    }

    /// Set the modification time of `path` to `secs` ago.
    fn age(path: &Path, secs: u64) {
        let f = std::fs::File::options().write(true).open(path).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(secs))
            .unwrap();
    }

    #[test]
    fn location_ignores_empty_variables() {
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                vars.iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| OsString::from(v))
            }
        };
        assert_eq!(
            cache_dir_from(env(&[("MENDR_CACHE_DIR", "/c"), ("HOME", "/h")])),
            PathBuf::from("/c")
        );
        assert_eq!(
            cache_dir_from(env(&[("MENDR_CACHE_DIR", ""), ("XDG_CACHE_HOME", "/x")])),
            PathBuf::from("/x/mendr")
        );
        assert_eq!(
            cache_dir_from(env(&[("XDG_CACHE_HOME", ""), ("HOME", "/h")])),
            PathBuf::from("/h/.cache/mendr")
        );
        let fallback = cache_dir_from(env(&[("HOME", "")]));
        assert!(fallback.starts_with(std::env::temp_dir()));
        assert!(
            fallback
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("mendr")
        );
    }

    #[test]
    fn reads_respect_age_and_survive_bad_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        assert_eq!(read_in(root, "t", "missing", None), None);
        write_in(root, "t", "k", "v");
        assert_eq!(read_in(root, "t", "k", None).as_deref(), Some("v"));
        let hour = Duration::from_secs(3600);
        assert_eq!(read_in(root, "t", "k", Some(hour)).as_deref(), Some("v"));
        age(&path_in(root, "t", "k"), 7200);
        assert_eq!(read_in(root, "t", "k", Some(hour)), None, "too old");
        assert_eq!(read_in(root, "t", "k", None).as_deref(), Some("v"));

        std::fs::write(path_in(root, "t", "binary"), [0xff, 0xfe, 0x00]).unwrap();
        assert_eq!(read_in(root, "t", "binary", None), None, "not UTF-8");
        std::fs::create_dir_all(path_in(root, "t", "dir")).unwrap();
        assert_eq!(read_in(root, "t", "dir", None), None, "not a file");
        write_in(root, "t", "dir", "v");
        assert_eq!(
            read_in(root, "t", "dir", None),
            None,
            "write failed quietly"
        );
        let leftovers = std::fs::read_dir(root.join("t"))
            .unwrap()
            .flatten()
            .filter(|e| is_temp_name(&e.file_name().to_string_lossy()))
            .count();
        assert_eq!(leftovers, 0, "failed rename cleans up its temp file");
        // A file where the namespace directory should be.
        std::fs::write(root.join("blocked"), "").unwrap();
        write_in(root, "blocked", "k", "v");
        assert_eq!(read_in(root, "blocked", "k", None), None);
    }

    #[test]
    fn temp_names() {
        assert!(is_temp_name("pkg.tmp123.0"));
        assert!(is_temp_name("registry.npmjs.org_foo-0123abcd.tmp9.42"));
        assert!(!is_temp_name("pkg"));
        assert!(!is_temp_name("pkg.tmp"));
        assert!(!is_temp_name("left-pad.tmpl"));
        assert!(!is_temp_name("x.tmp1.2a"));
    }

    #[test]
    fn prune_removes_old_entries_and_stale_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for key in ["old", "fresh"] {
            write_in(root, "ns", key, key);
        }
        assert!(root.join(TAG_FILE).is_file());
        let ns = root.join("ns");
        age(&ns.join("old"), 31 * 86_400);
        age(&ns.join("fresh"), 29 * 86_400);
        for (name, secs) in [("a.tmp1.0", 7200), ("b.tmp1.1", 60)] {
            std::fs::write(ns.join(name), "").unwrap();
            age(&ns.join(name), secs);
        }
        std::fs::create_dir(ns.join("nested")).unwrap();
        std::fs::write(ns.join("nested").join("deep"), "").unwrap();
        age(&ns.join("nested").join("deep"), 365 * 86_400);
        std::fs::write(root.join("top"), "").unwrap();
        age(&root.join("top"), 365 * 86_400);

        prune_in(root, SystemTime::now());
        assert!(!ns.join("old").exists());
        assert!(ns.join("fresh").exists());
        assert!(!ns.join("a.tmp1.0").exists());
        assert!(ns.join("b.tmp1.1").exists());
        assert!(ns.join("nested").join("deep").exists(), "not recursive");
        assert!(root.join("top").exists(), "only namespace directories");
        assert!(root.join(TAG_FILE).exists());

        // Without the tag nothing is touched.
        let other = tempfile::tempdir().unwrap();
        std::fs::create_dir(other.path().join("ns")).unwrap();
        let precious = other.path().join("ns").join("precious");
        std::fs::write(&precious, "").unwrap();
        age(&precious, 365 * 86_400);
        prune_in(other.path(), SystemTime::now());
        assert!(precious.exists());
        prune_in(&other.path().join("missing"), SystemTime::now());
    }
}
