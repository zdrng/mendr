//! A simple on-disk cache: one file per key, grouped in namespaces.
//!
//! Location (first that applies):
//! 1. `$MENDR_CACHE_DIR`
//! 2. `$XDG_CACHE_HOME/mendr`
//! 3. `$HOME/.cache/mendr`
//! 4. `./.mendr-cache`
//!
//! Namespaces in use: `osv` (advisory records). Adapters should use their own
//! namespace (`cargo-index`, `crates-io`, `npm`, `pnpm`). Cache failures are never
//! fatal: reads return `None`, writes are best-effort.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Root cache directory (not created until something is written).
pub fn cache_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("MENDR_CACHE_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(dir) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(dir).join("mendr");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".cache").join("mendr");
    }
    PathBuf::from(".mendr-cache")
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

pub fn path(namespace: &str, key: &str) -> PathBuf {
    cache_dir().join(namespace).join(file_name(key))
}

/// Cached value, if present and (when `max_age` is given) younger than it.
pub fn read(namespace: &str, key: &str, max_age: Option<Duration>) -> Option<String> {
    let p = path(namespace, key);
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
    let p = path(namespace, key);
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Write to a temp file then rename, so readers never see partial data.
    let tmp = p.with_extension(format!("tmp{}", std::process::id()));
    if std::fs::write(&tmp, value).is_ok() {
        let _ = std::fs::rename(&tmp, &p);
    }
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
}
