//! Gradle dependency lockfiles (`gradle.lockfile`, one per project of the
//! build, written by `gradle dependencies --write-locks`):
//!
//! ```text
//! # This is a Gradle generated file for dependency locking.
//! com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath
//! empty=annotationProcessor
//! ```
//!
//! Only the project lockfiles are read; `buildscript-gradle.lockfile` and
//! `settings-gradle.lockfile` (plugin classpaths) are not.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::ecosystem::AdapterError;

pub const FILE: &str = "gradle.lockfile";

/// Directories never searched for project lockfiles: build output, caches,
/// and the separate builds of convention plugins.
const SKIP_DIRS: &[&str] = &[
    "build",
    "buildSrc",
    "build-logic",
    "src",
    "out",
    "node_modules",
];
/// How deep below the root project lockfiles are searched.
const MAX_DEPTH: usize = 6;

/// One locked module version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// `group:artifact`.
    pub module: String,
    pub version: String,
    /// Configurations that resolve this version (`compileClasspath`, ...).
    pub configurations: BTreeSet<String>,
}

/// The lockfile of one project of the build.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lockfile {
    /// Project directory relative to the root (`""` = root project).
    pub dir: PathBuf,
    /// Sorted by module, then version.
    pub entries: Vec<Entry>,
    /// Every configuration the lockfile mentions, including `empty=` ones.
    pub configurations: BTreeSet<String>,
}

impl Lockfile {
    pub fn parse(dir: PathBuf, text: &str) -> Result<Lockfile, AdapterError> {
        let mut entries = Vec::new();
        let mut configurations = BTreeSet::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parse_error = || AdapterError::Parse {
                what: dir.join(FILE).display().to_string(),
                message: format!("unexpected line {line:?}"),
            };
            let (coordinates, confs) = line.split_once('=').ok_or_else(parse_error)?;
            let confs: BTreeSet<String> = confs
                .split(',')
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .map(str::to_string)
                .collect();
            configurations.extend(confs.iter().cloned());
            if coordinates == "empty" {
                continue;
            }
            let mut parts = coordinates.splitn(3, ':');
            let (Some(group), Some(artifact), Some(version)) =
                (parts.next(), parts.next(), parts.next())
            else {
                return Err(parse_error());
            };
            entries.push(Entry {
                module: format!("{group}:{artifact}"),
                version: version.to_string(),
                configurations: confs,
            });
        }
        entries.sort_by(|a, b| (&a.module, &a.version).cmp(&(&b.module, &b.version)));
        Ok(Lockfile {
            dir,
            entries,
            configurations,
        })
    }

    /// Whether the project resolves JVM classpaths, i.e. has the
    /// `implementation` configuration (java/kotlin/android plugins).
    pub fn has_classpaths(&self) -> bool {
        self.configurations.iter().any(|c| {
            ["compileClasspath", "runtimeClasspath"].contains(&c.as_str())
                || c.ends_with("CompileClasspath")
                || c.ends_with("RuntimeClasspath")
        })
    }

    /// Whether `module@version` is locked.
    pub fn contains(&self, module: &str, version: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.module == module && e.version == version)
    }
}

/// Whether the build rooted at `root` has a project lockfile.
pub fn exists(root: &Path) -> bool {
    let mut found = Vec::new();
    find(root, Path::new(""), 0, true, &mut found);
    !found.is_empty()
}

/// Every project lockfile of the build rooted at `root`, sorted by project
/// directory.
pub fn load_all(root: &Path) -> Result<Vec<Lockfile>, AdapterError> {
    let mut dirs = Vec::new();
    find(root, Path::new(""), 0, false, &mut dirs);
    dirs.sort();
    if dirs.is_empty() {
        return Err(AdapterError::Other(format!(
            "no {FILE} in {}: enable dependency locking \
             (`dependencyLocking {{ lockAllConfigurations() }}`) and run \
             `gradle dependencies --write-locks`",
            root.display()
        )));
    }
    dirs.into_iter()
        .map(|dir| {
            let text = std::fs::read_to_string(root.join(&dir).join(FILE))?;
            Lockfile::parse(dir, &text)
        })
        .collect()
}

/// Collect project directories (relative to `root`) holding a lockfile;
/// with `first`, stop at the first one.
fn find(root: &Path, rel: &Path, depth: usize, first: bool, out: &mut Vec<PathBuf>) {
    let dir = root.join(rel);
    if dir.join(FILE).is_file() {
        out.push(rel.to_path_buf());
        if first {
            return;
        }
    }
    if depth >= MAX_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    let mut subdirs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.file_name())
        .filter(|n| {
            let n = n.to_string_lossy();
            !n.starts_with('.') && !SKIP_DIRS.contains(&n.as_ref())
        })
        .map(|n| rel.join(n))
        .collect();
    subdirs.sort();
    for sub in subdirs {
        find(root, &sub, depth + 1, first, out);
        if first && !out.is_empty() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "\
# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
org.apache.commons:commons-text:1.9=compileClasspath,runtimeClasspath
org.apache.commons:commons-lang3:3.11=compileClasspath, runtimeClasspath,testRuntimeClasspath
empty=annotationProcessor
";

    #[test]
    fn parses_entries_and_configurations() {
        let lock = Lockfile::parse(PathBuf::from("app"), TEXT).unwrap();
        assert_eq!(
            lock.entries
                .iter()
                .map(|e| format!("{}@{}", e.module, e.version))
                .collect::<Vec<_>>(),
            [
                "org.apache.commons:commons-lang3@3.11",
                "org.apache.commons:commons-text@1.9"
            ]
        );
        assert_eq!(lock.entries[0].configurations.len(), 3);
        assert!(lock.configurations.contains("annotationProcessor"));
        assert!(lock.contains("org.apache.commons:commons-text", "1.9"));
        assert!(!lock.contains("org.apache.commons:commons-text", "1.10.0"));
        assert!(lock.has_classpaths());
        let android = Lockfile::parse(PathBuf::new(), "a:b:1=debugRuntimeClasspath\n").unwrap();
        assert!(android.has_classpaths());
        let other = Lockfile::parse(PathBuf::new(), "a:b:1=tools\n").unwrap();
        assert!(!other.has_classpaths());
        assert!(Lockfile::parse(PathBuf::new(), "nonsense\n").is_err());
        assert!(Lockfile::parse(PathBuf::new(), "a:b=x\n").is_err());
    }

    #[test]
    fn finds_project_lockfiles() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        assert!(!exists(root));
        let err = load_all(root).unwrap_err().to_string();
        assert!(err.contains("--write-locks"), "{err}");
        for rel in ["app", "libs/core", "build/tmp", "buildSrc", ".gradle/x"] {
            std::fs::create_dir_all(root.join(rel)).unwrap();
            std::fs::write(root.join(rel).join(FILE), "a:b:1=compileClasspath\n").unwrap();
        }
        assert!(exists(root));
        let dirs: Vec<PathBuf> = load_all(root).unwrap().into_iter().map(|l| l.dir).collect();
        assert_eq!(dirs, [PathBuf::from("app"), PathBuf::from("libs/core")]);
    }
}
