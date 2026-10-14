//! Gradle overrides: dependency constraints that keep vulnerable versions
//! out, in one marked `dependencies { constraints { .. } }` block that
//! mendr appends to a project's build script and then maintains.

use std::path::{Path, PathBuf};

use crate::ecosystem::AdapterError;

/// First line of the block mendr maintains.
const MARKER: &str = "// Added by mendr: constraints that keep vulnerable versions out.";

/// Add a dependency constraint forcing at least `module:to` to the build
/// script of the Gradle project in `root.join(project_dir)` (`""` = root
/// project), on `configuration` (e.g. `implementation`). Uses
/// `build.gradle.kts` or `build.gradle` in that directory; if neither
/// exists, creates `build.gradle.kts` when the root uses the Kotlin DSL,
/// else `build.gradle`. `reason` is written verbatim into `because(..)`.
/// A constraint on `module` already in mendr's block gets version `to`.
pub fn add(
    root: &Path,
    project_dir: &Path,
    configuration: &str,
    module: &str,
    to: &str,
    reason: &str,
) -> Result<(), AdapterError> {
    let path = script(root, &root.join(project_dir));
    let kotlin = path.extension().is_some_and(|e| e == "kts");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };
    let new = with_constraint(&text, kotlin, configuration, module, to, reason)
        .map_err(|e| AdapterError::ManifestNotEditable(format!("{}: {e}", path.display())))?;
    Ok(std::fs::write(&path, new)?)
}

/// The build script of the project in `dir` (possibly not existing yet).
fn script(root: &Path, dir: &Path) -> PathBuf {
    for name in ["build.gradle.kts", "build.gradle"] {
        if dir.join(name).is_file() {
            return dir.join(name);
        }
    }
    let kotlin =
        root.join("settings.gradle.kts").is_file() || root.join("build.gradle.kts").is_file();
    dir.join(if kotlin {
        "build.gradle.kts"
    } else {
        "build.gradle"
    })
}

/// `text` with the constraint added to (or updated in) mendr's block.
fn with_constraint(
    text: &str,
    kotlin: bool,
    configuration: &str,
    module: &str,
    to: &str,
    reason: &str,
) -> Result<String, String> {
    let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let entry = entry(kotlin, configuration, module, to, reason);
    let Some(marker) = text.find(MARKER) else {
        let block = format!("{MARKER}\ndependencies {{\n    constraints {{\n{entry}    }}\n}}\n")
            .replace('\n', eol);
        let mut out = text.to_string();
        if text.is_empty() {
            return Ok(block);
        }
        if !text.ends_with('\n') {
            // Keep the file's missing trailing newline.
            out.push_str(eol);
            out.push_str(eol);
            out.push_str(block.strip_suffix(eol).unwrap_or(&block));
        } else {
            out.push_str(eol);
            out.push_str(&block);
        }
        return Ok(out);
    };
    let (open, close) =
        constraints_block(text, marker).ok_or("mendr's constraints block was edited")?;
    let body = &text[open..close];
    for q in ['"', '\''] {
        let needle = format!("{q}{module}:");
        if let Some(at) = body.find(&needle) {
            let start = open + at + needle.len();
            let len = text[start..]
                .find([q, ':', '@'])
                .ok_or("unterminated string")?;
            let mut out = text.to_string();
            out.replace_range(start..start + len, to);
            return Ok(out);
        }
    }
    // Insert as the last entry, before the line holding the closing brace.
    let line = text[..close].rfind('\n').map_or(0, |n| n + 1);
    let at = if text[line..close].trim().is_empty() {
        line
    } else {
        close
    };
    let mut out = text.to_string();
    out.insert_str(at, &entry.replace('\n', eol));
    Ok(out)
}

/// One constraint, indented for mendr's block, with a trailing newline.
fn entry(kotlin: bool, configuration: &str, module: &str, to: &str, reason: &str) -> String {
    if kotlin {
        let reason = escape(reason, &['"', '$']);
        format!(
            "        {configuration}(\"{module}:{to}\") {{\n            because(\"{reason}\")\n        }}\n"
        )
    } else {
        let reason = escape(reason, &['\'']);
        format!(
            "        {configuration}('{module}:{to}') {{\n            because '{reason}'\n        }}\n"
        )
    }
}

/// `s` as the body of a string literal: backslashes, `special` characters
/// and line breaks escaped.
fn escape(s: &str, special: &[char]) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\\' => out.push_str("\\\\"),
            _ if special.contains(&c) => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Byte range of the body of the `constraints {` block following the
/// marker at `from` (after `{`, up to the closing `}`).
fn constraints_block(text: &str, from: usize) -> Option<(usize, usize)> {
    let deps = from + text[from..].find("dependencies")?;
    let kw = deps + text[deps..].find("constraints")?;
    let after = &text[kw + "constraints".len()..];
    let open = kw + "constraints".len() + after.find('{')? + 1;
    if !after[..open - kw - "constraints".len() - 1]
        .trim()
        .is_empty()
    {
        return None;
    }
    let b = text.as_bytes();
    let (mut depth, mut i) = (1, open);
    while i < b.len() {
        match b[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((open, i));
                }
            }
            q @ (b'"' | b'\'') => {
                i += 1;
                while i < b.len() && b[i] != q {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                i = text[i..].find('\n').map_or(b.len(), |n| i + n);
            }
            _ => {}
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const KOTLIN_BLOCK: &str = r#"
// Added by mendr: constraints that keep vulnerable versions out.
dependencies {
    constraints {
        implementation("g.x:a:1.2.4") {
            because("mendr: g.x:a 1.2.3 is vulnerable")
        }
    }
}
"#;

    const KOTLIN_ENTRY_B: &str = r#"        api("g.x:b:2.0") {
            because("say \"hi\" \$x \\ ok")
        }
"#;

    const GROOVY_BLOCK: &str = r#"
// Added by mendr: constraints that keep vulnerable versions out.
dependencies {
    constraints {
        implementation('g.x:a:1.2.4') {
            because 'mendr: g.x:a 1.2.3 is vulnerable'
        }
    }
}
"#;

    const GROOVY_ENTRY_B: &str = r#"        api('g.x:b:2.0') {
            because 'it\'s $x'
        }
"#;

    fn project(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, text) in files {
            let path = dir.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        dir
    }

    fn read(dir: &tempfile::TempDir, name: &str) -> String {
        std::fs::read_to_string(dir.path().join(name)).unwrap()
    }

    fn add_a(dir: &tempfile::TempDir, project: &str, to: &str) {
        let reason = "mendr: g.x:a 1.2.3 is vulnerable";
        add(
            dir.path(),
            Path::new(project),
            "implementation",
            "g.x:a",
            to,
            reason,
        )
        .unwrap();
    }

    #[test]
    fn kotlin_append_insert_replace() {
        let original = "plugins {\n    java\n}\n";
        let dir = project(&[("build.gradle.kts", original)]);
        add_a(&dir, "", "1.2.4");
        let first = format!("{original}{KOTLIN_BLOCK}");
        assert_eq!(read(&dir, "build.gradle.kts"), first);

        let reason = "say \"hi\" $x \\ ok";
        add(dir.path(), Path::new(""), "api", "g.x:b", "2.0", reason).unwrap();
        let second = first.replace("    }\n}\n", &format!("{KOTLIN_ENTRY_B}    }}\n}}\n"));
        assert_eq!(read(&dir, "build.gradle.kts"), second);

        add_a(&dir, "", "1.2.5");
        let third = second.replace("g.x:a:1.2.4", "g.x:a:1.2.5");
        assert_eq!(read(&dir, "build.gradle.kts"), third);
        assert_eq!(third.matches("g.x:a:").count(), 1, "no duplicate");
    }

    #[test]
    fn groovy_append_insert_replace() {
        let original = "plugins {\n    id 'java'\n}\n";
        let dir = project(&[("build.gradle", original)]);
        add_a(&dir, "", "1.2.4");
        let first = format!("{original}{GROOVY_BLOCK}");
        assert_eq!(read(&dir, "build.gradle"), first);

        add(dir.path(), Path::new(""), "api", "g.x:b", "2.0", "it's $x").unwrap();
        let second = first.replace("    }\n}\n", &format!("{GROOVY_ENTRY_B}    }}\n}}\n"));
        assert_eq!(read(&dir, "build.gradle"), second);

        add_a(&dir, "", "1.3.0");
        assert_eq!(
            read(&dir, "build.gradle"),
            second.replace("g.x:a:1.2.4", "g.x:a:1.3.0")
        );
    }

    #[test]
    fn keeps_newline_conventions() {
        let dir = project(&[
            ("a/build.gradle", "plugins { id 'java' }"),
            ("b/build.gradle", "plugins {\r\n    id 'java'\r\n}\r\n"),
        ]);
        add_a(&dir, "a", "1.2.4");
        let block = GROOVY_BLOCK.strip_suffix('\n').unwrap();
        let a = read(&dir, "a/build.gradle");
        assert_eq!(a, format!("plugins {{ id 'java' }}\n{block}"));
        add(dir.path(), Path::new("a"), "api", "g.x:b", "2.0", "it's $x").unwrap();
        let block_b = block.replace("    }\n}", &format!("{GROOVY_ENTRY_B}    }}\n}}"));
        assert_eq!(
            read(&dir, "a/build.gradle"),
            format!("plugins {{ id 'java' }}\n{block_b}")
        );

        add_a(&dir, "b", "1.2.4");
        add(dir.path(), Path::new("b"), "api", "g.x:b", "2.0", "it's $x").unwrap();
        let block_b = GROOVY_BLOCK.replace("    }\n}\n", &format!("{GROOVY_ENTRY_B}    }}\n}}\n"));
        assert_eq!(
            read(&dir, "b/build.gradle"),
            format!("plugins {{\n    id 'java'\n}}\n{block_b}").replace('\n', "\r\n")
        );
    }

    #[test]
    fn creates_missing_scripts_in_the_root_dsl() {
        let dir = project(&[("settings.gradle.kts", ""), ("lib/build.gradle", "")]);
        std::fs::create_dir(dir.path().join("app")).unwrap();
        add_a(&dir, "", "1.2.4");
        add_a(&dir, "app", "1.2.4");
        add_a(&dir, "lib", "1.2.4");
        let kotlin = KOTLIN_BLOCK.strip_prefix('\n').unwrap();
        assert_eq!(read(&dir, "build.gradle.kts"), kotlin);
        assert_eq!(read(&dir, "app/build.gradle.kts"), kotlin);
        assert_eq!(
            read(&dir, "lib/build.gradle"),
            GROOVY_BLOCK.strip_prefix('\n').unwrap()
        );
        assert!(!dir.path().join("lib/build.gradle.kts").exists());

        let groovy = project(&[("settings.gradle", "")]);
        add_a(&groovy, "", "1.2.4");
        assert_eq!(
            read(&groovy, "build.gradle"),
            GROOVY_BLOCK.strip_prefix('\n').unwrap()
        );
    }

    #[test]
    fn edited_block_is_not_editable() {
        let text = format!("{MARKER}\n// gone\n");
        let dir = project(&[("build.gradle", &text)]);
        let err = add(dir.path(), Path::new(""), "api", "g.x:b", "2.0", "r").unwrap_err();
        assert!(
            matches!(err, AdapterError::ManifestNotEditable(_)),
            "{err:?}"
        );
        assert_eq!(read(&dir, "build.gradle"), text);
    }
}
