//! `package.json` reads and edits that keep the file's formatting: key order
//! (serde_json `preserve_order`), indentation, line endings and the trailing
//! newline.

use std::path::Path;

use serde::Serialize;
use serde_json::Value;

use crate::ecosystem::AdapterError;
use crate::ecosystem::node_semver::{Range, Ver};

/// A parsed JSON file plus the formatting needed to write it back.
pub struct JsonFile {
    pub value: Value,
    indent: String,
    crlf: bool,
    trailing_newline: bool,
}

impl JsonFile {
    pub fn parse(text: &str) -> Result<JsonFile, serde_json::Error> {
        // Indentation of the first indented line ("  " if none).
        let indent = text
            .lines()
            .skip(1)
            .map(|l| &l[..l.len() - l.trim_start().len()])
            .find(|ws| !ws.is_empty())
            .unwrap_or("  ")
            .to_string();
        Ok(JsonFile {
            value: serde_json::from_str(text)?,
            indent,
            crlf: text.contains("\r\n"),
            trailing_newline: text.ends_with('\n'),
        })
    }

    pub fn read(path: &Path) -> Result<JsonFile, AdapterError> {
        let text = std::fs::read_to_string(path)?;
        JsonFile::parse(&text).map_err(|e| AdapterError::Parse {
            what: path.display().to_string(),
            message: e.to_string(),
        })
    }

    pub fn render(&self) -> String {
        let mut buf = Vec::new();
        let fmt = serde_json::ser::PrettyFormatter::with_indent(self.indent.as_bytes());
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, fmt);
        self.value
            .serialize(&mut ser)
            .expect("serializing a JSON value cannot fail");
        let mut text = String::from_utf8(buf).expect("serde_json writes UTF-8");
        if self.trailing_newline {
            text.push('\n');
        }
        if self.crlf {
            text = text.replace('\n', "\r\n");
        }
        text
    }

    /// The spec declared as `section.name`, if it is a string.
    pub fn spec(&self, section: &str, name: &str) -> Option<&str> {
        self.value.get(section)?.get(name)?.as_str()
    }

    /// Replace the spec declared as `section.name` (which must exist).
    pub fn set_spec(&mut self, section: &str, name: &str, spec: &str) {
        if let Some(slot) = self.value.get_mut(section).and_then(|s| s.get_mut(name)) {
            *slot = Value::String(spec.to_string());
        }
    }
}

/// `name` and `version` of the package in `path`, if declared.
pub fn identity(path: &Path) -> (Option<String>, Option<String>) {
    let value = std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    let field = |key: &str| {
        value
            .as_ref()
            .and_then(|v| v.get(key))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    (field("name"), field("version"))
}

/// How a declared spec changes for a direct bump to `to`.
#[derive(Debug, PartialEq)]
pub enum SpecBump {
    /// Write this spec instead.
    Rewrite(String),
    /// The spec already allows `to`; keep it and re-resolve the lockfile.
    Keep,
}

/// New spec for a dependency declared as `spec` that must resolve to `to`.
/// Keeps the user's style: `^1.2.3` -> `^1.4.0`, `~1.2.3` -> `~1.4.0`,
/// `1.2.3` -> `1.4.0`, `>=1.2.3` -> `>=1.4.0`, `npm:x@^1` -> `npm:x@^1.4.0`.
/// Other ranges are kept if they allow `to`, else replaced by `^to`.
/// `None` for specs that are not semver ranges (tags, URLs, git, files,
/// `workspace:`, `catalog:`).
pub fn bump_spec(spec: &str, to: &str) -> Option<SpecBump> {
    if let Some(rest) = spec.strip_prefix("npm:") {
        // `npm:name@range`; scoped names start with `@`.
        let at = rest.get(1..)?.find('@')? + 1;
        let (name, range) = (&rest[..at], &rest[at + 1..]);
        return Some(match bump_spec(range, to)? {
            SpecBump::Rewrite(r) => SpecBump::Rewrite(format!("npm:{name}@{r}")),
            SpecBump::Keep => SpecBump::Keep,
        });
    }
    let trimmed = spec.trim();
    for op in ["^", "~", ">=", "=", ""] {
        if let Some(v) = trimmed.strip_prefix(op)
            && Ver::parse(v).is_some()
            && !v.starts_with(['=', ' '])
        {
            return Some(SpecBump::Rewrite(format!("{op}{to}")));
        }
    }
    let range = Range::parse(trimmed)?;
    Some(match Ver::parse(to) {
        Some(v) if range.satisfies(&v) => SpecBump::Keep,
        _ => SpecBump::Rewrite(format!("^{to}")),
    })
}

/// The exact spec that pins a dependency declared as `spec` to `to`
/// (`^1.2.5` -> `1.2.6`, `npm:x@^1` -> `npm:x@1.2.6`). `None` for specs
/// that are not semver ranges.
pub fn pin_spec(spec: &str, to: &str) -> Option<String> {
    match super::alias(spec) {
        Some((name, range)) => {
            Range::parse(range)?;
            Some(format!("npm:{name}@{to}"))
        }
        None => {
            Range::parse(spec.trim())?;
            Some(to.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite(spec: &str, to: &str) -> Option<String> {
        match bump_spec(spec, to)? {
            SpecBump::Rewrite(s) => Some(s),
            SpecBump::Keep => Some("<keep>".into()),
        }
    }

    #[test]
    fn bumps_keep_range_style() {
        assert_eq!(rewrite("^1.4.1", "1.4.2").as_deref(), Some("^1.4.2"));
        assert_eq!(rewrite("~0.5.1", "0.5.6").as_deref(), Some("~0.5.6"));
        assert_eq!(rewrite("1.4.1", "1.4.2").as_deref(), Some("1.4.2"));
        assert_eq!(rewrite("=1.4.1", "1.4.2").as_deref(), Some("=1.4.2"));
        assert_eq!(rewrite(">=1.4.1", "1.4.2").as_deref(), Some(">=1.4.2"));
        assert_eq!(rewrite("v1.4.1", "1.4.2").as_deref(), Some("1.4.2"));
        assert_eq!(
            rewrite("npm:@s/real@^1.0.0", "1.2.0").as_deref(),
            Some("npm:@s/real@^1.2.0")
        );
        assert_eq!(rewrite("1.x", "1.4.2").as_deref(), Some("<keep>"));
        assert_eq!(rewrite("*", "1.4.2").as_deref(), Some("<keep>"));
        assert_eq!(rewrite("1.x", "2.0.1").as_deref(), Some("^2.0.1"));
        assert_eq!(rewrite(">=1 <1.3", "1.4.2").as_deref(), Some("^1.4.2"));
        for bad in [
            "latest",
            "github:a/b",
            "file:../x",
            "link:../x",
            "https://x/y.tgz",
            "npm:x",
            "workspace:*",
            "workspace:^1.0.0",
            "catalog:",
            "catalog:react18",
        ] {
            assert_eq!(bump_spec(bad, "1.0.0"), None, "{bad}");
        }
    }

    #[test]
    fn pins_are_exact() {
        assert_eq!(pin_spec("^1.2.5", "1.2.6").as_deref(), Some("1.2.6"));
        assert_eq!(pin_spec("1.x", "1.2.6").as_deref(), Some("1.2.6"));
        assert_eq!(
            pin_spec("npm:@s/x@~1.0.0", "1.0.3").as_deref(),
            Some("npm:@s/x@1.0.3")
        );
        assert_eq!(pin_spec("npm:x", "1.0.0").as_deref(), Some("npm:x@1.0.0"));
        for bad in ["latest", "catalog:", "workspace:*", "github:a/b"] {
            assert_eq!(pin_spec(bad, "1.0.0"), None, "{bad}");
        }
    }

    #[test]
    fn json_round_trip_keeps_formatting() {
        let text = "{\r\n    \"name\": \"x\",\r\n    \"dependencies\": {\r\n        \"a\": \"^1.0.0\"\r\n    }\r\n}";
        let mut f = JsonFile::parse(text).unwrap();
        assert_eq!(f.render(), text);
        assert_eq!(f.spec("dependencies", "a"), Some("^1.0.0"));
        assert_eq!(f.spec("devDependencies", "a"), None);
        f.set_spec("dependencies", "a", "^1.2.0");
        f.set_spec("dependencies", "missing", "1");
        assert_eq!(f.render(), text.replace("^1.0.0", "^1.2.0"));
        let tabs = "{\n\t\"z\": [\n\t\t1\n\t],\n\t\"y\": \"\u{e9}/\"\n}\n";
        assert_eq!(JsonFile::parse(tabs).unwrap().render(), tabs);
    }
}
