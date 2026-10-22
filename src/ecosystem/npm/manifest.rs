//! `package.json` / `package-lock.json` edits that keep the file's
//! formatting: key order (serde_json `preserve_order`), indentation, line
//! endings and the trailing newline.

use std::path::Path;

use serde::Serialize;
use serde_json::Value;

use crate::ecosystem::AdapterError;
use crate::ecosystem::node_semver::{Range, Ver};

/// Dependency sections of a `package.json`, in npm's order.
pub const SECTIONS: [&str; 4] = [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];

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

    pub fn write(&self, path: &Path) -> Result<(), AdapterError> {
        Ok(std::fs::write(path, self.render())?)
    }
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
/// `None` for specs that are not semver ranges (tags, URLs, git, files).
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

/// Add the override `"<package>@<from> - <to>": "<to>"` to the root
/// manifest. npm 10 only applies a keyed override when the key range
/// matches both the dependency's declared spec and the replacement version,
/// hence the hyphen range (`"pkg@from"` alone is silently ignored).
pub fn add_override(doc: &mut Value, package: &str, from: &str, to: &str) -> Result<(), String> {
    let obj = doc.as_object_mut().ok_or("package.json is not an object")?;
    let overrides = obj
        .entry("overrides")
        .or_insert_with(|| Value::Object(Default::default()));
    let map = overrides
        .as_object_mut()
        .ok_or("package.json `overrides` is not an object")?;
    map.insert(
        format!("{package}@{from} - {to}"),
        Value::String(to.to_string()),
    );
    Ok(())
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
            "https://x/y.tgz",
            "npm:x",
        ] {
            assert_eq!(bump_spec(bad, "1.0.0"), None, "{bad}");
        }
    }

    #[test]
    fn json_round_trip_keeps_formatting() {
        let text = "{\r\n    \"name\": \"x\",\r\n    \"b\": 1,\r\n    \"a\": {}\r\n}";
        let mut f = JsonFile::parse(text).unwrap();
        assert_eq!(f.render(), text);
        add_override(&mut f.value, "p", "0.1.7", "0.1.13").unwrap();
        assert_eq!(
            f.render(),
            "{\r\n    \"name\": \"x\",\r\n    \"b\": 1,\r\n    \"a\": {},\r\n    \"overrides\": {\r\n        \"p@0.1.7 - 0.1.13\": \"0.1.13\"\r\n    }\r\n}"
        );
        let tabs = "{\n\t\"z\": [\n\t\t1\n\t],\n\t\"y\": \"\u{e9}/\"\n}\n";
        assert_eq!(JsonFile::parse(tabs).unwrap().render(), tabs);
        let mut bad = serde_json::json!({"overrides": []});
        assert!(add_override(&mut bad, "p", "1", "2").is_err());
    }
}
