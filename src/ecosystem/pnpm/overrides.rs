//! Line-level edits of the top-level `overrides` mapping: adding entries to
//! `pnpm-workspace.yaml`, removing temporary ones from `pnpm-lock.yaml`.
//! Everything else is kept byte for byte (comments, quoting, key order, line
//! endings), which a YAML serializer would not do.
//!
//! Only a block mapping (`overrides:` followed by indented `key: value`
//! lines) or an empty flow mapping (`overrides: {}`) is edited. In a file
//! with several YAML documents (pnpm 12 can write an "env" document before
//! the lockfile) only the last one is looked at.

/// Add (or replace) the entry `key: value` in the `overrides` mapping of
/// `text`, creating the mapping if needed. Keys and values are written
/// single-quoted.
pub fn add(text: &str, key: &str, value: &str) -> Result<String, String> {
    let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut lines: Vec<String> = text.split_inclusive('\n').map(str::to_string).collect();
    let entry = |indent: &str| format!("{indent}{}: {}{eol}", quote(key), quote(value));
    let start = last_document(&lines);
    let (header, kind) = match find_header(&lines, start) {
        Some(found) => found,
        None => {
            end_line(&mut lines, eol);
            lines.push(format!("overrides:{eol}"));
            lines.push(entry("  "));
            return Ok(lines.concat());
        }
    };
    match kind {
        Header::Block => {
            let s = section(&lines, header);
            let indent = s.indent.unwrap_or_else(|| "  ".to_string());
            match s
                .entries
                .iter()
                .find(|&&e| key_of(&lines[e]).as_deref() == Some(key))
            {
                Some(&existing) => lines[existing] = entry(&indent),
                None => {
                    if s.end == lines.len() {
                        end_line(&mut lines, eol);
                    }
                    lines.insert(s.end, entry(&indent));
                }
            }
        }
        Header::EmptyFlow => {
            lines[header] = format!("overrides:{eol}");
            lines.insert(header + 1, entry("  "));
        }
        Header::Other => return Err("`overrides` is not a block mapping".to_string()),
    }
    Ok(lines.concat())
}

/// Remove the entries with these keys from the `overrides` mapping of
/// `text`, and the mapping itself (with the blank lines after it) if
/// nothing else is left in it.
pub fn remove(text: &str, keys: &[String]) -> String {
    let mut lines: Vec<&str> = text.split_inclusive('\n').collect();
    let start = last_document(&lines);
    let Some((header, Header::Block)) = find_header(&lines, start) else {
        return text.to_string();
    };
    let s = section(&lines, header);
    let drop: Vec<usize> = s
        .entries
        .iter()
        .copied()
        .filter(|&e| key_of(lines[e]).is_some_and(|k| keys.contains(&k)))
        .collect();
    let others = (header + 1..s.end).any(|i| !drop.contains(&i) && !lines[i].trim().is_empty());
    if !drop.is_empty() && !others {
        let mut end = s.end;
        while end < lines.len() && lines[end].trim().is_empty() {
            end += 1;
        }
        lines.drain(header..end);
    } else {
        for &i in drop.iter().rev() {
            lines.remove(i);
        }
    }
    lines.concat()
}

#[derive(Debug, PartialEq)]
enum Header {
    /// `overrides:` (entries on the following, indented lines).
    Block,
    /// `overrides: {}`.
    EmptyFlow,
    /// Any other inline value.
    Other,
}

/// The lines of one block mapping section.
struct Section {
    /// Lines of the direct entries.
    entries: Vec<usize>,
    /// Index after the last non-blank line of the section.
    end: usize,
    /// Indentation of the entries, if there are any.
    indent: Option<String>,
}

/// Index of the first line of the last YAML document.
fn last_document<S: AsRef<str>>(lines: &[S]) -> usize {
    lines
        .iter()
        .rposition(|l| {
            let l = l.as_ref().trim_end();
            l == "---" || l.starts_with("--- ")
        })
        .map_or(0, |i| i + 1)
}

/// The top-level `overrides:` line at or after `from`.
fn find_header<S: AsRef<str>>(lines: &[S], from: usize) -> Option<(usize, Header)> {
    (from..lines.len()).find_map(|i| {
        let rest = lines[i].as_ref().trim_end().strip_prefix("overrides:")?;
        let value = rest.split(" #").next().unwrap_or_default().trim();
        let kind = match value {
            "" => Header::Block,
            "{}" => Header::EmptyFlow,
            _ => Header::Other,
        };
        Some((i, kind))
    })
}

fn indentation(line: &str) -> &str {
    &line[..line.len() - line.trim_start().len()]
}

/// The indented lines below `header`.
fn section<S: AsRef<str>>(lines: &[S], header: usize) -> Section {
    let mut end = header + 1;
    let mut indent: Option<String> = None;
    let mut entries = Vec::new();
    for (i, line) in lines.iter().enumerate().skip(header + 1) {
        let line = line.as_ref();
        let content = line.trim();
        if content.is_empty() {
            continue;
        }
        let ws = indentation(line);
        if ws.is_empty() {
            break;
        }
        end = i + 1;
        if content.starts_with('#') {
            continue;
        }
        let child = indent.get_or_insert_with(|| ws.to_string());
        if ws == child.as_str() {
            entries.push(i);
        }
    }
    Section {
        entries,
        end,
        indent,
    }
}

/// Make sure the last line ends with a line break.
fn end_line(lines: &mut [String], eol: &str) {
    if let Some(last) = lines.last_mut()
        && !last.ends_with('\n')
    {
        last.push_str(eol);
    }
}

fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// The (unquoted) key of a `key: value` line.
fn key_of(line: &str) -> Option<String> {
    let s = line.trim();
    if let Some(rest) = s.strip_prefix('\'') {
        let mut key = String::new();
        let mut chars = rest.char_indices();
        while let Some((i, c)) = chars.next() {
            if c != '\'' {
                key.push(c);
            } else if rest[i + 1..].starts_with('\'') {
                key.push('\'');
                chars.next();
            } else {
                return rest[i + 1..].trim_start().starts_with(':').then_some(key);
            }
        }
        None
    } else if let Some(rest) = s.strip_prefix('"') {
        let mut key = String::new();
        let mut chars = rest.char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '\\' => key.push(chars.next()?.1),
                '"' => return rest[i + 1..].trim_start().starts_with(':').then_some(key),
                c => key.push(c),
            }
        }
        None
    } else {
        let end = s
            .find(": ")
            .or_else(|| s.ends_with(':').then(|| s.len() - 1))?;
        Some(s[..end].trim_end().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn adds_to_missing_empty_and_existing_mappings() {
        assert_eq!(
            add("", "a>b", "1.0.0").unwrap(),
            "overrides:\n  'a>b': '1.0.0'\n"
        );
        assert_eq!(
            add("packages:\n  - 'pkgs/*'", "b", "2").unwrap(),
            "packages:\n  - 'pkgs/*'\noverrides:\n  'b': '2'\n"
        );
        assert_eq!(
            add("overrides: {}  # none yet\nx: 1\n", "b", "2").unwrap(),
            "overrides:\n  'b': '2'\nx: 1\n"
        );
        let text = "# settings\r\noverrides:   # pinned\r\n    foo: ^1.0.0\r\n    # keep\r\n    'bar@1>baz': 2.0.0\r\n\r\ncatalog:\r\n  x: 1\r\n";
        assert_eq!(
            add(text, "@s/p@1.0.0>q", "1.2.6").unwrap(),
            text.replace(
                "2.0.0\r\n\r\n",
                "2.0.0\r\n    '@s/p@1.0.0>q': '1.2.6'\r\n\r\n"
            )
        );
        // An existing entry for the key is replaced in place.
        assert_eq!(
            add(text, "bar@1>baz", "2.0.1").unwrap(),
            text.replace("'bar@1>baz': 2.0.0", "'bar@1>baz': '2.0.1'")
        );
        // Section at the end of a file without a final newline.
        assert_eq!(
            add("overrides:\n  a: '1'", "b", "2").unwrap(),
            "overrides:\n  a: '1'\n  'b': '2'\n"
        );
        assert_eq!(
            add("overrides:\nnext: 1\n", "b", "2").unwrap(),
            "overrides:\n  'b': '2'\nnext: 1\n"
        );
        assert!(add("overrides: {a: '1'}\n", "b", "2").is_err());
        // Not fooled by similar keys or nested ones.
        assert_eq!(
            add("overridesX: 1\nx:\n  overrides: 1\n", "b", "2").unwrap(),
            "overridesX: 1\nx:\n  overrides: 1\noverrides:\n  'b': '2'\n"
        );
    }

    #[test]
    fn removes_entries_and_empty_mappings() {
        let lock = "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n\n\
                    overrides:\n  mkdirp@0.5.5>minimist: 1.2.6\n  '@s/a@1.0.0>b': 2.0.0\n\n\
                    importers:\n\n  .: {}\n";
        assert_eq!(
            remove(lock, &keys(&["mkdirp@0.5.5>minimist", "@s/a@1.0.0>b"])),
            "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n\nimporters:\n\n  .: {}\n"
        );
        assert_eq!(
            remove(lock, &keys(&["@s/a@1.0.0>b"])),
            lock.replace("  '@s/a@1.0.0>b': 2.0.0\n", "")
        );
        assert_eq!(remove(lock, &keys(&["other"])), lock);
        assert_eq!(remove("importers: {}\n", &keys(&["x"])), "importers: {}\n");

        // Only the last document of a multi-document lockfile.
        let multi = "---\nlockfileVersion: '9.0'\n\nimporters: {}\n\n---\nlockfileVersion: '9.0'\n\n\
                     overrides:\n  a>b: 1.0.1\n\nimporters: {}\n";
        assert_eq!(
            remove(multi, &keys(&["a>b"])),
            "---\nlockfileVersion: '9.0'\n\nimporters: {}\n\n---\nlockfileVersion: '9.0'\n\nimporters: {}\n"
        );
    }

    #[test]
    fn reads_quoted_and_plain_keys() {
        assert_eq!(key_of("  a@1>b: 1.0.0").as_deref(), Some("a@1>b"));
        assert_eq!(key_of("  'it''s': x").as_deref(), Some("it's"));
        assert_eq!(key_of("  \"q\\\"k\" : x").as_deref(), Some("q\"k"));
        assert_eq!(key_of("  nested:").as_deref(), Some("nested"));
        assert_eq!(key_of("  - item"), None);
        assert_eq!(key_of("  'open"), None);
    }
}
