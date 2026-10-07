//! Fixture harness: runs the `mendr` binary against every scenario under
//! `test-projects/` that contains an `expected.json`, and compares the stable
//! parts of the JSON report. See `test-projects/README.md` for the format.
//!
//! Needs network (registries, toolchains), so it is ignored by default:
//!
//! ```sh
//! nix develop -c cargo test --test fixtures -- --ignored
//! MENDR_FIXTURE=cargo/relock nix develop -c cargo test --test fixtures -- --ignored  # one scenario
//! ```
//!
//! `MENDR_FIXTURE_ALLOW_UNSANDBOXED=1` passes `--allow-unsandboxed` to
//! full-mode runs (for machines with a reachable container daemon socket).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Plan,
    Full,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    mode: Mode,
    #[serde(default)]
    args: Vec<String>,
    exit_code: i32,
    findings: Vec<ExpectedFinding>,
    /// After the run, each file (relative to the scenario) must contain
    /// every listed string. For checking `--write`.
    #[serde(default)]
    files: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedFinding {
    advisory: String,
    package: String,
    version: Option<String>,
    via: Option<String>,
    strategy: Option<String>,
    target: Option<ExpectedTarget>,
    outcome: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedTarget {
    package: String,
    to: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Shared download cache: `<target>/fixture-cache`.
fn cache_root() -> PathBuf {
    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    tmp.parent().unwrap_or(&tmp).join("fixture-cache")
}

/// Every directory below `test-projects/` containing `expected.json`.
fn discover(dir: &Path, out: &mut Vec<PathBuf>) {
    if dir.join("expected.json").is_file() {
        out.push(dir.to_path_buf());
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut dirs: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .filter(|p| {
            !matches!(
                p.file_name().and_then(|n| n.to_str()),
                Some("node_modules" | "target" | "osv")
            )
        })
        .collect();
    dirs.sort();
    for d in dirs {
        discover(&d, out);
    }
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if name == "node_modules" || name == "target" {
            continue;
        }
        let (src, dst) = (entry.path(), to.join(&name));
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&src, &dst);
        } else {
            std::fs::copy(&src, &dst).unwrap();
        }
    }
}

/// `"planned"`, `"fixed"`, `"skipped:<reason>"`, `"failed:<reason>"`.
fn outcome_label(outcome: &Value) -> String {
    let kind = outcome["kind"].as_str().unwrap_or("?");
    match outcome["reason"]["kind"].as_str() {
        Some(reason) => format!("{kind}:{reason}"),
        None => kind.to_string(),
    }
}

fn describe(f: &Value) -> String {
    format!(
        "{} {}@{} via {} -> {} {}",
        f["advisory"]["id"].as_str().unwrap_or("?"),
        f["package"].as_str().unwrap_or("?"),
        f["version"].as_str().unwrap_or("?"),
        f["via"]["name"].as_str().unwrap_or("?"),
        outcome_label(&f["outcome"]),
        f["change"],
    )
}

fn matches_key(e: &ExpectedFinding, f: &Value) -> bool {
    let adv = &f["advisory"];
    let id_ok = adv["id"] == e.advisory.as_str()
        || adv["aliases"]
            .as_array()
            .is_some_and(|a| a.iter().any(|x| x == e.advisory.as_str()));
    id_ok
        && f["package"] == e.package.as_str()
        && e.version
            .as_ref()
            .is_none_or(|v| f["version"] == v.as_str())
        && e.via
            .as_ref()
            .is_none_or(|v| f["via"]["name"] == v.as_str())
}

/// Compare the report against expectations; returns a list of problems.
fn compare(expected: &Expected, report: &Value, exit_code: Option<i32>) -> Vec<String> {
    let mut problems = Vec::new();
    if exit_code != Some(expected.exit_code) {
        problems.push(format!(
            "exit code: expected {}, got {exit_code:?}",
            expected.exit_code
        ));
    }
    let mut actual: Vec<&Value> = Vec::new();
    for p in report["projects"].as_array().into_iter().flatten() {
        if let Some(err) = p["error"].as_str() {
            problems.push(format!("project {} errored: {err}", p["path"]));
        }
        actual.extend(p["findings"].as_array().into_iter().flatten());
    }
    let mut used = vec![false; actual.len()];
    for e in &expected.findings {
        let hits: Vec<usize> = (0..actual.len())
            .filter(|&i| !used[i] && matches_key(e, actual[i]))
            .collect();
        let i = match hits.as_slice() {
            [i] => *i,
            [] => {
                problems.push(format!("missing finding {} in {}", e.advisory, e.package));
                continue;
            }
            _ => {
                problems.push(format!(
                    "ambiguous expectation {} in {}: {} findings match (add `version`/`via`)",
                    e.advisory,
                    e.package,
                    hits.len()
                ));
                continue;
            }
        };
        used[i] = true;
        let f = actual[i];
        let label = outcome_label(&f["outcome"]);
        if label != e.outcome {
            problems.push(format!(
                "{}: outcome expected `{}`, got `{label}` ({})",
                e.advisory,
                e.outcome,
                describe(f)
            ));
        }
        if let Some(s) = &e.strategy
            && f["strategy"] != s.as_str()
        {
            problems.push(format!(
                "{}: strategy expected `{s}`, got {}",
                e.advisory, f["strategy"]
            ));
        }
        if let Some(t) = &e.target
            && (f["change"]["package"] != t.package.as_str() || f["change"]["to"] != t.to.as_str())
        {
            problems.push(format!(
                "{}: target expected {}@{}, got change {}",
                e.advisory, t.package, t.to, f["change"]
            ));
        }
    }
    for (i, f) in actual.iter().enumerate() {
        if !used[i] {
            problems.push(format!("unexpected finding: {}", describe(f)));
        }
    }
    problems
}

fn run_scenario(dir: &Path) -> Result<(), String> {
    let expected: Expected = serde_json::from_str(
        &std::fs::read_to_string(dir.join("expected.json"))
            .map_err(|e| format!("reading expected.json: {e}"))?,
    )
    .map_err(|e| format!("invalid expected.json: {e}"))?;

    let work = tempfile::tempdir().unwrap();
    let project = work.path().join("project");
    copy_dir(dir, &project);
    let home = work.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let cache = cache_root();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mendr"));
    cmd.current_dir(&project)
        .args(["--format", "json", "--osv-snapshot"])
        .arg(project.join("osv"));
    match expected.mode {
        Mode::Plan => {
            cmd.arg("--plan-only");
        }
        // Escape hatch for machines where mendr's safety checks fail even in
        // the isolated environment (e.g. a reachable /var/run/docker.sock).
        Mode::Full
            if std::env::var_os("MENDR_FIXTURE_ALLOW_UNSANDBOXED").is_some_and(|v| v == "1") =>
        {
            cmd.arg("--allow-unsandboxed");
        }
        Mode::Full => {}
    }
    cmd.args(&expected.args);
    // Isolated environment: no secrets, fresh HOME, shared download caches.
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &home)
        .env("CARGO_HOME", cache.join("cargo"))
        .env("npm_config_cache", cache.join("npm"))
        .env("MENDR_CACHE_DIR", cache.join("mendr"));
    // Toolchain setup from the dev shell (compiler wrappers, SDK paths, TLS
    // trust roots), not secrets. `NIX_CONFIG` can hold access tokens.
    for (var, value) in std::env::vars_os() {
        let Some(name) = var.to_str() else { continue };
        let toolchain = (name.starts_with("NIX_") && name != "NIX_CONFIG")
            || matches!(
                name,
                "SSL_CERT_FILE"
                    | "SDKROOT"
                    | "DEVELOPER_DIR"
                    | "MACOSX_DEPLOYMENT_TARGET"
                    | "CC"
                    | "CXX"
                    | "AR"
                    | "AS"
                    | "LD"
                    | "NM"
                    | "RANLIB"
                    | "STRIP"
            );
        if toolchain {
            cmd.env(var, value);
        }
    }

    let output = cmd.output().map_err(|e| format!("running mendr: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let report: Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("report is not JSON ({e})\nstdout:\n{stdout}\nstderr:\n{stderr}"))?;
    let mut problems = compare(&expected, &report, output.status.code());
    for (file, needles) in &expected.files {
        let text = std::fs::read_to_string(project.join(file)).unwrap_or_default();
        for needle in needles.iter().filter(|n| !text.contains(n.as_str())) {
            problems.push(format!("{file} does not contain {needle:?}"));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{}\n--- mendr stderr ---\n{stderr}",
            problems.join("\n")
        ))
    }
}

#[test]
#[ignore = "needs network and toolchains; run with --ignored"]
fn fixtures() {
    let root = repo_root().join("test-projects");
    let mut scenarios = Vec::new();
    discover(&root, &mut scenarios);
    if let Ok(filter) = std::env::var("MENDR_FIXTURE") {
        scenarios.retain(|s| {
            s.strip_prefix(&root)
                .is_ok_and(|rel| rel.starts_with(&filter))
        });
    }
    if scenarios.is_empty() {
        println!("no fixture scenarios found under {}", root.display());
        return;
    }
    let mut failures = Vec::new();
    for dir in &scenarios {
        let name = dir.strip_prefix(&root).unwrap().display().to_string();
        match run_scenario(dir) {
            Ok(()) => println!("ok   {name}"),
            Err(e) => {
                println!("FAIL {name}");
                failures.push(format!("=== {name} ===\n{e}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} scenarios failed:\n\n{}",
        failures.len(),
        scenarios.len(),
        failures.join("\n\n")
    );
}

/// The comparison logic itself runs without network.
#[test]
fn compare_detects_mismatches() {
    let report = serde_json::json!({
        "projects": [{
            "path": ".", "error": null,
            "findings": [{
                "advisory": {"id": "GHSA-1", "aliases": ["CVE-1"]},
                "package": "p", "version": "1.0.0", "via": {"name": "a", "version": "1.0.0"},
                "strategy": "relock",
                "change": {"kind": "relock", "package": "p", "from": "1.0.0", "to": "1.0.1"},
                "outcome": {"kind": "planned", "strategy": "relock", "change": {}}
            }, {
                "advisory": {"id": "GHSA-2", "aliases": []},
                "package": "q", "version": "2.0.0", "via": {"name": "q", "version": "2.0.0"},
                "strategy": null, "change": null,
                "outcome": {"kind": "skipped", "reason": {"kind": "no_patched_version", "package": "q"}}
            }]
        }]
    });
    let good: Expected = serde_json::from_value(serde_json::json!({
        "mode": "plan", "exit_code": 1,
        "findings": [
            {"advisory": "CVE-1", "package": "p", "via": "a", "strategy": "relock",
             "target": {"package": "p", "to": "1.0.1"}, "outcome": "planned"},
            {"advisory": "GHSA-2", "package": "q", "outcome": "skipped:no_patched_version"}
        ]
    }))
    .unwrap();
    assert_eq!(compare(&good, &report, Some(1)), Vec::<String>::new());

    let bad: Expected = serde_json::from_value(serde_json::json!({
        "mode": "plan", "exit_code": 0,
        "findings": [
            {"advisory": "GHSA-1", "package": "p", "strategy": "direct_bump",
             "target": {"package": "p", "to": "1.0.2"}, "outcome": "fixed"}
        ]
    }))
    .unwrap();
    let problems = compare(&bad, &report, Some(1));
    assert_eq!(problems.len(), 5, "{problems:#?}"); // exit, outcome, strategy, target, unexpected GHSA-2
}
