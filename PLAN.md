# mendr — Plan

mendr scans projects for known vulnerabilities (via [OSV](https://osv.dev)) and fixes them the way a
developer would: take the smallest change that works, and when the vulnerable package is a transitive
dependency, update the direct dependency that pulls it in. Every fix is verified with build and test,
and every attempt ends in a structured result with a reason.

## Principles

- **Simple.** Plain functions, run one after another, blocking I/O. No async runtime, no queues, no
  plugin system.
- **One binary crate** with modules. Split into a workspace only if it becomes painful.
- **One trait per ecosystem.** Each ecosystem is one module implementing `Ecosystem`. Planning,
  rules and reporting never know which ecosystem they run on.
- **Never touch the user's checkout.** All changes happen in a temporary copy.
- **Safe by default.** Refuse to run builds when secrets are reachable, unless explicitly allowed.
- **Native tools are the source of truth.** After every change, resolve the graph again and rescan.

## How a run works

1. Load `mendr.toml`, apply CLI flag overrides.
2. Run safety checks.
3. For each project: detect the ecosystem, resolve the dependency graph, look up vulnerabilities in OSV.
4. Plan: for each vulnerable package, pick the cheapest strategy the rules allow:
   `relock` → `direct bump` → `override` → give up with a reason.
5. Unless `--plan-only`: copy the project, run a baseline build/test, then apply each change, build,
   test, and keep or revert it.
6. Print the report (JSON or Markdown).

## Module layout

```
src/
  main.rs            CLI (clap)
  config.rs          mendr.toml + flag overrides
  model.rs           Version, DepGraph, Change, Outcome, reasons
  osv.rs             OSV client, cache, snapshot loading, range matching, alias dedupe
  rules.rs           release age, major bumps, severity, ignore list (plain fns)
  safety.rs          secret and escape-route checks
  plan.rs            fix planning (ecosystem-agnostic)
  verify.rs          temp copy, baseline, apply, build, test, revert
  report.rs          JSON + Markdown output
  cache.rs           on-disk cache (OSV records, adapter registry responses)
  http.rs            blocking HTTP helpers (ureq)
  ecosystem/
    mod.rs           Ecosystem trait + detection
    cargo.rs
    npm.rs
    gradle.rs
    fake.rs          in-memory ecosystem for unit tests
tests/
  fixtures.rs        runs the binary against every test project
test-projects/       see below
```

## Config (draft)

```toml
[policy]
strategies = ["relock", "direct-bump", "override"]  # order = preference
allow-major = false
min-release-age = "7d"       # default 7d; "0" disables
min-severity = "medium"      # default "low" (everything)
target = "minimal"           # or "latest-compatible"

[safety]
allow-unsandboxed = false
deny-paths = ["~/.aws"]

[[project]]
path = "apps/web"            # ecosystem auto-detected
test = "npm test"

[[project]]
path = "services/api"
ecosystem = "gradle"
build = "./gradlew assemble"
test = "./gradlew test"
timeout = "20m"

[[ignore]]
id = "GHSA-xxxx-yyyy"
reason = "not reachable"
expires = 2026-12-31
```

CLI overrides: `--allow-major`, `--allow-unsandboxed`, `--min-release-age <dur>`, `--plan-only`,
`--format json|markdown`, `--osv-snapshot <dir>`, `--output <file>`, `--write`, `--config <path>`.
Without a config file mendr uses the defaults and one auto-detected project in the current
directory. Full reference: the doc comment at the top of `src/config.rs`.

Exit codes: 0 = no unresolved findings, 1 = unresolved findings remain, 2 = error. A finding is
resolved when it is `fixed`, `planned` (a fix exists; `--plan-only`), `skipped:ignored` or
`skipped:below_min_severity`. By default mendr never modifies the project; `--write` copies the
verified manifest/lockfile changes back.

## Results

- `Planned { strategy, change }`: a fix was planned but not verified (`--plan-only`)
- `Fixed { strategy, change }`
- `Skipped { reason }`: `NoPatchedVersion`, `NoParentVersionFixes`, `MajorBumpBlocked`,
  `StrategyUnsupported`, `ReleaseTooRecent`, `Ignored`, `BelowMinSeverity`
- `Failed { reason }`: `BaselineFailed`, `ResolutionConflict`, `ReleaseAgePolicyViolated`,
  `InstallFailed`, `BuildFailed`, `TestFailed`, `Timeout`, `NewVulnerabilityIntroduced`,
  `StillVulnerable`, `ManifestNotEditable`, `Error`

Reasons carry details (exit code, log tail, offending package/version, ...). JSON uses snake_case
tags: `{"kind": "skipped", "reason": {"kind": "no_parent_version_fixes", ...}}`. Changes:
`Relock { package, from, to }`, `DirectBump { package, from, to, bump }`,
`Override { package, from, to }`. The report shape is documented in `src/report.rs`.

## Planning decisions

- A finding is one advisory × one vulnerable package version × one **via** (the first registry
  package on the path = the dependency a local manifest declares). The same vulnerable package
  reached through two direct dependencies gives two findings, each with its own fix.
- Fix candidates: newer, non-yanked, non-prerelease versions not affected by *any* advisory for
  the package. Strategy order comes from `policy.strategies`; first success wins.
- Direct bump search walks newer versions of the via package ascending and follows only the
  dependencies that lead to the vulnerable package in the current graph (memoized, depth ≤ 8,
  ≤ 200 candidates), resolving each to its highest matching version. Verification's rescan
  catches anything this approximation misses.
- When nothing works the reason is: first policy block (`major_bump_blocked`,
  `release_too_recent`), else `no_parent_version_fixes`, else `strategy_unsupported`. So a Cargo
  "no-fix" scenario reports `no_parent_version_fixes` (override unsupported is implied).
- Changes are merged per `(package, from)`: highest `to` wins, a bump absorbs a relock.
- `min-release-age`: a version without a known publish date counts as too new (fail closed);
  adapters must report publish dates.
- Unknown severity always passes `min-severity`.
- OSV: withdrawn and RustSec informational (`unmaintained`, `unsound`, ...) records are dropped;
  aliases are merged; the primary id is the smallest non-CVE id. Severity comes from the CVSS v3
  vector, else `database_specific.severity`.
- Cargo graph: nodes/edges from `Cargo.lock`, members + their requirements from
  `cargo metadata --no-deps` (no downloads, no build scripts), registry edge requirements from the
  sparse index. Only crates.io packages are `registry` nodes; path/git/alternative-registry packages
  are local, and edges *from* git, alternative-registry or out-of-workspace path packages get
  requirement `*` (their manifests are not read).
- Cargo direct bump: every workspace declaration (`[dependencies]`, dev, build, `[target.*]`,
  renamed) whose requirement allows `from` is rewritten; `workspace = true` ones in the root's
  `[workspace.dependencies]`. The new requirement is `to`, keeping an explicit `=`/`~`/`^`. The
  lockfile is updated with `cargo update --workspace` (manifests temporarily pinned to `=to`).
- Cargo ignores `ApplyOptions::release_cutoff` (stable Cargo cannot resolve by publish time), so
  verification's release-age check on the lockfile diff is the only guard for new transitive
  versions a Cargo change pulls in.
- Cargo publish dates come from the sparse index `pubtime` (present on every version as of
  2026-10); the crates.io API (1 req/s) is only a fallback. Registry responses are cached for 1h
  (`cargo-index`, `crates-io` cache namespaces).

## Test projects

Small real projects with known vulnerable dependencies. One directory per **scenario**, not per
ecosystem, so each strategy and each failure reason is covered:

```
test-projects/
  cargo/
    relock/                  vulnerable transitive dep, fixed version is in range
    direct-bump/             fix requires bumping the direct dep
    no-fix/                  no parent version pulls in a fix (Cargo has no real override)
    build-break/             the only fix is a bump that breaks the code
    baseline-broken/         project fails before any change
  npm/
    relock/
    direct-bump/
    override/
    build-break/
  gradle/
    ...                      added with the Gradle milestone
```

Each scenario contains the project (with its **committed lockfile**), an `osv/` directory with
the OSV records it needs (per-scenario snapshot: deterministic, and no shared files between
scenarios), an optional `mendr.toml`, and an `expected.json`. `tests/fixtures.rs` discovers every
directory with an `expected.json`, copies it to a temp dir, runs `mendr --format json
--osv-snapshot <copy>/osv` in an isolated environment (cleared env, fresh `HOME`, shared download
caches under `target/fixture-cache`), and compares only stable fields (advisory ID, package,
strategy, target version, outcome kind). Log tails and timestamps are ignored. Format and
environment details: `test-projects/README.md`. Run with
`nix develop -c cargo test --test fixtures -- --ignored`.

Constraints to keep in mind:

- **Isolation from the repo.** Every Cargo fixture declares an empty `[workspace]` table so Cargo
  does not treat it as part of mendr. npm fixtures must not sit under a root `package.json` with
  workspaces.
- **Determinism.** New advisories are published all the time and would change results. Fixture runs
  use each scenario's frozen `osv/` snapshot. A separate scheduled CI job runs against live OSV to catch drift.
- **Security alerts noise.** GitHub/Dependabot will flag the intentionally vulnerable lockfiles.
  Exclude `test-projects/` from Dependabot and dismiss alerts for it.
- **Fixtures run untrusted build scripts.** CI runs them in a container with no secrets, so mendr's
  own safety checks pass without `--allow-unsandboxed`. This doubles as a test of the safety checks.
- **Pick vulnerable packages carefully.** Old, well-known advisories with stable fixes, no install
  scripts, exact versions pinned in the lockfile. Verify each scenario actually reproduces.

## Milestones

### M0 — Setup
- [x] `cargo init`, add clap, serde, serde_json, toml, toml_edit, semver, ureq, thiserror, anyhow
      (+ jiff for timestamps/dates, tempfile)
- [x] CI: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`
- [x] Dependabot exclusion for `test-projects/`

### M1 — Core (no real ecosystem yet)
- [x] `model.rs`: Version, VersionReq, DepGraph, Change, Outcome, reasons (serde-serializable)
- [x] `config.rs`: parse `mendr.toml`, apply flag overrides, validate
- [x] `osv.rs`: query OSV API, load snapshot dir, local cache
- [x] `osv.rs`: range matching (`introduced` / `fixed` / `last_affected`), alias dedupe, skip withdrawn
- [x] `rules.rs`: release age, major bump, severity threshold, ignore list with expiry
- [x] `ecosystem/mod.rs`: `Ecosystem` trait
- [x] `ecosystem/fake.rs`: in-memory graph + registry
- [x] `plan.rs`: relock / direct bump / override decision, recursive parent search, merge per direct dep
- [x] Unit tests for planner and rules using the fake ecosystem
- [x] `report.rs`: JSON output
- [x] `tests/fixtures.rs` harness + `test-projects/README.md` (`expected.json` format)
- [x] `safety.rs` / `verify.rs` stubs with documented signatures (filled in by M3)

### M2 — Cargo adapter
- [x] Detect (`Cargo.toml` + `Cargo.lock`)
- [x] Graph via `Cargo.lock` + `cargo metadata --no-deps --format-version 1` + sparse index (no downloads)
- [x] Registry: sparse index (versions, deps, yanked, `pubtime`) + crates.io API fallback for publish dates, cached
- [x] Version semantics via `semver` (0.x-aware bump kind)
- [x] Apply relock: `cargo update -p name@from --precise to`
- [x] Apply direct bump with `toml_edit`, including `[workspace.dependencies]` inheritance
- [x] `supports(Override) == false` (planner then reports `no_parent_version_fixes`, or
      `strategy_unsupported` if override is the only enabled strategy)
- [x] Register in `src/ecosystem/mod.rs` (`pub mod cargo;` + one line in `ecosystems()`)
- [x] Fixtures: `cargo/relock`, `cargo/direct-bump`, `cargo/no-fix`

### M3 — Verification and safety
- [ ] `safety.rs`: credential files, secret env vars, Docker socket, configurable deny paths
- [ ] Refuse to run unless checks pass or `--allow-unsandboxed`
- [ ] `verify.rs`: temp copy, baseline build/test, apply, build, test, keep or revert
- [ ] Command timeouts
- [ ] Rescan after each change → `NewVulnerabilityIntroduced`
- [ ] Release-age check on every new package version in the lockfile diff
- [ ] Combine all kept changes and verify once more
- [ ] Fixtures: `cargo/build-break`, `cargo/baseline-broken`
- [ ] CI job: fixture tests in a container without secrets
- [ ] `report.rs`: Markdown output

### M4 — npm adapter
- [ ] Detect (`package.json` + `package-lock.json` v2/v3; yarn/pnpm → unsupported for now)
- [ ] Graph by parsing `package-lock.json` `packages` map
- [ ] Registry: packument (versions, deps, `time`), cached
- [ ] Version semantics via `node-semver`
- [ ] Apply via npm with `--package-lock-only --ignore-scripts --before=<cutoff>`
- [ ] Override via `overrides` in `package.json`
- [ ] Register in `src/ecosystem/mod.rs` (`pub mod npm;` + one line in `ecosystems()`)
- [ ] Peer dependency errors → `ResolutionConflict`
- [ ] Fixtures: `npm/relock`, `npm/direct-bump`, `npm/override`, `npm/build-break`
- [ ] CI: add Node toolchain to fixture job

### M5 — Gradle adapter
- [ ] Graph via injected init script that dumps the resolved graph as JSON
- [ ] Find where a version is declared: build files, `libs.versions.toml`, `ext`, BOMs
- [ ] Apply direct bump / BOM bump; override via `constraints {}`
- [ ] `ManifestNotEditable` when the declaration can't be located
- [ ] Fixtures under `test-projects/gradle/`
- [ ] CI: add JDK to fixture job

### Later
- [ ] Go adapter
- [ ] Flutter/Dart adapter
- [ ] yarn / pnpm support
- [ ] SARIF output
- [ ] `--sandbox=docker|podman` self-launch
