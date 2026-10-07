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
min-release-age = "7d"
min-severity = "medium"
target = "minimal"           # or "latest-compatible"

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
`--format json|markdown`, `--osv-snapshot <dir>`.

## Results (draft)

- `Fixed { strategy, change }`
- `Skipped { reason }`: `NoPatchedVersion`, `NoParentVersionFixes`, `MajorBumpBlocked`,
  `StrategyUnsupported`, `Ignored`
- `Failed { reason }`: `BaselineFailed`, `ResolutionConflict`, `ReleaseAgePolicyViolated`,
  `InstallFailed`, `BuildFailed`, `TestFailed`, `Timeout`, `NewVulnerabilityIntroduced`,
  `ManifestNotEditable`

Reasons carry details (exit code, log tail, offending package/version, ...).

## Test projects

Small real projects with known vulnerable dependencies. One directory per **scenario**, not per
ecosystem, so each strategy and each failure reason is covered:

```
test-projects/
  osv-snapshot/              frozen OSV advisories used by fixture runs (deterministic)
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

Each scenario contains the project (with its **committed lockfile**) and an `expected.json`.
`tests/fixtures.rs` copies each scenario to a temp dir, runs `mendr --format json` with
`--osv-snapshot`, and compares only stable fields (advisory ID, package, strategy, target version,
outcome kind). Log tails and timestamps are ignored.

Constraints to keep in mind:

- **Isolation from the repo.** Every Cargo fixture declares an empty `[workspace]` table so Cargo
  does not treat it as part of mendr. npm fixtures must not sit under a root `package.json` with
  workspaces.
- **Determinism.** New advisories are published all the time and would change results. Fixture runs
  use the frozen `osv-snapshot`. A separate scheduled CI job runs against live OSV to catch drift.
- **Security alerts noise.** GitHub/Dependabot will flag the intentionally vulnerable lockfiles.
  Exclude `test-projects/` from Dependabot and dismiss alerts for it.
- **Fixtures run untrusted build scripts.** CI runs them in a container with no secrets, so mendr's
  own safety checks pass without `--allow-unsandboxed`. This doubles as a test of the safety checks.
- **Pick vulnerable packages carefully.** Old, well-known advisories with stable fixes, no install
  scripts, exact versions pinned in the lockfile. Verify each scenario actually reproduces.

## Milestones

### M0 — Setup
- [ ] `cargo init`, add clap, serde, serde_json, toml, toml_edit, semver, ureq, thiserror, anyhow
- [ ] CI: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`
- [ ] Dependabot exclusion for `test-projects/`

### M1 — Core (no real ecosystem yet)
- [ ] `model.rs`: Version, VersionReq, DepGraph, Change, Outcome, reasons (serde-serializable)
- [ ] `config.rs`: parse `mendr.toml`, apply flag overrides, validate
- [ ] `osv.rs`: query OSV API, load snapshot dir, local cache
- [ ] `osv.rs`: range matching (`introduced` / `fixed` / `last_affected`), alias dedupe, skip withdrawn
- [ ] `rules.rs`: release age, major bump, severity threshold, ignore list with expiry
- [ ] `ecosystem/mod.rs`: `Ecosystem` trait
- [ ] `ecosystem/fake.rs`: in-memory graph + registry
- [ ] `plan.rs`: relock / direct bump / override decision, recursive parent search, merge per direct dep
- [ ] Unit tests for planner and rules using the fake ecosystem
- [ ] `report.rs`: JSON output

### M2 — Cargo adapter
- [ ] Detect (`Cargo.toml` + `Cargo.lock`)
- [ ] Graph via `cargo metadata --format-version 1`
- [ ] Registry: sparse index (versions, deps, yanked) + crates.io API for publish dates, cached
- [ ] Version semantics via `semver` (0.x-aware bump kind)
- [ ] Apply relock: `cargo update -p name@from --precise to`
- [ ] Apply direct bump with `toml_edit`, including `[workspace.dependencies]` inheritance
- [ ] Override reported as `StrategyUnsupported`
- [ ] Fixtures: `cargo/relock`, `cargo/direct-bump`, `cargo/no-fix`

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
