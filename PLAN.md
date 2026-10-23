# mendr — Plan

mendr scans projects for known vulnerabilities (via [OSV](https://osv.dev)) and fixes them the way a
developer would, following the user's policy (which strategies in which order, smallest fixed or
latest compatible version), and when the vulnerable package is a transitive dependency, update the
direct dependency that pulls it in. Every fix is verified with build and test,
and every attempt ends in a structured result with a reason.

## Principles

- **Simple.** Plain functions, run one after another, blocking I/O. No async runtime, no queues, no
  plugin system.
- **One binary crate** with modules. Split into a workspace only if it becomes painful.
- **One trait per ecosystem.** Each ecosystem is one module implementing `Ecosystem`. Planning,
  rules and reporting never know which ecosystem they run on.
- **One place for the operating system.** Everything OS-specific is in `src/platform`, behind
  one interface with one implementation per platform (`unix.rs`, `windows.rs`); only the one for
  the target is compiled. The rest of mendr never asks which system it runs on, and all `unsafe`
  code is in those two files (`#![deny(unsafe_code)]` elsewhere).
- **Never touch the user's checkout.** All changes happen in a temporary copy.
- **Isolation is not mendr's job.** Verification runs dependency code with the user's permissions;
  run mendr in an isolated environment when that matters, or use `--plan-only`.
- **Native tools are the source of truth.** After every change, resolve the graph again and rescan.

## How a run works

1. Load `mendr.toml`, apply CLI flag overrides.
2. For each project: detect the ecosystem, resolve the dependency graph, look up vulnerabilities in OSV.
3. Plan: for each vulnerable package, take the first of the enabled strategies (in their configured
   order, default `relock` → `direct bump` → `override`) that the rules allow, else give up with a
   reason. `target` picks the smallest fixed version or the latest compatible one.
4. Unless `--plan-only` or nothing is planned: copy the project, run a baseline build/test, then
   apply each change, build, test, and keep or revert it.
5. Print the report (JSON or Markdown).

## Module layout

```
src/
  main.rs            CLI (clap)
  config.rs          mendr.toml + flag overrides
  model.rs           Version, DepGraph, Change, Outcome, reasons
  osv.rs             OSV client, cache, snapshot loading, range matching, alias dedupe
  rules.rs           release age, major bumps, severity, ignore list (plain fns)
  plan.rs            fix planning (ecosystem-agnostic)
  verify.rs          temp copy, baseline, apply, build, test, revert
  interrupt.rs       Ctrl-C/SIGTERM: deferred exit, unwind, exit code
  platform/          everything OS-specific, one implementation compiled per target
    mod.rs           the interface: shell, process tree, interrupt handlers, terminal,
                     cache dir, permissions, symlinks, wrapper scripts, finding programs
    unix.rs          sh -c, process groups, signals (Linux, macOS, BSD)
    windows.rs       cmd /C, job objects, console control events
  report.rs          JSON + Markdown output
  cache.rs           on-disk cache (OSV records, adapter registry responses)
  http.rs            blocking HTTP helpers (ureq)
  ecosystem/
    mod.rs           Ecosystem trait + detection
    cargo.rs
    node_semver.rs   node-semver rules, shared by npm and pnpm
    npm/             lockfile, manifest, registry
    pnpm/            lockfile, manifest, overrides, registry
    gradle/          lockfile, graph, declare, constraints, registry (deps.dev), version
    fake.rs          in-memory ecosystem for unit tests
tests/
  fixtures.rs        runs the binary against every test project
test-projects/       see below
```

## Config

```toml
[policy]
strategies = ["relock", "direct-bump", "override"]  # order = preference
allow-major = false
min-release-age = "7d"       # default 7d; "0" disables
min-severity = "medium"      # default "low" (everything)
target = "minimal"           # smallest fixed version, or "latest-compatible"

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

CLI overrides: `--allow-major`, `--min-release-age <dur>`,
`--plan-only`, `--format json|markdown`, `--osv-snapshot <dir>`, `--output <file>`, `--write`, `--config <path>`.
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
  reached through two direct dependencies gives two findings, each with its own fix. Only a via
  declared by a root / workspace member is a direct-bump target (not one declared only by a
  path/git dependency). Up to 5 paths are reported per finding.
- Relock: a candidate must satisfy the requirements of `P`'s parents in the via group; with
  `Ecosystem::shared_copies` (Cargo: one copy per version) those of every parent of `P`.
- Fix candidates: newer, non-yanked, non-prerelease versions not affected by any advisory for
  the package that is neither ignored nor below `min-severity`. Direct-bump candidates of the via
  must not be affected by the via's own advisories. Strategy order comes from `policy.strategies`; first success wins.
- Direct bump search walks newer versions of the via package ascending and follows only the
  dependencies that lead to the vulnerable package in the current graph (memoized, depth ≤ 8,
  ≤ 200 candidates), resolving each to its highest matching version. Verification's rescan
  catches anything this approximation misses.
- When nothing works the reason is: first policy block (`major_bump_blocked`,
  `release_too_recent`), else `no_parent_version_fixes`, else `strategy_unsupported`. So a Cargo
  "no-fix" scenario reports `no_parent_version_fixes` (override unsupported is implied).
- Changes are merged per `(package, from)`: highest `to` wins, a bump absorbs a relock. A merged
  bump/override that became major without `allow-major` -> `major_bump_blocked`.
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

- npm (`src/ecosystem/npm/`):
  - relock = delete the lockfile entries of `package@from`, then `npm install --package-lock-only`;
    npm re-resolves exactly those copies to the newest version their parents allow (before the
    release cutoff), so the result may be above `to`.
  - override = `"overrides": {"<package>@<from> - <to>": "<to>"}`. npm 10 silently ignores a
    keyed override whose key range does not also match the replacement (`"pkg@1.2.3"` alone does
    nothing); the hyphen range scopes the override to the vulnerable line.
  - direct bump keeps the range style (`^1.2.3` → `^1.4.0`, `~`, `>=`, exact, `npm:` aliases) in
    every local `package.json` (root, workspaces) whose dependency resolves to `package@from`;
    other ranges are kept if they already allow `to` (plus a relock), else become `^to`; tags,
    URLs, git and `file:` specs → `manifest_not_editable`.
  - Default install is `npm ci` *with* install scripts (verification runs project code anyway and
    many packages need their scripts); build/test run only if `scripts.build` / a real
    `scripts.test` exist. Override per project with `install = "npm ci --ignore-scripts"`.
  - npm has no yanking; `deprecated` versions are *not* treated as yanked (most old fixed
    releases are deprecated). Bundled dependencies are not part of the graph.
  - serde_json's `preserve_order` feature is enabled crate-wide so manifest rewrites keep key order.

- Gradle (`src/ecosystem/gradle/`), builds with dependency locking only:
  - the graph is rebuilt without running Gradle: one root per project lockfile, every locked
    module the build declares hangs off it (requirement = the declared version, empty when it
    has none: platform/BOM/plugin-managed, so never direct-bumped), module edges come from
    each locked version's POM via deps.dev (only to versions locked in the same project with a
    configuration in common), and anything still unreachable hangs off its root with an empty
    requirement. Declarations are matched build-wide, not per project.
  - `satisfies` treats a plain version as exact (what a fresh resolution picks for a POM pin),
    so relocks never apply; `shared_copies` is true (one version per configuration).
  - apply edits the build files, then runs `gradle dependencies --write-locks` through
    `ApplyOptions::shell` (the build scripts run, so only during verification). "Cannot find a version of" / "Could not find"
    -> `ResolutionConflict`.
  - Gradle resolves conflicts to the highest version, so a bump through one direct dependency
    often fixes the findings of another via too; verification keeps such later changes
    without applying them.

### Verification (M3)

- Changes are applied **cumulatively** in one temp copy, in `plan.changes` order: each change is
  verified on top of the changes kept so far and reverted (snapshot restore) on failure. The last
  kept change therefore already ran build + test with all kept changes; the combined
  install/build/test re-run happens only when a later attempt was reverted (it may have left
  state in excluded dirs). If that re-run fails, every kept change fails with its reason.
- A change whose findings an earlier kept change already fixed is not applied and kept. One
  whose `package@from` is no longer locked (an earlier kept change already moved it) is not
  applied either; it is kept if the rescan shows its findings fixed, else `still_vulnerable`.
- The copy skips `copy_excludes()` (paths relative to the project) and drops symlinks that
  do not resolve inside the project. Snapshots/restores also skip `copy_excludes()` and leave
  them as they are, so the install command must reconcile them (e.g. `npm ci`). Consequence:
  dependencies outside the project dir (Cargo `path = "../x"`) are missing in the copy ->
  `baseline_failed`; point `[[project]] path` at the workspace root instead.
- **Adapters:** `apply` must change only manifests/lockfiles inside `workdir` (no temp files
  left behind): `--write` copies back exactly the non-excluded files `apply` changed, with
  their content captured right after `apply` (build/test output never reaches the project).
  `resolve_graph` runs on the copy after every `apply`; `releases()` is called for every
  package version new in the graph (release-age check, fail closed without a publish date).
- Rescan: `still_vulnerable` = a finding's package at its old version, or at any version its
  advisory affects, is still reachable from a direct dependency named like its `via`.
  `new_vulnerability_introduced` = an (advisory id/alias, package) pair not present before the
  change, unless ignored or below `min-severity`.
- Commands run in the platform's shell (`sh -c`, Windows `cmd /D /S /C`) in the copy with
  mendr's environment, stdin closed, stdout+stderr combined into the log tail. A timeout kills
  the command's whole process tree (process group, Windows job object; `src/platform`). A baseline
  timeout is reported as `baseline_failed` (`exit_code: null`, log tail says "timed out").

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
  mixed/
    monorepo/                mendr.toml with a Cargo and an npm project, [[ignore]], --write
  gradle/
    direct-bump/             version in libs.versions.toml, --write
    override/                BOM-managed dependency -> constraints {}, --write
    build-break/
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
  use each scenario's frozen `osv/` snapshot. (A scheduled job against live OSV to catch drift is
  listed under Later.)
- **Security alerts noise.** GitHub/Dependabot will flag the intentionally vulnerable lockfiles.
  Exclude `test-projects/` from Dependabot and dismiss alerts for it.
- **Fixtures run untrusted build scripts.** Fixable scenarios run in full mode (build + test). CI
  runs them on a runner VM with no secrets and Docker stopped. The harness passes
  only `PATH`, an empty `HOME`, cache dirs and the dev shell's toolchain variables (`NIX_*` except
  `NIX_CONFIG`, `SDKROOT`, `CC`, ...; needed to link on macOS). `expected.json` can check file contents after `--write` (`files`).
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
- [x] `verify.rs` stub with documented signatures (filled in by M3)

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

### M3 — Verification
- [x] `verify.rs`: temp copy, baseline build/test, apply, build, test, keep or revert
- [x] Command timeouts
- [x] Rescan after each change → `NewVulnerabilityIntroduced`
- [x] Release-age check on every new package version in the lockfile diff
- [x] Combine all kept changes and verify once more (cumulative; re-run after a revert)
- [x] Fixtures: `cargo/build-break`, `cargo/baseline-broken`
- [x] CI job: fixture tests without secrets (runner VM, no credentials, Docker stopped)
- [x] `report.rs`: Markdown output

### M4 — npm adapter
- [x] Detect (`package.json` + `package-lock.json` v2/v3; yarn/pnpm → unsupported for now)
- [x] Graph by parsing `package-lock.json` `packages` map (incl. workspaces, aliases, links)
- [x] Registry: packument (versions, deps, `time`), cached
- [x] Version semantics: npm's semver rules (small own port; the `node-semver` crate disagrees
      with npm on `<=1.2`-style ranges)
- [x] Apply via npm with `--package-lock-only --ignore-scripts --before=<cutoff>`
- [x] Override via `overrides` in `package.json`
- [x] Register in `src/ecosystem/mod.rs` (`pub mod npm;` + one line in `ecosystems()`)
- [x] Peer dependency errors → `ResolutionConflict`
- [x] Fixtures: `npm/relock`, `npm/direct-bump`, `npm/override`
- [x] Fixture: `npm/build-break` (full mode)
- [x] CI: add Node toolchain to fixture job (Node 22 comes from the flake's dev shell)

### M4b — pnpm adapter (independent of the npm adapter)
- [x] Detect (`package.json` + `pnpm-lock.yaml`)
- [x] Graph by parsing `pnpm-lock.yaml` v9 `importers` / `packages` / `snapshots` (incl.
      workspaces, links, aliases, peer variants, catalogs, pnpm 12's leading env document);
      ranges on registry edges from the version manifests (`GET <registry>/<name>/<version>`,
      cached forever)
- [x] Registry: packument (versions, deps, `time`), cached under `pnpm`
- [x] Version semantics: node-semver rules (the npm port, shared in `node_semver.rs`)
- [x] Apply via pnpm (>= 10) with `--lockfile-only --ignore-scripts`, a non-strict
      `minimum-release-age` and `trust-lockfile`
- [x] Relock by pinning the dependents for one install (parent-scoped overrides, exact importer
      specs), then unpinning: pnpm override keys match declared ranges, so a plain
      `pkg@from` key would also move copies at other versions
- [x] Override via parent-scoped `overrides` in `pnpm-workspace.yaml` (pnpm >= 11 ignores
      `pnpm.overrides` in `package.json`)
- [x] `ERR_PNPM_NO_MATCHING_VERSION` & co. → `ResolutionConflict`
- [x] Fixtures: `pnpm/relock`, `pnpm/direct-bump`, `pnpm/override`, `pnpm/build-break`
- [x] pnpm in the flake's dev shell
- [ ] Direct bumps of dependencies declared through catalogs (edit `pnpm-workspace.yaml`)

### M5 — Gradle adapter (dependency locking required)
- [x] Detect (build/settings script + a `gradle.lockfile`; without one: "no supported project
      with a lockfile", like npm without `package-lock.json`)
- [x] Graph from the project lockfiles + declarations + POM dependencies (deps.dev), no Gradle run
- [x] Version semantics: Maven `ComparableVersion` port + Gradle notation
- [x] Find where a version is declared: build scripts (string/map notation, one level of
      `val`/`def`/`ext`/`extra`/`gradle.properties` indirection), version catalogs
- [x] Direct bump; override via a marked `constraints {}` block
- [x] Lockfile update (`gradle dependencies --write-locks`) through `ApplyOptions::shell`
- [x] `ManifestNotEditable` when the declaration can't be located; unversioned (BOM-managed)
      declarations fall through to override
- [x] Fixtures under `test-projects/gradle/`
- [x] CI: Gradle + JDK in the dev shell
- [ ] BOM/platform bumps, relock via `--update-locks`, plugin classpath lockfiles

### Later
- [ ] Gradle builds without dependency locking
- [ ] Go adapter
- [ ] Flutter/Dart adapter
- [ ] yarn support
- [ ] SARIF output
- [ ] Scheduled CI job: fixtures against live OSV to catch advisory drift
