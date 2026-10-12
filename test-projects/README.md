# Test projects

Small real projects with known vulnerable dependencies, one directory per
**scenario**. `tests/fixtures.rs` runs the `mendr` binary against each one:

```sh
nix develop -c cargo test --test fixtures -- --ignored              # all scenarios
MENDR_FIXTURE=cargo/relock nix develop -c cargo test --test fixtures -- --ignored
```

Adding a scenario needs no harness change: any directory below
`test-projects/` that contains an `expected.json` is a scenario.

## Scenarios

| scenario | mode | expected outcome |
|----------|------|------------------|
| `cargo/relock` | full | smallvec relocked to 1.6.1 -> `fixed` |
| `cargo/direct-bump` | full | tempfile bumped to 3.4.0 (drops remove_dir_all) -> `fixed` |
| `cargo/no-fix` | plan | no tempdir release fixes remove_dir_all -> `skipped:no_parent_version_fixes` |
| `cargo/build-break` | full | only fix is time 0.2.23 (`--allow-major`), whose API breaks the code -> `failed:build_failed` |
| `cargo/baseline-broken` | full | the project's own test fails before any change -> `failed:baseline_failed` |
| `npm/relock` | full | minimist relocked -> `fixed` |
| `npm/direct-bump` | full | jsprim bumped to 1.4.2 -> `fixed` |
| `npm/override` | full | path-to-regexp overridden to 0.1.13 -> `fixed` |
| `npm/build-break` | full | only fix is nth-check 2.0.1 (`--allow-major`), which breaks `npm test` -> `failed:test_failed` |
| `pnpm/relock` | full | minimist relocked to 1.2.6, `--write`: only `pnpm-lock.yaml` changes -> `fixed` |
| `pnpm/direct-bump` | full | jsprim bumped to 1.4.2, `--write` -> `fixed`, files checked |
| `pnpm/override` | full | path-to-regexp overridden to 0.1.13 for router 1.3.8 in `pnpm-workspace.yaml`, `--write` -> `fixed`, files checked |
| `pnpm/build-break` | full | only fix is nth-check 2.0.1 (`--allow-major`), which breaks `pnpm test` -> `failed:test_failed` |
| `mixed/monorepo` | full | `mendr.toml` with a Cargo and an npm project, `[[ignore]]` with and without expiry, `--write` -> `fixed` / `skipped:ignored`, files checked |

## Layout

```
test-projects/<ecosystem>/<scenario>/
  Cargo.toml / package.json ...  the real project
  Cargo.lock / package-lock.json / pnpm-lock.yaml
                                 committed lockfile pinning the vulnerable version
  mendr.toml                     optional config
  osv/                           OSV records this scenario needs (one record per *.json file,
                                 standard osv.dev schema, e.g. saved from
                                 https://api.osv.dev/v1/vulns/<ID>)
  expected.json                  expectations (below)
```

Each scenario carries its own `osv/` snapshot so results are deterministic and
scenarios never share files. A multi-project scenario (`mixed/<scenario>/`)
has a `mendr.toml` with `[[project]]` entries pointing at sub-directories and
one `osv/` for all of them.

Isolation rules:

- Cargo fixtures declare an empty `[workspace]` table so Cargo does not treat
  them as part of mendr's workspace.
- npm fixtures must not sit under a `package.json` with workspaces, pnpm fixtures not under a
  `pnpm-workspace.yaml`.
- Pick old, well-known advisories with stable fixes; no install scripts; exact
  versions pinned in the lockfile.

## How a scenario runs

1. The scenario directory is copied to a temp dir (without `target/`,
   `node_modules/`).
2. `mendr --format json --osv-snapshot <copy>/osv [--plan-only] <args...>` runs
   with the copy as working directory and an isolated environment:
   `env_clear()`, then only `PATH`, `HOME=<fresh empty dir>`,
   `CARGO_HOME=target/fixture-cache/cargo`,
   `npm_config_cache=target/fixture-cache/npm`,
   `pnpm_config_store_dir=target/fixture-cache/pnpm-store`,
   `MENDR_CACHE_DIR=target/fixture-cache/mendr`, plus the dev shell's
   toolchain variables when set: `NIX_*` (except `NIX_CONFIG`, which can hold
   tokens), `SSL_CERT_FILE`, `SDKROOT`, `DEVELOPER_DIR`,
   `MACOSX_DEPLOYMENT_TARGET`, `CC`, `CXX`, `AR`, `AS`, `LD`, `NM`, `RANLIB`,
   `STRIP` (needed to link on macOS). The empty `HOME` and cleared
   environment are why mendr's safety checks pass without
   `--allow-secrets`.
3. The exit code and the findings in the JSON report are compared with
   `expected.json`, then the `files` expectations are checked in the copy.

Full-mode scenarios run real builds, so mendr's safety checks apply. The one
check the harness cannot isolate is a container daemon socket
(`/var/run/docker.sock`, `/run/podman/podman.sock`) that is reachable on the
machine: mendr then refuses (exit 2). Stop the daemon, or opt in explicitly
for local runs:

```sh
MENDR_FIXTURE_ALLOW_SECRETS=1 nix develop -c cargo test --test fixtures -- --ignored
```

With `MENDR_FIXTURE_ALLOW_SECRETS=1` the harness passes
`--allow-secrets` to full-mode runs. CI never sets it.

## `expected.json`

```json
{
  "mode": "plan",
  "args": ["--allow-major"],
  "exit_code": 0,
  "findings": [
    {
      "advisory": "RUSTSEC-2021-0003",
      "package": "smallvec",
      "version": "1.6.0",
      "via": "smallvec",
      "strategy": "relock",
      "target": { "package": "smallvec", "to": "1.6.1" },
      "outcome": "planned"
    }
  ]
}
```

| field       | required | meaning |
|-------------|----------|---------|
| `mode`      | yes      | `"plan"` adds `--plan-only`; `"full"` runs verification (build + test) |
| `args`      | no       | extra CLI arguments |
| `exit_code` | yes      | 0 = nothing unresolved, 1 = unresolved findings remain, 2 = error |
| `findings`  | yes      | the **complete** list of expected findings (extra findings fail the test) |
| `files`     | no       | `{"<path>": ["text", ...]}`: after the run, each file (relative to the scenario) must contain every string; use with `"args": ["--write"]` |

Per finding:

| field      | required | compared against |
|------------|----------|------------------|
| `advisory` | yes      | report `advisory.id` **or** any of `advisory.aliases` |
| `package`  | yes      | vulnerable package name |
| `version`  | no       | vulnerable (locked) version |
| `via`      | no       | name of the direct dependency the paths go through (`== package` when direct) |
| `strategy` | no       | `"relock"`, `"direct_bump"`, `"override"` |
| `target`   | no       | `change.package` and `change.to` of the planned change |
| `outcome`  | yes      | `"planned"`, `"fixed"`, `"skipped:<reason>"`, `"failed:<reason>"` |

Reasons are the snake_case kinds from `src/model.rs`:

- skipped: `no_patched_version`, `no_parent_version_fixes`, `major_bump_blocked`,
  `strategy_unsupported`, `release_too_recent`, `ignored`, `below_min_severity`
- failed: `baseline_failed`, `resolution_conflict`, `release_age_policy_violated`,
  `install_failed`, `build_failed`, `test_failed`, `timeout`,
  `new_vulnerability_introduced`, `still_vulnerable`, `manifest_not_editable`, `error`

Expected findings are matched to report findings by `advisory` + `package`
(+ `version` / `via` when given); each must match exactly one report finding.
Log tails, severity scores, summaries, paths and timestamps are never compared.

Note: `min-release-age` defaults to 7 days and is checked against the current
date, so fixture fixes must be older than that (they always are for old
advisories). Use `"args": ["--min-release-age", "0"]` if needed.
