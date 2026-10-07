# Test projects

Small real projects with known vulnerable dependencies, one directory per
**scenario**. `tests/fixtures.rs` runs the `mendr` binary against each one:

```sh
nix develop -c cargo test --test fixtures -- --ignored              # all scenarios
MENDR_FIXTURE=cargo/relock nix develop -c cargo test --test fixtures -- --ignored
```

Adding a scenario needs no harness change: any directory below
`test-projects/` that contains an `expected.json` is a scenario.

## Layout

```
test-projects/<ecosystem>/<scenario>/
  Cargo.toml / package.json ...  the real project
  Cargo.lock / package-lock.json committed lockfile pinning the vulnerable version
  mendr.toml                     optional config
  osv/                           OSV records this scenario needs (one record per *.json file,
                                 standard osv.dev schema, e.g. saved from
                                 https://api.osv.dev/v1/vulns/<ID>)
  expected.json                  expectations (below)
```

Each scenario carries its own `osv/` snapshot so results are deterministic and
scenarios never share files.

Isolation rules:

- Cargo fixtures declare an empty `[workspace]` table so Cargo does not treat
  them as part of mendr's workspace.
- npm fixtures must not sit under a `package.json` with workspaces.
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
   `MENDR_CACHE_DIR=target/fixture-cache/mendr`, plus `SSL_CERT_FILE` /
   `NIX_SSL_CERT_FILE` when set. The empty `HOME` is why mendr's safety checks
   pass without `--allow-unsandboxed`.
3. The exit code and the findings in the JSON report are compared with
   `expected.json`.

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
