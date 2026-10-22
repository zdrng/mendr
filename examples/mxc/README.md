# Running mendr in an MXC sandbox

[MXC](https://github.com/microsoft/mxc) runs a command in a sandbox that the kernel enforces (on
macOS: Seatbelt, no root, no daemon). The two policies here run mendr for one project and block
everything else:

| file | for |
|------|-----|
| [`npm.json`](npm.json) | an npm or pnpm project, Node from Homebrew |
| [`cargo.json`](cargo.json) | a Rust project, toolchain from rustup |

Inside the sandbox:

- **readable and writable:** the project (for `--write`) and `~/.mendr-sandbox`, which is
  `HOME` and `TMPDIR` for mendr and everything it starts (npm/pnpm/Cargo caches, mendr's cache,
  the temp copy of the project);
- **readable:** `~/.cargo/bin` (mendr itself, rustup's `cargo`/`rustc`), the toolchain
  (`/opt/homebrew` or `~/.rustup`) and the system directories MXC always allows (`/usr`,
  `/System`, `/Library`, `/private/etc`, Xcode's command line tools);
- **blocked:** the rest of your home directory (`~/.ssh`, `~/.aws`, `~/.npmrc`,
  `~/.cargo/credentials.toml`, `~/.gitconfig`, other repositories, ...), the rest of `/tmp`,
  and every host environment variable: the sandbox gets only the variables listed in
  `process.env`;
- **network:** outbound open (OSV, registries, `npm install`, `cargo build` need it), nothing
  can connect in, and `localhost` is not reachable.

## Use

1. Get `mxc-exec-mac` (macOS 15 or later): `arm64/mxc-exec-mac` in `mxc-release-binaries.zip`
   of the [MXC releases](https://github.com/microsoft/mxc/releases), or build it from source.
2. Copy a policy and replace `/Users/me/...` with your paths: the project in `process.cwd` and
   `readwritePaths`, your home in the rest. Paths must be absolute (no `~`, no `..`).
3. If Node, mendr or the toolchain live elsewhere, add their directory to `PATH` **and** to
   `readonlyPaths`. With Nix: `/nix/store` in `readonlyPaths` and the output of
   `nix develop -c printenv PATH` as `PATH`.
4. Create the scratch directory once, then run:

```sh
mkdir -p ~/.mendr-sandbox/tmp
mxc-exec-mac --dry-run npm.json          # validate the policy
mxc-exec-mac npm.json > report.md        # progress on stderr, report on stdout
```

Change `commandLine` for other flags (`mendr --write`, `--plan-only`, ...). Without `--write`
the project can move from `readwritePaths` to `readonlyPaths`.

Notes:

- `~/.mendr-sandbox` is shared by every run that uses it, so code from one project's build can
  leave files for the next; `rm -rf ~/.mendr-sandbox` resets it (the next run downloads again).
- Tests that talk to a server on `localhost` need
  `"ingress": { "default": "allow", "hostLoopback": "allow" }`.
- Registry tokens from `~/.npmrc` or the host environment do not reach the sandbox, so
  dependencies from a registry that needs a login cannot be installed.
- A Rust project whose `rust-toolchain.toml` names a toolchain rustup has not installed fails:
  `~/.rustup` is read-only. Install it outside the sandbox first.
- Something blocked that should not be: run `mxc-exec-mac --debug npm.json` to see the
  generated profile, and see MXC's
  [Seatbelt guide](https://github.com/microsoft/mxc/blob/main/docs/backends/seatbelt/seatbelt-backend.md).
