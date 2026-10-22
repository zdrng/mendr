#!/usr/bin/env bash
# Reports unsafe code in mendr and its dependencies (cargo-geiger). A report,
# not a gate: unsafe code never fails it. Run in the dev shell:
#
#   nix develop -c scripts/geiger.sh [--output-format Ascii|GitHubMarkdown|Utf8]
#
# cargo-geiger 0.13 exits 1 on "Failed to match" warnings with current Cargo
# even when the report is complete, so the exit code is ignored and the report
# is checked instead. It cleans its target directory first, so it gets its own.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
name=mendr
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

CARGO_TARGET_DIR="$root/target/geiger" \
  cargo geiger --locked --manifest-path "$root/Cargo.toml" "$@" >"$work/report" 2>"$work/log" || true
if ! grep -qE " $name [0-9]" "$work/report"; then
  cat "$work/log" >&2
  echo "geiger.sh: cargo geiger produced no report" >&2
  exit 1
fi
cat "$work/report"
