#!/usr/bin/env bash
# All checks: run them before every commit; the release workflow runs them
# before it builds anything. In the dev shell:
#
#   nix develop -c scripts/check.sh
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo deny --locked check
cargo audit
