#!/usr/bin/env bash
# Builds the release binary twice, from two copies of the source in directories
# with different path lengths and with separate target directories, and fails
# unless both binaries are bit for bit identical. Run in the dev shell, whose
# toolchain is pinned by flake.lock:
#
#   nix develop -c scripts/check-reproducible.sh
#
# Reproducible because of: --locked, the pinned toolchain, one codegen unit
# and stripped symbols (Cargo.toml [profile.release]) and --remap-path-prefix
# for the source, target and Cargo home directories, so no machine paths end
# up in panic messages.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
name=mendr
# Everything the release build reads.
inputs="Cargo.toml Cargo.lock src"
cargo_home=${CARGO_HOME:-$HOME/.cargo}
export LC_ALL=C TZ=UTC CARGO_INCREMENTAL=0

extra=""
# ld64 hashes the debug map (absolute object file paths) into LC_UUID before
# the symbols are stripped; -S leaves the debug map out.
[ "$(uname -s)" = Darwin ] && extra="-C link-arg=-Wl,-S"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# build <n>: builds copy <n> and prints the binary's hash.
build() {
  local src="$work/$1/src-$1/$name" tdir="$work/$1/target"
  mkdir -p "$src"
  # shellcheck disable=SC2086 # $inputs is a list of paths
  (cd "$root" && cp -R $inputs "$src/")
  RUSTFLAGS="--remap-path-prefix=$src=/$name --remap-path-prefix=$tdir=/target --remap-path-prefix=$cargo_home=/cargo $extra" \
    CARGO_TARGET_DIR="$tdir" \
    cargo build --release --locked --manifest-path "$src/Cargo.toml" >&2
  sha256sum "$tdir/release/$name" | cut -d' ' -f1
}

a=$(build a)
b=$(build bb)
echo "build a:  $a"
echo "build bb: $b"
if [ "$a" != "$b" ]; then
  trap - EXIT
  echo "check-reproducible: the two builds differ. Compare them with:" >&2
  echo "  nix run nixpkgs#diffoscope -- $work/a/target/release/$name $work/bb/target/release/$name" >&2
  exit 1
fi
echo "check-reproducible: ok"
