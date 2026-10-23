#!/usr/bin/env bash
# Reproducible release builds, used by .github/workflows/release.yml. This
# script and the workflow are the same in mendr, pinr and lootr; only the
# `targets` line below differs. The package name and version come from
# Cargo.toml.
#
#   scripts/release.sh version                      version from Cargo.toml
#   scripts/release.sh name                         package name from Cargo.toml
#   scripts/release.sh rust-version                 release toolchain (flake.nix)
#   scripts/release.sh matrix                       build matrix for the workflow (JSON)
#   scripts/release.sh build <target> <outdir>      build one asset
#   scripts/release.sh reproduce <target> <outdir>  build twice, fail unless identical
#   scripts/release.sh smoke <target> <outdir>      check and run the built asset
#   scripts/release.sh sbom <outdir>                CycloneDX SBOM
#
# Linux and macOS: run in `nix develop .#release` (Rust pinned by flake.nix
# and flake.lock, zig for the musl builds). Windows: Git Bash with rustup's
# toolchain `rust-version`; Nix does not run on Windows. `smoke` needs no
# toolchain.
#
# Targets and assets:
#   x86_64-unknown-linux-musl, aarch64-unknown-linux-musl
#       static binaries, built on Linux with cargo-zigbuild (zig is the C
#       compiler and linker for musl, also across architectures)
#   universal-apple-darwin
#       arm64 + x86_64 in one binary (lipo), built on macOS and linked by
#       the system's /usr/bin/cc, so it only references system libraries
#   x86_64-pc-windows-msvc
#       built on Windows with the C runtime linked statically
#   Linux and macOS: <name>-<version>-<target>.tar.gz with a directory
#   <name>-<version>-<target>/ holding the binary, LICENSE and README.md.
#   Windows: <name>-<version>-<target>.exe.
#
# Reproducibility: --locked, the pinned toolchain, one codegen unit and no
# symbols (Cargo.toml [profile.release]), --remap-path-prefix and
# -ffile-prefix-map for the source, target and Cargo home directories (no
# machine paths in the binary), /Brepro on Windows (no link timestamp), and
# archives with sorted entries, fixed owner and modes, mtime = commit time
# and gzip without name or time.
set -euo pipefail

targets="x86_64-unknown-linux-musl aarch64-unknown-linux-musl universal-apple-darwin"

root=$(cd "$(dirname "$0")/.." && pwd)
manifest_value() {
  sed -n "s/^$1 = \"\\([^\"]*\\)\"\$/\\1/p" "$root/Cargo.toml" | head -n 1
}
name=$(manifest_value name)
version=$(manifest_value version)
[ -n "$name" ] && [ -n "$version" ] || { echo "release.sh: no name or version in Cargo.toml" >&2; exit 2; }

export LC_ALL=C TZ=UTC CARGO_INCREMENTAL=0
# The deployment target is fixed (the dev shell would otherwise leak its own).
export MACOSX_DEPLOYMENT_TARGET=11.0

windows=false
case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) windows=true ;; esac

# native <path>: the path as the compiler sees it (C:\... on Windows).
native() {
  if $windows; then cygpath -w "$1"; else echo "$1"; fi
}

runner() {
  case "$1" in
    *-linux-musl) echo ubuntu-24.04 ;;
    *-apple-darwin) echo macos-15 ;;
    *-windows-msvc) echo windows-2025 ;;
    *) echo "release.sh: unknown target $1" >&2; exit 2 ;;
  esac
}

asset() {
  case "$1" in
    *-windows-msvc) echo "$name-$version-$1.exe" ;;
    *) echo "$name-$version-$1.tar.gz" ;;
  esac
}

# Commit time for archive mtimes. Nix shells always set
# SOURCE_DATE_EPOCH=315532800 (1980), so git comes first.
epoch() {
  local e
  e=$(git -C "$root" log -1 --format=%ct 2>/dev/null || true)
  [ -n "$e" ] || e=${SOURCE_DATE_EPOCH:-}
  [[ "$e" =~ ^[0-9]+$ ]] || { echo "release.sh: no commit to take the time from" >&2; exit 2; }
  echo "$e"
}

# cargo_build <source dir> <target dir> <rust target>: prints the binary path.
cargo_build() {
  local src=$1 tdir=$2 rtarget=$3
  local cargo_home=${CARGO_HOME:-$HOME/.cargo}
  local tvar flags cflags
  tvar=$(echo "$rtarget" | tr 'a-z-' 'A-Z_')
  # Later --remap-path-prefix flags win: the most specific paths go last.
  flags="--remap-path-prefix=$(native "$cargo_home")=/cargo --remap-path-prefix=$(native "$src")=/$name --remap-path-prefix=$(native "$tdir")=/target"
  cflags="-ffile-prefix-map=$cargo_home=/cargo -ffile-prefix-map=$src=/$name -ffile-prefix-map=$tdir=/target"
  case "$rtarget" in
    *-linux-musl)
      env "CFLAGS_$rtarget=$cflags" "CARGO_TARGET_${tvar}_RUSTFLAGS=$flags" \
        cargo zigbuild --release --locked --target "$rtarget" \
        --manifest-path "$src/Cargo.toml" --target-dir "$tdir" >&2
      ;;
    *-apple-darwin)
      # ld64 hashes the debug map (absolute object file paths) into LC_UUID
      # before the symbols are stripped; -S leaves the debug map out.
      env "CC_$rtarget=/usr/bin/cc" "CFLAGS_$rtarget=$cflags" \
        "CARGO_TARGET_${tvar}_LINKER=/usr/bin/cc" \
        "CARGO_TARGET_${tvar}_RUSTFLAGS=$flags -C link-arg=-Wl,-S" \
        cargo build --release --locked --target "$rtarget" \
        --manifest-path "$src/Cargo.toml" --target-dir "$tdir" >&2
      ;;
    *-windows-msvc)
      env "CARGO_TARGET_${tvar}_RUSTFLAGS=$flags -C target-feature=+crt-static -C link-arg=/Brepro" \
        cargo build --release --locked --target "$rtarget" \
        --manifest-path "$(native "$src")/Cargo.toml" --target-dir "$(native "$tdir")" >&2
      ;;
  esac
  case "$rtarget" in
    *-windows-msvc) echo "$tdir/$rtarget/release/$name.exe" ;;
    *) echo "$tdir/$rtarget/release/$name" ;;
  esac
}

# build_binary <source dir> <target dir> <release target> <output file>
build_binary() {
  local src=$1 tdir=$2 target=$3 out=$4
  case "$target" in
    *-linux-musl | *-windows-msvc)
      cp "$(cargo_build "$src" "$tdir" "$target")" "$out"
      ;;
    universal-apple-darwin)
      [ "$(uname -s)" = Darwin ] || { echo "release.sh: $target needs a macOS host" >&2; exit 2; }
      local arm x86
      arm=$(cargo_build "$src" "$tdir" aarch64-apple-darwin)
      x86=$(cargo_build "$src" "$tdir" x86_64-apple-darwin)
      lipo -create -output "$out" "$arm" "$x86"
      ;;
    *)
      echo "release.sh: unknown target $target" >&2
      exit 2
      ;;
  esac
}

# package <source dir> <binary> <target> <outdir>: writes the asset.
package() {
  local src=$1 bin=$2 target=$3 outdir=$4
  local stage dir f
  mkdir -p "$outdir"
  case "$target" in
    *-windows-msvc)
      cp "$bin" "$outdir/$(asset "$target")"
      ;;
    *)
      dir="$name-$version-$target"
      stage=$(mktemp -d)
      mkdir -m 0755 "$stage/$dir"
      install -m 0755 "$bin" "$stage/$dir/$name"
      for f in LICENSE README.md THIRD_PARTY.md; do
        if [ -f "$src/$f" ]; then install -m 0644 "$src/$f" "$stage/$dir/$f"; fi
      done
      tar -C "$stage" --sort=name --format=gnu --mtime="@$(epoch)" \
        --owner=0 --group=0 --numeric-owner -cf - "$dir" | gzip -9 -n >"$outdir/$(asset "$target")"
      rm -rf "$stage"
      ;;
  esac
  echo "$outdir/$(asset "$target")"
}

# copy_source <dir>: the files the release build reads, plus the shipped ones.
copy_source() {
  local f
  mkdir -p "$1"
  for f in Cargo.toml Cargo.lock build.rs src LICENSE README.md THIRD_PARTY.md; do
    if [ -e "$root/$f" ]; then cp -R "$root/$f" "$1/"; fi
  done
}

cmd_build() {
  local target=$1 outdir=$2 work
  work=$(mktemp -d)
  copy_source "$work/$name"
  build_binary "$work/$name" "$work/target" "$target" "$work/bin"
  package "$work/$name" "$work/bin" "$target" "$outdir"
  rm -rf "$work"
}

# Two builds from copies of the source in directories with different path
# lengths and separate target directories: the assets must be identical.
cmd_reproduce() {
  local target=$1 outdir=$2 work n out a b
  work=$(mktemp -d)
  for n in a bb; do
    copy_source "$work/$n/src-$n/$name"
    build_binary "$work/$n/src-$n/$name" "$work/$n/target" "$target" "$work/$n/bin"
    out=$(package "$work/$n/src-$n/$name" "$work/$n/bin" "$target" "$work/$n/out")
    echo "build $n: $(sha256sum "$out" | cut -d' ' -f1)  $(basename "$out")" >&2
  done
  a=$(sha256sum <"$work/a/out/$(asset "$target")")
  b=$(sha256sum <"$work/bb/out/$(asset "$target")")
  if [ "$a" != "$b" ]; then
    echo "release.sh: $target is not reproducible. Compare with:" >&2
    echo "  nix run nixpkgs#diffoscope -- $work/a/out/$(asset "$target") $work/bb/out/$(asset "$target")" >&2
    exit 1
  fi
  mkdir -p "$outdir"
  cp "$work/a/out/$(asset "$target")" "$outdir/"
  rm -rf "$work"
  echo "$outdir/$(asset "$target")"
}

# Checks that the asset is what it claims to be and runs it where the host can.
cmd_smoke() {
  local target=$1 outdir=$2 file bin got tmp
  file="$outdir/$(asset "$target")"
  [ -f "$file" ] || { echo "release.sh: $file is missing" >&2; exit 1; }
  tmp=$(mktemp -d)
  case "$target" in
    *-windows-msvc) bin=$file ;;
    *)
      tar -xzf "$file" -C "$tmp"
      bin="$tmp/$name-$version-$target/$name"
      [ -x "$bin" ] || { echo "release.sh: no executable $name in $file" >&2; exit 1; }
      ;;
  esac
  case "$target" in
    x86_64-unknown-linux-musl) file "$bin" | grep -q 'x86-64.*static' ;;
    aarch64-unknown-linux-musl) file "$bin" | grep -q 'ARM aarch64.*statically linked' ;;
    universal-apple-darwin)
      lipo -info "$bin" | grep -q 'x86_64 arm64'
      # Only system libraries, nothing from Nix or Homebrew.
      if otool -L "$bin" | grep '^[[:space:]]' | grep -Ev '^[[:space:]]+(/usr/lib/|/System/Library/)'; then
        echo "release.sh: $target links libraries outside the system" >&2
        exit 1
      fi
      ;;
  esac
  # Runs only where the host can execute the binary.
  case "$target/$(uname -m)" in
    x86_64-unknown-linux-musl/x86_64 | universal-apple-darwin/*)
      got=$(env -i HOME="$tmp" PATH="/usr/bin:/bin" "$bin" --version)
      ;;
    x86_64-pc-windows-msvc/*) got=$("$bin" --version | tr -d '\r') ;;
    *) got="$name $version" ;;
  esac
  [ "$got" = "$name $version" ] || { echo "release.sh: --version printed '$got'" >&2; exit 1; }
  rm -rf "$tmp"
  echo "smoke test ok: $(basename "$file")"
}

cmd_matrix() {
  local t sep=""
  printf '['
  for t in $targets; do
    printf '%s{"target":"%s","runner":"%s"}' "$sep" "$t" "$(runner "$t")"
    sep=,
  done
  printf ']\n'
}

cmd_sbom() {
  local outdir=$1
  mkdir -p "$outdir"
  # All platforms (a superset of the release targets' dependencies), with
  # build dependencies (they run at build time).
  cargo cyclonedx --manifest-path "$root/Cargo.toml" --format json --spec-version 1.5 \
    --target all --override-filename "$name-$version.cdx" >&2
  mv "$root/$name-$version.cdx.json" "$outdir/"
  echo "$outdir/$name-$version.cdx.json"
}

usage() {
  echo "usage: $0 version | name | rust-version | matrix | build|reproduce|smoke <target> <outdir> | sbom <outdir>" >&2
  exit 2
}

case "${1:-}" in
  version) echo "$version" ;;
  name) echo "$name" ;;
  rust-version) sed -n 's/^ *releaseRust = "\([^"]*\)";$/\1/p' "$root/flake.nix" ;;
  matrix) cmd_matrix ;;
  build) [ $# -eq 3 ] || usage; cmd_build "$2" "$3" ;;
  reproduce) [ $# -eq 3 ] || usage; cmd_reproduce "$2" "$3" ;;
  smoke) [ $# -eq 3 ] || usage; cmd_smoke "$2" "$3" ;;
  sbom) [ $# -eq 2 ] || usage; cmd_sbom "$2" ;;
  *) usage ;;
esac
