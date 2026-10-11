#!/usr/bin/env bash
# Fetch libgcc.a + libgcc_eh.a (DWARF-2 unwinding) from the official rust-mingw component matching the
# active rustc, verify the tarball against static.rust-lang.org's published sha256, and place them in
# toolchain/i686-dw2/ with a VERSION file that build.rs checks.
set -euo pipefail
client="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$client"
full="$(rustc -V)"
ver="$(rustc -V | cut -d' ' -f2)"
name="rust-mingw-${ver}-i686-pc-windows-gnu"
url="https://static.rust-lang.org/dist/${name}.tar.xz"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -sSfL "$url" -o "$tmp/$name.tar.xz"
curl -sSfL "$url.sha256" -o "$tmp/$name.tar.xz.sha256"
published="$(cut -d' ' -f1 "$tmp/$name.tar.xz.sha256")"
actual="$(shasum -a 256 "$tmp/$name.tar.xz" | cut -d' ' -f1)"
if [[ "$published" != "$actual" ]]; then
  echo "sha256 mismatch for $url: published $published, downloaded $actual" >&2
  exit 1
fi
tar -xJf "$tmp/$name.tar.xz" -C "$tmp"
src="$tmp/$name/rust-mingw/lib/rustlib/i686-pc-windows-gnu/lib/self-contained"
mkdir -p toolchain/i686-dw2
cp "$src/libgcc.a" "$src/libgcc_eh.a" toolchain/i686-dw2/
printf '%s\n' "$full" > toolchain/i686-dw2/VERSION
echo "fetched $name (sha256 $actual) for: $full"
shasum -a 256 toolchain/i686-dw2/libgcc.a toolchain/i686-dw2/libgcc_eh.a
