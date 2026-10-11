#!/usr/bin/env bash
# Fetch the m2-sdk import library (libm2-sdk.dll.a) for the release named in m2-sdk.version, verify it
# against the sha256 GitHub records for that release asset, and place it in toolchain/m2-sdk/ with a
# VERSION file that build.rs checks. Needs the GitHub CLI (`gh`), authenticated.
set -euo pipefail
client="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$client"
repo=Mercenaries-Fan-Build/mercs2-sdk
asset=libm2-sdk.dll.a
tag="$(tr -d '[:space:]' < m2-sdk.version)"
# Read the recorded digest BEFORE downloading, so the check is against what the release claims to hold.
want="$(gh api "repos/$repo/releases/tags/$tag" --jq ".assets[] | select(.name == \"$asset\") | .digest")"
if [[ -z "$want" ]]; then
  echo "$asset is not in $repo $tag (m2-sdk.version)" >&2
  exit 1
fi
want="${want#sha256:}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
gh release download "$tag" --repo "$repo" --pattern "$asset" --dir "$tmp"
got="$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1)"
if [[ "$want" != "$got" ]]; then
  echo "sha256 mismatch for $asset in $tag: recorded $want, downloaded $got" >&2
  exit 1
fi
mkdir -p toolchain/m2-sdk
cp "$tmp/$asset" toolchain/m2-sdk/
printf '%s\n' "$tag" > toolchain/m2-sdk/VERSION
echo "fetched $asset from $repo $tag (sha256 $got)"
