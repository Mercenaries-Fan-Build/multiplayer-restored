#!/usr/bin/env bash
# Refresh the embedded Mozilla CA bundle from curl.se (https://curl.se/docs/caextract.html).
# Downloads cacert.pem and curl.se's published SHA-256, refuses a mismatch, then prints the values
# that must be copied into src/tls.rs (CA_BUNDLE_SHA256 and CA_BUNDLE_MOZILLA_DATE).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -sSfL https://curl.se/ca/cacert.pem -o "$tmp/cacert.pem"
curl -sSfL https://curl.se/ca/cacert.pem.sha256 -o "$tmp/cacert.pem.sha256"
published="$(cut -d' ' -f1 "$tmp/cacert.pem.sha256")"
actual="$(shasum -a 256 "$tmp/cacert.pem" | cut -d' ' -f1)"
if [[ "$published" != "$actual" ]]; then
  echo "sha256 mismatch: published $published, downloaded $actual" >&2
  exit 1
fi
cp "$tmp/cacert.pem" "$tmp/cacert.pem.sha256" "$here/"
echo "CA_BUNDLE_SHA256 = $actual"
grep -m1 'Certificate data from Mozilla as of' "$here/cacert.pem"
