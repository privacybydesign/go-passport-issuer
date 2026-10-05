#!/usr/bin/env bash
# Downloads the Iris engine archive that iris-verifier links against, and
# verifies it against the checksum pinned below.
#
# The archive is not in this repository: it is a release asset, published with
# the manufacturer's permission. Downloading it grants no right to use it; see
# ../../LICENSE.
#
# Override any of LIBPASSPORTREADER_RELEASE, LIBPASSPORTREADER_SHA256,
# LIBPASSPORTREADER_BASE_URL or LIBPASSPORTREADER_URL to fetch from elsewhere,
# for example a mirror or a local file server.
set -euo pipefail

RELEASE="${LIBPASSPORTREADER_RELEASE:-libpassportreader-20261002}"
SHA256="${LIBPASSPORTREADER_SHA256:-9ada7e81482963ff3aea283138d14db405feb42bbe06d322a04104f57ac972ff}"
BASE_URL="${LIBPASSPORTREADER_BASE_URL:-https://github.com/privacybydesign/go-passport-issuer/releases/download}"
URL="${LIBPASSPORTREADER_URL:-${BASE_URL}/${RELEASE}/libpassportreader-linux-x86_64.a}"

# sha256sum on Linux, shasum on macOS.
sha_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/linux/x86_64"
archive="${dir}/libpassportreader.a"

if [ -f "${archive}" ] && [ "$(sha_of "${archive}")" = "${SHA256}" ]; then
  echo "libpassportreader.a is already present and matches the pinned checksum"
  exit 0
fi

mkdir -p "${dir}"
echo "Fetching ${URL}"
curl -fsSL --retry 3 -o "${archive}.tmp" "${URL}"

actual="$(sha_of "${archive}.tmp")"
if [ "${actual}" != "${SHA256}" ]; then
  rm -f "${archive}.tmp"
  echo "checksum mismatch: expected ${SHA256}, got ${actual}" >&2
  exit 1
fi

mv "${archive}.tmp" "${archive}"
echo "Wrote ${archive}"
