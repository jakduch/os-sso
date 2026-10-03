#!/bin/sh

set -eu

BASE_URL=${BASE_URL:-https://jakduch.github.io/os-sso}
FETCH=${FETCH:-fetch}
TMP_BOOTSTRAP=$(mktemp /tmp/os-sso-bootstrap.XXXXXX)
trap 'rm -f "$TMP_BOOTSTRAP"' EXIT HUP INT TERM

# Always fetch the bootstrap that belongs to the currently published signed
# repository.  It installs the repository trust material, removes the former
# os-sso-devel package when present and installs the production os-sso package.
"$FETCH" -qo "$TMP_BOOTSTRAP" "$BASE_URL/bootstrap.sh"
sh -n "$TMP_BOOTSTRAP"
/bin/sh "$TMP_BOOTSTRAP"
