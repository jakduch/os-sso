#!/bin/sh

set -eu

BASE_URL=${BASE_URL:-https://jakduch.github.io/os-sso}
EXPECTED_KEY_SHA256=3efc7a48172fb2f5efe0249de9064c771b902876e43332af28871a04b8b486e7
KEY_DIR=${KEY_DIR:-/usr/local/etc/pkg/keys}
REPO_DIR=${REPO_DIR:-/usr/local/etc/pkg/repos}
FETCH=${FETCH:-fetch}
PKG=${PKG:-pkg}
REGISTER=${REGISTER:-/usr/local/opnsense/scripts/firmware/register.php}
SHA256=${SHA256:-sha256}
TMP_KEY=$(mktemp /tmp/jakduch-os-sso.pub.XXXXXX)
TMP_CONF=$(mktemp /tmp/JakduchOSSSO.conf.XXXXXX)
trap 'rm -f "$TMP_KEY" "$TMP_CONF"' EXIT HUP INT TERM

"$FETCH" -qo "$TMP_KEY" "$BASE_URL/os-sso.pub"
ACTUAL_KEY_SHA256=$("$SHA256" -q "$TMP_KEY")
if [ "$ACTUAL_KEY_SHA256" != "$EXPECTED_KEY_SHA256" ]; then
    echo "os-sso repository key fingerprint mismatch" >&2
    exit 1
fi

"$FETCH" -qo "$TMP_CONF" "$BASE_URL/JakduchOSSSO.conf"
install -d -m 0755 "$KEY_DIR" "$REPO_DIR"
install -m 0644 "$TMP_KEY" "$KEY_DIR/jakduch-os-sso.pub"
install -m 0644 "$TMP_CONF" "$REPO_DIR/JakduchOSSSO.conf"

"$PKG" update -f

# Releases up to v2026.10.8 used the development package identity.  The OPNsense
# package framework deliberately marks os-sso and os-sso-devel as conflicting, so
# remove the old identity before installing the production package.  The durable
# plugin configuration is stored in /conf/config.xml and is not owned by either
# package.  The old package's pre-deinstall hook stops managed OpenVPN instances;
# the new package's post-install hook synchronizes and starts them again.
if "$PKG" info -e os-sso-devel; then
    echo "Replacing os-sso-devel with os-sso"
    "$PKG" delete -y os-sso-devel
fi

"$PKG" install -y os-sso
"$REGISTER" install os-sso
