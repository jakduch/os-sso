#!/bin/sh

set -eu

BASE_URL=https://jakduch.github.io/os-sso
EXPECTED_KEY_SHA256=3efc7a48172fb2f5efe0249de9064c771b902876e43332af28871a04b8b486e7
KEY_DIR=/usr/local/etc/pkg/keys
REPO_DIR=/usr/local/etc/pkg/repos
TMP_KEY=$(mktemp /tmp/jakduch-os-sso.pub.XXXXXX)
TMP_CONF=$(mktemp /tmp/JakduchOSSSO.conf.XXXXXX)
trap 'rm -f "$TMP_KEY" "$TMP_CONF"' EXIT HUP INT TERM

fetch -qo "$TMP_KEY" "$BASE_URL/os-sso.pub"
ACTUAL_KEY_SHA256=$(sha256 -q "$TMP_KEY")
if [ "$ACTUAL_KEY_SHA256" != "$EXPECTED_KEY_SHA256" ]; then
    echo "os-sso repository key fingerprint mismatch" >&2
    exit 1
fi

fetch -qo "$TMP_CONF" "$BASE_URL/JakduchOSSSO.conf"
install -d -m 0755 "$KEY_DIR" "$REPO_DIR"
install -m 0644 "$TMP_KEY" "$KEY_DIR/jakduch-os-sso.pub"
install -m 0644 "$TMP_CONF" "$REPO_DIR/JakduchOSSSO.conf"

pkg update -f
pkg install os-sso-devel
/usr/local/opnsense/scripts/firmware/register.php install os-sso-devel
