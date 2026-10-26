#!/bin/sh
set -eu
TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM
mkdir "$TEST_ROOT/state"
printf 'PROFILE_staff_ENFORCE_USERNAME=1\n' > "$TEST_ROOT/vpn.conf"
sed -e "s@/usr/local/etc/sso/vpn.conf@$TEST_ROOT/vpn.conf@g" \
    -e "s@/var/db/os-sso-vpn@$TEST_ROOT/state@g" \
    src/opnsense/scripts/OPNsense/SSO/vpn_verdict.sh > "$TEST_ROOT/verdict.sh"
SID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
CONTROL="$TEST_ROOT/control"
printf 'pending' > "$CONTROL"
printf '%s\n192.0.2.1\nalice\nstaff\n' "$CONTROL" > "$TEST_ROOT/state/$SID"
OUT=$(sh "$TEST_ROOT/verdict.sh" "$SID" inspect 192.0.2.1 alice)
[ "$OUT" = 'ok alice' ]
[ -f "$TEST_ROOT/state/$SID" ]
[ "$(cat "$CONTROL")" = pending ]
OUT=$(sh "$TEST_ROOT/verdict.sh" "$SID" 1 192.0.2.1 alice)
[ "$OUT" = 'ok alice' ]
[ ! -f "$TEST_ROOT/state/$SID" ]
[ "$(cat "$CONTROL")" = 1 ]
if sh "$TEST_ROOT/verdict.sh" "$SID" 1 192.0.2.1 alice > /dev/null 2>&1; then
    echo 'a consumed VPN session was accepted again' >&2
    exit 1
fi
printf 'VPN inspection is read-only and the final verdict is single-use.\n'
