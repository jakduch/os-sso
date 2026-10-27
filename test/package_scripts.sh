#!/bin/sh

set -eu

TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM
export TEST_ROOT
export SSO_SYNC="$TEST_ROOT/sync" SSO_GUARD="$TEST_ROOT/guard"
export PATH="$TEST_ROOT:$PATH"

cat > "$SSO_SYNC" <<'SCRIPT'
#!/bin/sh
echo "sync:$*" >> "$TEST_ROOT/log"
if [ "${SSO_TEST_SYNC_FAIL:-0}" = 1 ]; then
    echo 'ERROR: simulated reconciliation failure'
    exit 1
fi
echo 'OK: changed=0 managed=1'
SCRIPT

cat > "$SSO_GUARD" <<'SCRIPT'
#!/bin/sh
case "$1" in
    onestatus) test -f "$TEST_ROOT/running" ;;
    onestart|onerestart)
        echo "$1" >> "$TEST_ROOT/log"
        test "${SSO_TEST_GUARD_FAIL:-0}" != 1 || exit 1
        : > "$TEST_ROOT/running"
        ;;
    onestop)
        echo onestop >> "$TEST_ROOT/log"
        rm -f "$TEST_ROOT/running"
        ;;
    *) exit 64 ;;
esac
SCRIPT
cat > "$TEST_ROOT/logger" <<'SCRIPT'
#!/bin/sh
echo "logger:$*" >> "$TEST_ROOT/syslog"
SCRIPT
chmod 755 "$SSO_SYNC" "$SSO_GUARD" "$TEST_ROOT/logger"

sh ./+POST_INSTALL.post
grep -qx 'sync:--repair-running' "$TEST_ROOT/log"
grep -qx onestart "$TEST_ROOT/log"

: > "$TEST_ROOT/log"
sh ./+POST_INSTALL.post
grep -qx 'sync:--repair-running' "$TEST_ROOT/log"
grep -qx onerestart "$TEST_ROOT/log"
if grep -q -- --stop-managed "$TEST_ROOT/log"; then
    echo "post-install stopped managed VPNs" >&2
    exit 1
fi

: > "$TEST_ROOT/log"
PKG_UPGRADE=true sh ./+PRE_DEINSTALL.post
test ! -s "$TEST_ROOT/log"
test -f "$TEST_ROOT/running"

PKG_UPGRADE=false sh ./+PRE_DEINSTALL.post
test "$(cat "$TEST_ROOT/log")" = "$(printf 'onestop\nsync:--stop-managed')"
test ! -f "$TEST_ROOT/running"

: > "$TEST_ROOT/log"
SSO_TEST_SYNC_FAIL=1 sh ./+POST_INSTALL.post > "$TEST_ROOT/output" 2>&1
grep -q 'continuing package installation' "$TEST_ROOT/output"
grep -qx onestart "$TEST_ROOT/log"
if grep -q -- --stop-managed "$TEST_ROOT/log"; then
    echo "post-install stopped managed VPNs" >&2
    exit 1
fi

: > "$TEST_ROOT/log"
SSO_TEST_GUARD_FAIL=1 sh ./+POST_INSTALL.post > "$TEST_ROOT/output" 2>&1
grep -q 'runtime guard could not be reloaded' "$TEST_ROOT/output"
grep -qx onerestart "$TEST_ROOT/log"
if grep -q -- --stop-managed "$TEST_ROOT/log"; then
    echo "post-install stopped managed VPNs" >&2
    exit 1
fi

if SSO_TEST_SYNC_FAIL=1 PKG_UPGRADE=false sh ./+PRE_DEINSTALL.post > "$TEST_ROOT/output" 2>&1; then
    echo 'deinstallation hid a stop failure' >&2
    exit 1
fi
grep -q 'could not prove every managed OpenVPN instance is stopped' "$TEST_ROOT/output"
echo 'package lifecycle regression checks passed'
