#!/bin/sh

set -eu

TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM

export TEST_ROOT

cat > "$TEST_ROOT/fetch" <<'EOF'
#!/bin/sh
set -eu
test "$1" = "-qo"
case "$3" in
    */os-sso.pub)
        cp repository/os-sso.pub "$2"
        ;;
    */JakduchOSSSO.conf)
        cp repository/JakduchOSSSO.conf "$2"
        ;;
    */bootstrap.sh)
        cat > "$2" <<'SCRIPT'
#!/bin/sh
printf 'bootstrap\n' >> "$TEST_ROOT/log"
SCRIPT
        ;;
    *)
        exit 64
        ;;
esac
EOF

cat > "$TEST_ROOT/pkg" <<'EOF'
#!/bin/sh
set -eu
printf 'pkg:%s\n' "$*" >> "$TEST_ROOT/log"
if [ "$1" = "info" ]; then
    test "${HAS_DEVEL:-0}" = "1"
fi
EOF

cat > "$TEST_ROOT/register" <<'EOF'
#!/bin/sh
set -eu
printf 'register:%s\n' "$*" >> "$TEST_ROOT/log"
EOF

cat > "$TEST_ROOT/sha256" <<'EOF'
#!/bin/sh
set -eu
test "$1" = "-q"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$2" | awk '{print $1}'
else
    shasum -a 256 "$2" | awk '{print $1}'
fi
EOF

chmod 755 "$TEST_ROOT/fetch" "$TEST_ROOT/pkg" "$TEST_ROOT/register" "$TEST_ROOT/sha256"

run_bootstrap()
{
    HAS_DEVEL=$1 \
        KEY_DIR="$TEST_ROOT/keys" \
        REPO_DIR="$TEST_ROOT/repos" \
        FETCH="$TEST_ROOT/fetch" \
        PKG="$TEST_ROOT/pkg" \
        REGISTER="$TEST_ROOT/register" \
        SHA256="$TEST_ROOT/sha256" \
        sh repository/bootstrap.sh
}

run_bootstrap 1
cat > "$TEST_ROOT/expected" <<'EOF'
pkg:update -f
pkg:info -e os-sso-devel
pkg:delete -y os-sso-devel
pkg:install -y os-sso
register:install os-sso
EOF
cmp "$TEST_ROOT/expected" "$TEST_ROOT/log"

: > "$TEST_ROOT/log"
FETCH="$TEST_ROOT/fetch" sh repository/reinstall.sh
printf 'bootstrap\n' > "$TEST_ROOT/expected"
cmp "$TEST_ROOT/expected" "$TEST_ROOT/log"
cmp repository/os-sso.pub "$TEST_ROOT/keys/jakduch-os-sso.pub"
cmp repository/JakduchOSSSO.conf "$TEST_ROOT/repos/JakduchOSSSO.conf"

: > "$TEST_ROOT/log"
run_bootstrap 0
cat > "$TEST_ROOT/expected" <<'EOF'
pkg:update -f
pkg:info -e os-sso-devel
pkg:install -y os-sso
register:install os-sso
EOF
cmp "$TEST_ROOT/expected" "$TEST_ROOT/log"
