#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# SkyNet sidecar — smoke test / CI validation
#
# Usage:
#   bash smoke_test.sh
#
# This script verifies that the sidecar builds, passes lint,
# and all tests pass. Exit code is 0 on success, non-zero on failure.
#
# Set SKIP_BUILD=1 to skip the build step (faster for test-only checks).
# Set VERBOSE=1 to see full test output.
# ---------------------------------------------------------------------------

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

pass=0
fail=0
TEST_EXIT=0

step()  { echo -e "${CYAN}[smoke]${NC} $*"; }
ok()    { echo -e "  ${GREEN}✓${NC} $*"; ((pass++)); }
nok()   { echo -e "  ${RED}✗${NC} $*"; ((fail++)); }
skip()  { echo -e "  ${YELLOW}—${NC} $*"; }
header(){ echo -e "\n${CYAN}══════════════════════════════════════════════${NC}"; }

# Cross-platform temp file helper
mktemp_sidecar() {
    local tmpl="${1:-skynet-smoke-XXXXXXXX}"
    local dir="${TMPDIR:-${TEMP:-${TMP:-/tmp}}}"
    # Generate a random name since mktemp may not exist
    local name="${dir}/${tmpl}"
    name="${name%XXXXXXXX}$(date +%s)-$$"
    echo "$name"
}

# ── Locate Go ──────────────────────────────────────────────────────────────
step "Checking Go toolchain..."
GO=$(command -v go || true)
if [ -z "$GO" ]; then
    # Try common locations
    for try in /usr/local/go/bin/go /c/Users/123/.workbuddy/binaries/go/versions/*/go/bin/go; do
        [ -x "$try" ] && { GO="$try"; break; }
    done
fi
if [ -z "$GO" ]; then
    nok "Go not found — install Go 1.25+ and try again"
    exit 1
fi
GOVERSION=$("$GO" version 2>/dev/null || echo "unknown")
ok "Go toolchain: $GOVERSION"

# ── Change to sidecar directory ────────────────────────────────────────────
cd "$(dirname "$0")"

header
step "Starting smoke tests for SkyNet sidecar"
echo "  Directory: $(pwd)"
echo ""

# ── Step 1: Build ──────────────────────────────────────────────────────────
header
step "1/5: Building sidecar..."
if [ "${SKIP_BUILD:-0}" != "1" ]; then
    if "$GO" build -o /dev/null . 2>&1; then
        ok "Build succeeded"
    else
        nok "Build failed"
    fi
else
    skip "Build skipped (SKIP_BUILD=1)"
fi

# ── Step 2: Cross-platform build check ─────────────────────────────────────
header
step "2/5: Cross-platform build check..."
cross_ok=true
for os_arch in "linux/amd64" "darwin/amd64" "windows/amd64"; do
    GOOS="${os_arch%/*}" GOARCH="${os_arch#*/}"
    out=$(mktemp_sidecar "skynet-${os_arch%/}")
    if GOOS=$GOOS GOARCH=$GOARCH "$GO" build -o "$out" . 2>/dev/null; then
        ok "  $os_arch"
    else
        nok "  $os_arch"
        cross_ok=false
    fi
    rm -f "$out"
done

# ── Step 3: go vet ─────────────────────────────────────────────────────────
header
step "3/5: Running go vet..."
if "$GO" vet ./... 2>&1; then
    ok "go vet — no issues"
else
    nok "go vet found issues"
fi

# ── Step 4: Tests ──────────────────────────────────────────────────────────
header
step "4/5: Running unit tests..."
TEST_FLAGS="-count=1"
[ "${VERBOSE:-0}" = "1" ] && TEST_FLAGS="$TEST_FLAGS -v"

TEST_OUT=$(mktemp_sidecar "skynet-test-output")
if "$GO" test $TEST_FLAGS ./... > "$TEST_OUT" 2>&1; then
    ok "All tests passed"
else
    TEST_EXIT=$?
    nok "Some tests failed (exit code $TEST_EXIT)"
    echo ""
    # Show summary of failures.
    grep -E "^--- FAIL" "$TEST_OUT" | head -10 | while read -r line; do
        echo "       $line"
    done
    echo ""
    grep -E "^(FAIL|ok)" "$TEST_OUT" | head -20
fi
rm -f "$TEST_OUT"

# ── Step 5: Build utilities ────────────────────────────────────────────────
header
step "5/5: Building swbn-pkg utility..."
if "$GO" build -o /dev/null ./cmd/swbn-pkg/ 2>&1; then
    ok "swbn-pkg build succeeded"
else
    nok "swbn-pkg build failed"
fi

# ── Summary ────────────────────────────────────────────────────────────────
header
total=$((pass + fail))
echo -e "  Results: ${GREEN}${pass} passed${NC}, ${RED}${fail} failed${NC} (${total} total)"
echo ""

if [ "$fail" -eq 0 ] && [ "$TEST_EXIT" -eq 0 ]; then
    echo -e "  ${GREEN}╔════════════════════════════════════╗${NC}"
    echo -e "  ${GREEN}║   SMOKE TEST PASSED  ✅            ║${NC}"
    echo -e "  ${GREEN}╚════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "  ${RED}╔════════════════════════════════════╗${NC}"
    echo -e "  ${RED}║   SMOKE TEST FAILED  ❌            ║${NC}"
    echo -e "  ${RED}╚════════════════════════════════════╝${NC}"
    exit 1
fi
