#!/usr/bin/env bash
# Usage: ./xtests/run.sh [options|live|madns|all]

DOG="${DOG:-target/debug/dog}"
PASSED=0
FAILED=0
SKIPPED=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

if [[ ! -x "$DOG" ]]; then
    echo "Error: dog binary not found at $DOG"
    echo "Run 'cargo build' first or set DOG=/path/to/dog"
    exit 1
fi

test_cmd() {
    local name="$1"
    local expected_status="$2"
    local stdout_check="$3"
    local stderr_check="$4"
    shift 4

    local stdout_file
    local stderr_file
    stdout_file=$(mktemp)
    stderr_file=$(mktemp)

    timeout 10 "$@" >"$stdout_file" 2>"$stderr_file"
    local actual_status=$?

    if [[ $actual_status -eq 124 ]]; then
        actual_status=1
    fi

    local stdout_output
    local stderr_output
    stdout_output=$(cat "$stdout_file")
    stderr_output=$(cat "$stderr_file")
    rm -f "$stdout_file" "$stderr_file"

    local failed=0
    local reason=""

    if [[ "$actual_status" != "$expected_status" ]]; then
        failed=1
        reason="exit code: expected $expected_status, got $actual_status"
    fi

    if [[ -n "$stdout_check" ]] && [[ "$stdout_output" != *"$stdout_check"* ]]; then
        failed=1
        reason="stdout doesn't contain: $stdout_check"
    fi

    if [[ -n "$stderr_check" ]] && [[ "$stderr_output" != *"$stderr_check"* ]]; then
        failed=1
        reason="stderr doesn't contain: $stderr_check"
    fi

    if [[ $failed -eq 0 ]]; then
        echo -e "${GREEN}✓${NC} $name"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}✗${NC} $name"
        echo "  Command: $*"
        echo "  Reason: $reason"
        FAILED=$((FAILED + 1))
    fi
}

skip_test() {
    local name="$1"
    echo -e "${YELLOW}○${NC} $name (skipped)"
    SKIPPED=$((SKIPPED + 1))
}

check_network() {
    ping -c 1 -W 2 1.1.1.1 &>/dev/null
}

run_options_tests() {
    echo ""
    echo "=== Options Tests ==="
    test_cmd "dog --help shows help" 0 "Examples:" "" "$DOG" --help
    test_cmd "dog --help shows query options" 0 "Query options:" "" "$DOG" --help
    test_cmd "dog without args shows error" 3 "" "No domains" "$DOG"
    test_cmd "dog --version shows version" 0 "dog" "" "$DOG" --version
    test_cmd "dog --wibble shows invalid argument" 2 "" "unexpected argument" "$DOG" --wibble
    test_cmd "dog --class without value shows error" 2 "" "value is required" "$DOG" --class
    test_cmd "dog --class XYZZY shows invalid class" 2 "" "invalid value" "$DOG" --class XYZZY example.com
    test_cmd "dog --type XYZZY shows invalid type" 3 "" "Invalid query type" "$DOG" --type XYZZY example.com
    test_cmd "dog -Z invalid shows invalid tweak" 3 "" "Invalid protocol tweak" "$DOG" -Z invalid example.com
    test_cmd "dog OPT shows OPT error" 3 "" "OPT request is sent by default" "$DOG" OPT example.com
    test_cmd "dog --https without URL shows error" 3 "" "must pass a URL" "$DOG" --https example.com
}

run_live_tests() {
    echo ""
    echo "=== Live Tests (requires network) ==="

    if ! check_network; then
        echo -e "${YELLOW}Network unavailable, skipping live tests${NC}"
        return
    fi

    test_cmd "dog dns.google returns A record" 0 "A dns.google" "" "$DOG" dns.google @1.1.1.1
    test_cmd "dog with UDP works" 0 "A dns.google" "" "$DOG" dns.google -U @1.1.1.1
    test_cmd "dog with TCP works" 0 "A dns.google" "" "$DOG" dns.google -T @1.1.1.1
    test_cmd "dog MX record works" 0 "MX" "" "$DOG" MX google.com @1.1.1.1
    test_cmd "dog TXT record works" 0 "TXT" "" "$DOG" TXT google.com @1.1.1.1
    test_cmd "dog --json outputs JSON" 0 '"queries"' "" "$DOG" dns.google @1.1.1.1 --json
    test_cmd "dog --short outputs only data" 0 "" "" "$DOG" dns.google @1.1.1.1 --short
    test_cmd "dog --time shows duration" 0 "Ran in" "" "$DOG" dns.google @1.1.1.1 --time
    test_cmd "dog -x reverse lookup" 0 "PTR" "" "$DOG" -x 8.8.8.8 @1.1.1.1

    if timeout 5 "$DOG" --tls dns.google @1.1.1.1 &>/dev/null; then
        test_cmd "dog with TLS works" 0 "A dns.google" "" "$DOG" dns.google -S @1.1.1.1
    else
        skip_test "dog with TLS works (TLS not compiled)"
    fi

    if timeout 5 "$DOG" --https dns.google @https://cloudflare-dns.com/dns-query &>/dev/null; then
        test_cmd "dog with HTTPS works" 0 "A dns.google" "" "$DOG" dns.google -H @https://cloudflare-dns.com/dns-query
    else
        skip_test "dog with HTTPS works (HTTPS not compiled)"
    fi

    test_cmd "dog with non-existent server fails" 1 "" "" "$DOG" dns.google @192.0.2.1 -U
}

run_madns_tests() {
    echo ""
    echo "=== MADNS Tests (requires network) ==="

    if ! check_network; then
        echo -e "${YELLOW}Network unavailable, skipping madns tests${NC}"
        return
    fi

    local MADNS="@madns.binarystar.systems:5301"

    if ! timeout 5 "$DOG" A a.example "$MADNS" --tcp &>/dev/null; then
        echo -e "${YELLOW}MADNS server unreachable, skipping${NC}"
        return
    fi

    test_cmd "madns A record" 0 "1.2.3.4" "" "$DOG" A a.example "$MADNS" --tcp
    test_cmd "madns AAAA record" 0 "AAAA" "" "$DOG" AAAA aaaa.example "$MADNS" --tcp
    test_cmd "madns MX record" 0 "MX" "" "$DOG" MX mx.example "$MADNS" --tcp
    test_cmd "madns TXT record" 0 "TXT" "" "$DOG" TXT txt.example "$MADNS" --tcp
    test_cmd "madns CNAME record" 0 "CNAME" "" "$DOG" CNAME cname.example "$MADNS" --tcp
    test_cmd "madns NS record" 0 "NS" "" "$DOG" NS ns.example "$MADNS" --tcp
    test_cmd "madns SOA record" 0 "SOA" "" "$DOG" SOA soa.example "$MADNS" --tcp
    test_cmd "madns PTR record" 0 "PTR" "" "$DOG" PTR ptr.example "$MADNS" --tcp
    test_cmd "madns SRV record" 0 "SRV" "" "$DOG" SRV srv.example "$MADNS" --tcp
    test_cmd "madns CAA record" 0 "CAA" "" "$DOG" CAA caa.example "$MADNS" --tcp
    test_cmd "madns too-long A record error" 1 "" "record length" "$DOG" A too-long.a.invalid "$MADNS" --tcp
}

print_summary() {
    echo ""
    echo "=== Summary ==="
    echo -e "Passed:  ${GREEN}$PASSED${NC}"
    echo -e "Failed:  ${RED}$FAILED${NC}"
    echo -e "Skipped: ${YELLOW}$SKIPPED${NC}"

    if [[ $FAILED -gt 0 ]]; then
        exit 1
    fi
}

case "${1:-all}" in
    options) run_options_tests ;;
    live) run_live_tests ;;
    madns) run_madns_tests ;;
    all)
        run_options_tests
        run_live_tests
        run_madns_tests
        ;;
    *) echo "Usage: $0 [options|live|madns|all]"; exit 1 ;;
esac

print_summary
