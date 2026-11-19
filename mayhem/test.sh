#!/usr/bin/env bash
#
# mayhem/test.sh — RUN pgbouncer's own tests (what upstream `make check` runs), built by mayhem/build.sh:
#  1. upstream's pytest suite (test/test_*.py) against the normal-flags, cassert-enabled pgbouncer in
#     mayhem/.work/test/pgbouncer and a throwaway local PostgreSQL that test/utils.py starts with initdb
#     + pg_ctl on 127.0.0.1 / a unix socket (no outside network). Its tests assert query results, admin
#     SHOW output, auth outcomes and error messages. Counts come from pytest's junit XML.
#  2. test/hba_test: loads test/hba_test.rules and checks the auth method hba_eval() picks for every
#     line of test/hba_test.eval (known answers). Each eval line is one test case.
# Upstream skips some tests by itself here: USE_SUDO tests (iptables/tc; opt-in upstream too), LDAP
# tests (built --without-ldap), and the few its own skipif marks gate on platform/PG version.
# exit 0 = pass. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}


RUNNER="$SRC/test/hba_test"
BOUNCER_EXE="$SRC/mayhem/.work/test/pgbouncer"
for f in "$RUNNER" "$BOUNCER_EXE"; do
  if [ ! -x "$f" ]; then
    echo "test.sh: $f missing — mayhem/build.sh should have built it" >&2
    emit_ctrf "pgbouncer-pytest+hba_test" 0 1 0
    exit 1
  fi
done
export BOUNCER_EXE

# --- 1) pytest suite --------------------------------------------------------------------------
PG_BIN=$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)
if [ -z "$PG_BIN" ] || [ ! -x "$PG_BIN/initdb" ]; then
  echo "test.sh: PostgreSQL server binaries missing (mayhem/Dockerfile installs postgresql)" >&2
  emit_ctrf "pgbouncer-pytest+hba_test" 0 1 0
  exit 1
fi
export PATH="$PG_BIN:$PATH" PYTHONIOENCODING=utf8 PYTHONDONTWRITEBYTECODE=1
unset USE_SUDO ENABLE_VALGRIND
JUNIT="${TMPDIR:-/tmp}/pgbouncer-pytest-$$.xml"
rm -f "$JUNIT"
# Deselected (counted as skipped below), each needs something the offline grader does not have:
#  - test_load_balance_hosts_disable_bad_first: expects a DNS server to answer NXDOMAIN for
#    "unresolvable-hostname"; under --network none the lookup never fails, the connect just times out.
DESELECT=(
  "test/test_load_balance_hosts.py::test_load_balance_hosts_disable_bad_first"   # rootdir-relative node id
)
# test paths are absolute: test/utils.py chdir()s into test/, which breaks relative args in xdist workers
python3 -m pytest -p no:cacheprovider -n "$MAYHEM_JOBS" -r s --junitxml="$JUNIT" \
  "${DESELECT[@]/#/--deselect=}" "$SRC/test"; prc=$?
py_pass=0; py_fail=0; py_skip=0
if [ -s "$JUNIT" ]; then
  read -r py_pass py_fail py_skip < <(python3 -I - "$JUNIT" <<'PY'
import sys, xml.etree.ElementTree as ET
p = f = s = 0
for tc in ET.parse(sys.argv[1]).getroot().iter("testcase"):
    kids = {c.tag for c in tc}
    if kids & {"failure", "error"}: f += 1
    elif "skipped" in kids: s += 1
    else: p += 1
print(p, f, s)
PY
)
  py_skip=$(( py_skip + ${#DESELECT[@]} ))
fi
# pytest itself failed (collection error, crash) without a failing testcase: count it as a failure
if [ "$prc" -ne 0 ] && [ "$py_fail" -eq 0 ]; then py_fail=1; fi
[ $(( py_pass + py_fail )) -gt 0 ] || py_fail=1
rm -f "$JUNIT"
echo "test.sh: pytest passed=$py_pass failed=$py_fail skipped=$py_skip (rc=$prc)"

# --- 2) hba_test ------------------------------------------------------------------------------

# test cases = non-empty, non-comment lines of the eval file
total=$(grep -cvE '^(#|[[:space:]]*$)' "$SRC/test/hba_test.eval")
out=$(cd "$SRC/test" && ./hba_test 2>&1); rc=$?
echo "$out"
failed=$(printf '%s\n' "$out" | grep -c 'FAIL on line' || true)
if [ "$rc" -ne 0 ] || ! printf '%s\n' "$out" | grep -qx 'HBA test OK'; then
  # the runner did not report success: count every case as failed unless it listed them
  [ "$failed" -gt 0 ] || failed=$total
fi
passed=$(( total - failed ))
echo "test.sh: hba_test passed=$passed failed=$failed"
emit_ctrf "pgbouncer-pytest+hba_test" $(( passed + py_pass )) $(( failed + py_fail )) "$py_skip"
