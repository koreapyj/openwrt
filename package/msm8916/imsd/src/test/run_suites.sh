#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Run every test binary of the unified runner and print one combined summary.
#   run_suites.sh <outdir> <suite>...      (binaries <outdir>/<suite>, logs <outdir>/<suite>.log)
# Each suite prints its own "<n> checks, <m> failures|failed" line; the last such line is taken.
# Exit status 1 if any suite exits non-zero, shows failures, or prints no summary.
out=$1; shift
total=0; fails=0; nsuite=0; bad=0; skips=0
for s in "$@"; do
	log=$out/$s.log
	"$out/$s" > "$log" 2>&1
	rc=$?
	line=$(grep -E '[0-9]+ checks, [0-9]+ fail' "$log" | tail -n 1)
	n=$(echo "$line" | sed -n 's/.* \([0-9][0-9]*\) checks, .*/\1/p')
	f=$(echo "$line" | sed -n 's/.*checks, \([0-9][0-9]*\) fail.*/\1/p')
	if [ -z "$n" ]; then n=0; f=0; rc=${rc:-1}; [ "$rc" = 0 ] && rc=1; fi
	sk=$(grep -c '^ *SKIP' "$log")
	skips=$((skips + sk))
	status=ok
	if [ "$rc" != 0 ] || [ "$f" != 0 ]; then status=FAILED; bad=1; grep -E '^FAIL|Sanitizer|runtime error' "$log" | head -n 20; fi
	printf '  %-12s %8d checks, %d failures  [%s, exit %d]%s\n' "$s" "$n" "$f" "$status" "$rc" "$([ "$sk" != 0 ] && echo "  $sk SKIP")"
	total=$((total + n)); fails=$((fails + f)); nsuite=$((nsuite + 1))
done
if [ $bad = 0 ]; then verdict=PASS; else verdict=FAIL; fi
echo "TOTAL: $nsuite suites, $total checks, $fails failures -- $verdict"
[ $skips = 0 ] || echo "SKIPPED: $skips capture based parts (set IMSD_TEST_CAPDIR; details: grep SKIP <outdir>/*.log)"
[ $bad = 0 ]
