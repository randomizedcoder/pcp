# pcp-fuzz-runner <bindir> <corpus> [outdir]
# shellcheck shell=bash
#
# Runs every fuzz_* harness in bindir (except fuzz_selftest), one after
# another, seeded from corpus/<harness>/.  Then it runs each crash input
# again and keeps one per sanitizer SUMMARY line.
# Used by pcp-fuzz (bin/pcp-run-fuzzers), pcp-fuzz-run and pcp-fuzz-deep.
#
# outdir (default $FUZZ_WORKDIR, else a new temporary directory) gets:
#   <harness>/           working corpus, and the crash-* inputs found
#   <harness>.log        libFuzzer output
#   crashes/<harness>/   crash-<sig> and repro-<sig>.txt per distinct crash
#   summary.txt          per harness: coverage, crash inputs, distinct crashes
#   count.txt            all crash inputs; distinct_count.txt: distinct crashes
#
# Environment:
#   FUZZ_TIME     seconds per harness (60)
#   FUZZ_FORKS    libFuzzer -fork= jobs, with -ignore_crashes=1 (0: in-process)
#   FUZZ_MAXLEN   libFuzzer -max_len=
#   FUZZ_DICTDIR  directory of <harness>.dict files (used when present)
#   FUZZ_ONLY     space separated harness names to run (default: all)
#   FUZZ_LEAKS    1 to turn on LeakSanitizer (default off)
#   FUZZ_TIMEOUT  seconds one input may run before it counts as a hang (default 10)

bindir=$1
corpus=$2
out=${3:-${FUZZ_WORKDIR:-$(mktemp -d)}}
time=${FUZZ_TIME:-60}
forks=${FUZZ_FORKS:-0}

args=(-max_total_time="$time" -timeout="${FUZZ_TIMEOUT:-10}")
if [ "$forks" -gt 0 ]; then
	args+=(-fork="$forks" -ignore_crashes=1)
fi
if [ -n "${FUZZ_MAXLEN:-}" ]; then
	args+=(-max_len="$FUZZ_MAXLEN")
fi
export ASAN_OPTIONS=abort_on_error=0:detect_leaks=${FUZZ_LEAKS:-0}:symbolize=1
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1

mkdir -p "$out/crashes"
echo "=== PCP fuzzers: ${time} s per harness, ${forks} fork(s) ===" >"$out/summary.txt"
total=0
distinct=0
for bin in "$bindir"/fuzz_*; do
	name=$(basename "$bin")
	[ "$name" = fuzz_selftest ] && continue
	if [ -n "${FUZZ_ONLY:-}" ] && [[ " $FUZZ_ONLY " != *" $name "* ]]; then
		continue
	fi
	work=$out/$name
	mkdir -p "$work"
	if [ -d "$corpus/$name" ]; then
		cp -rn "$corpus/$name"/. "$work/" 2>/dev/null || true
		chmod -R u+w "$work"
	fi
	hargs=("${args[@]}")
	dict=${FUZZ_DICTDIR:-}/$name.dict
	if [ -n "${FUZZ_DICTDIR:-}" ] && [ -f "$dict" ]; then
		hargs+=(-dict="$dict")
	fi
	# The hard timeout stops a hung crash report from blocking the run.
	timeout -s KILL $((time + 300)) \
		"$bin" "${hargs[@]}" -artifact_prefix="$work/" "$work" >"$out/$name.log" 2>&1 || true

	# One crash kept per signature: the SUMMARY line, without addresses.
	declare -A seen=()
	crashes=0
	kept=0
	while IFS= read -r crash; do
		crashes=$((crashes + 1))
		sig=$(timeout -s KILL 120 "$bin" -timeout="${FUZZ_TIMEOUT:-10}" "$crash" 2>&1 | grep -m 1 -oE 'SUMMARY: .*' | sed 's/0x[0-9a-f]*//g' || true)
		sig=${sig:-unknown-$crashes}
		hash=$(printf '%s' "$sig" | cksum | cut -d ' ' -f 1)
		if [ -z "${seen[$hash]:-}" ]; then
			seen[$hash]=1
			kept=$((kept + 1))
			mkdir -p "$out/crashes/$name"
			cp "$crash" "$out/crashes/$name/crash-$hash"
			timeout -s KILL 120 "$bin" -timeout="${FUZZ_TIMEOUT:-10}" "$crash" >"$out/crashes/$name/repro-$hash.txt" 2>&1 || true
		fi
	done < <(find "$work" -maxdepth 1 \( -name 'crash-*' -o -name 'leak-*' -o -name 'oom-*' -o -name 'timeout-*' \))
	unset seen

	cov=$(grep -oE 'cov: [0-9]+' "$out/$name.log" | tail -n 1 || true)
	printf '  %-20s %-10s %s crash input(s), %s distinct\n' \
		"$name:" "${cov:-cov: ?}" "$crashes" "$kept" | tee -a "$out/summary.txt"
	total=$((total + crashes))
	distinct=$((distinct + kept))
done
{
	echo
	echo "Total crash inputs: $total   Distinct crashes: $distinct   (in $out)"
} | tee -a "$out/summary.txt"
echo "$total" >"$out/count.txt"
echo "$distinct" >"$out/distinct_count.txt"
