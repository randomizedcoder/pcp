"""Triage PCP static analysis findings across tools.

Ported from the rocm-systems nix analysis triage engine.  Normally run
by the pcp-analysis-<tier> builds (result/triage/), or by hand:

    nix run .#pcp-analysis-triage -- result/                    # full report
    nix run .#pcp-analysis-triage -- result/ --summary          # categories
    nix run .#pcp-analysis-triage -- result/ --high-confidence  # likely bugs
    nix run .#pcp-analysis-triage -- result/ --cross-ref        # multi-tool
    nix run .#pcp-analysis-triage -- result/ --category <name>  # one check
    nix run .#pcp-analysis-triage -- result/ --new-only         # un-triaged

Known findings are kept in build/nix/analysis/anomalies.toml.
"""

import argparse
import os
import sys

from parsers import load_all_findings
from filters import filter_findings, deduplicate, is_test_code
from anomalies import load_anomalies, apply_anomalies
from reporter import (
    print_summary, print_high_confidence, print_cross_ref,
    print_category, print_full_report, write_all_reports,
)

ANOMALIES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              '..', 'anomalies.toml')


def main():
    parser = argparse.ArgumentParser(
        description='Triage static analysis findings across multiple tools.'
    )
    parser.add_argument('result_dir', help='Path to analysis results directory')
    parser.add_argument('--summary', action='store_true',
                        help='Show category summary')
    parser.add_argument('--high-confidence', action='store_true',
                        help='Show only likely-real-bug findings')
    parser.add_argument('--cross-ref', action='store_true',
                        help='Show multi-tool correlations')
    parser.add_argument('--category', type=str,
                        help='Drill into a specific check category')
    parser.add_argument('--new-only', action='store_true',
                        help='Show only un-triaged findings (for CI gating)')
    parser.add_argument('--output-dir', type=str,
                        help='Write all reports as files to this directory')
    parser.add_argument('--include-test', action='store_true',
                        help='Include test code findings (excluded by default in high-confidence)')
    parser.add_argument('--source-root', type=str,
                        help='Path to source tree for anomaly anchor matching')
    parser.add_argument('--anomalies-file', type=str,
                        help='Path to anomalies.toml (default: bundled)')
    parser.add_argument('--no-anomalies', action='store_true',
                        help='Skip known anomaly matching (no suppression)')

    args = parser.parse_args()

    if not os.path.isdir(args.result_dir):
        print(f'Error: {args.result_dir} is not a directory', file=sys.stderr)
        sys.exit(1)

    # Load, filter, deduplicate
    raw = load_all_findings(args.result_dir)
    filtered = filter_findings(raw)
    deduped = deduplicate(filtered)

    # Apply known anomaly matching
    suppressed = []
    flagged = []
    findings = deduped

    anomalies_path = args.anomalies_file or ANOMALIES_FILE
    if not args.no_anomalies and args.source_root and os.path.isfile(anomalies_path):
        anomalies = load_anomalies(anomalies_path)
        findings, suppressed, flagged = apply_anomalies(deduped, anomalies, args.source_root)

    parts = [f'Loaded {len(raw)} raw -> {len(filtered)} filtered -> {len(deduped)} dedup']
    if suppressed or flagged:
        parts.append(f' -> {len(findings)} after anomalies '
                     f'({len(suppressed)} suppressed, {len(flagged)} flagged)')
    print(''.join(parts))

    if args.new_only:
        # Only show findings NOT in anomalies.toml (for CI gating)
        print(f'\n=== New/Un-triaged Findings ({len(findings)}) ===\n')
        for f in findings:
            print(f'  {f.tool}: {f.file}:{f.line}: [{f.severity}] {f.check_id} -- {f.message}')
        if not findings:
            print('  No new findings. All known issues are triaged.')
        sys.exit(0 if len(findings) == 0 else 1)

    if args.output_dir:
        write_all_reports(findings, args.output_dir, suppressed, flagged)
    elif args.summary:
        print_summary(findings)
    elif args.high_confidence:
        if not args.include_test:
            findings = [f for f in findings if not is_test_code(f.file)]
        print_high_confidence(findings)
    elif args.cross_ref:
        print_cross_ref(findings)
    elif args.category:
        print_category(findings, args.category)
    else:
        print_full_report(findings)


if __name__ == '__main__':
    main()
