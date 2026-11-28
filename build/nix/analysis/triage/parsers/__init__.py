"""Load the findings of every tool report in an analysis result.

The result is a pcp-analysis-<tier> output: one directory per tool,
each with report.txt.  A pcp-fuzz-run result linked as fuzz-run/ (in
pcp-analysis-all) adds the fuzzer crashes.
"""

from pathlib import Path

from finding import Finding
from parsers import cppcheck, clang, flawfinder, generic, fuzz, semgrep


# tool directory -> parser for its report.txt
_TEXT_PARSERS = {
    'cppcheck': lambda p: cppcheck.parse(p),
    'clang-tidy': lambda p: clang.parse(p, 'clang-tidy'),
    'scan-build': lambda p: clang.parse(p, 'scan-build'),
    'gcc-analyzer': lambda p: clang.parse(p, 'gcc-analyzer'),
    'gcc-warnings': lambda p: clang.parse(p, 'gcc-warnings'),
    'flawfinder': lambda p: flawfinder.parse(p),
    'coccinelle': lambda p: generic.parse(p, 'coccinelle'),
    'shellcheck': lambda p: generic.parse(p, 'shellcheck'),
    'ruff': lambda p: generic.parse(p, 'ruff'),
    'bandit': lambda p: generic.parse(p, 'bandit'),
}


def load_all_findings(result_dir: str) -> list[Finding]:
    """Load findings from all available tool reports."""
    findings = []
    rd = Path(result_dir)

    for tool, parse in _TEXT_PARSERS.items():
        p = rd / tool / 'report.txt'
        if p.exists():
            findings.extend(parse(str(p)))

    p = rd / 'semgrep' / 'report.json'
    if p.exists():
        findings.extend(semgrep.parse(str(p)))

    findings.extend(fuzz.parse(result_dir))
    return findings
