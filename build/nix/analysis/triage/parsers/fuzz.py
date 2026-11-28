"""Parse libFuzzer crash results from pcp-fuzz-run (or pcp-fuzz-deep).

run-fuzzers.sh keeps one input per distinct crash:
    crashes/<harness>/crash-<hash>
    crashes/<harness>/repro-<hash>.txt   sanitizer report for that input

Each distinct crash is an "error" finding at the first stack frame in
PCP code (not the harness).  The check ID is fuzz.<harness>.<kind>, where
kind comes from the sanitizer SUMMARY line (heap-buffer-overflow,
undefined-behavior, ...).
"""

import re
from pathlib import Path

from finding import Finding, normalize_path

# "#0 0x55d5 in __pmDecodeValueSet /build/source/src/libpcp/src/p_result.c:495:13"
_FRAME_RE = re.compile(r'#\d+ 0x[0-9a-f]+ in \S+ (\S+?):(\d+)(?::\d+)?$', re.M)
# UBSan: "src/libpcp/src/spec.c:113:9: runtime error: ..."
_UBSAN_RE = re.compile(r'^(\S+?):(\d+):\d+: runtime error: ', re.M)
_SUMMARY_RE = re.compile(r'SUMMARY: \w+: ([\w-]+)')
_BUILD_ROOT = '/build/source/'


def _rel(path: str) -> str:
    if path.startswith(_BUILD_ROOT):
        path = path[len(_BUILD_ROOT):]
    return normalize_path(path)


def _location(text: str) -> tuple[str, int]:
    """First PCP source location in the report, else ("", 0)."""
    candidates = [(m.start(), m.group(1), int(m.group(2)))
                  for r in (_UBSAN_RE, _FRAME_RE) for m in r.finditer(text)]
    for _, path, line in sorted(candidates):
        rel = _rel(path)
        if rel.startswith('src/') and 'fuzz_' not in rel:
            return rel, line
    return '', 0


def parse(result_dir: str) -> list[Finding]:
    findings: list[Finding] = []
    root = Path(result_dir)
    crashes = root / 'fuzz-run' / 'crashes'
    if not crashes.is_dir():
        crashes = root / 'crashes'     # a pcp-fuzz-run result given directly
    if not crashes.is_dir():
        return findings

    for hdir in sorted(p for p in crashes.iterdir() if p.is_dir()):
        harness = hdir.name
        for crash in sorted(hdir.glob('crash-*')):
            sig = crash.name[len('crash-'):]
            repro = hdir / f'repro-{sig}.txt'
            text = repro.read_text(errors='replace') if repro.exists() else ''
            path, line = _location(text)
            m = _SUMMARY_RE.search(text)
            kind = m.group(1) if m else 'crash'
            findings.append(Finding(
                tool='fuzz',
                check_id=f'fuzz.{harness}.{kind}',
                severity='error',
                file=path or f'build/nix/fuzz/harness/{harness}.c',
                line=line or 1,
                message=f'{harness} input {crash.name} crashes ({kind}); '
                        f'see crashes/{harness}/{repro.name}',
            ))
    return findings
