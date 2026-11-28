"""Parse clang-tidy, scan-build, gcc-warnings, and gcc-analyzer reports.

All four reports share the same text line format:
    src/libpcp/src/pdu.c:123:45: warning: message [check-name]
"""

import re

from finding import Finding, normalize_path, normalize_severity


_LINE_RE = re.compile(
    r'^(.+?):(\d+):\d+:\s+(warning|error):\s+(.+?)\s+\[([^\]]+)\]$'
)


def parse(path: str, tool_name: str) -> list[Finding]:
    """Parse a clang-style diagnostic text report."""
    findings = []
    try:
        with open(path) as f:
            for line in f:
                m = _LINE_RE.match(line.strip())
                if m:
                    findings.append(Finding(
                        tool=tool_name,
                        check_id=m.group(5),
                        severity=normalize_severity(m.group(3)),
                        file=normalize_path(m.group(1)),
                        line=int(m.group(2)),
                        message=m.group(4),
                    ))
    except FileNotFoundError:
        pass
    return findings
