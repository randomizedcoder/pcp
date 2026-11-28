"""Parse cppcheck text reports.

The pcp-analysis-cppcheck template gives one line per finding:
    src/libpcp/src/p_result.c:495:13: error: message [checkId]
"""

import re

from finding import Finding, normalize_path, normalize_severity


_LINE_RE = re.compile(r'^(.+?):(\d+):(\d+): (\w+): (.*) \[([^\]]+)\]$')


def parse(path: str) -> list[Finding]:
    findings = []
    try:
        with open(path, errors='replace') as f:
            for line in f:
                m = _LINE_RE.match(line.rstrip('\n'))
                if m:
                    findings.append(Finding(
                        tool='cppcheck',
                        check_id=m.group(6),
                        severity=normalize_severity(m.group(4)),
                        file=normalize_path(m.group(1)),
                        line=int(m.group(2)),
                        message=m.group(5),
                    ))
    except FileNotFoundError:
        pass
    return findings
