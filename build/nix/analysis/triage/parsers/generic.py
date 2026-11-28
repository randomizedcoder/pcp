"""Generic line-based parser for tools with simple output formats.

Handles tools that output in formats like:
    /path/to/file:123: message
    /path/to/file:123:45: message [check-id]
    /path/to/file:123: severity: message

Used for: coccinelle, shellcheck, ruff, bandit.
"""

import re

from finding import Finding, normalize_path, normalize_severity


# Pattern: file:line:col: severity: message [check-id]
# Also handles cpplint's double-bracket `[category] [priority]` tail by
# allowing an optional trailing `[digits]` priority after the check-id.
_FULL_RE = re.compile(
    r'^(.+?):(\d+)(?::\d+)?:\s*(?:(error|warning|note|info|style|convention|refactor))?\s*:?\s*(.+?)(?:\s+\[([^\]]+)\])?(?:\s+\[\d+\])?$'
)

# Pattern: file:line: message (check-id)
_PAREN_RE = re.compile(
    r'^(.+?):(\d+)(?::\d+)?:\s*(.+?)\s+\(([^)]+)\)\s*$'
)

# Ruff pattern: file:line:col: CODE message
_RUFF_RE = re.compile(
    r'^(.+?):(\d+):\d+:\s+([A-Z]+\d+)\s+(.+)$'
)


def parse(path: str, tool_name: str) -> list[Finding]:
    """Parse a generic line-based report."""
    findings = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('==='):
                    continue

                finding = _try_parse_line(line, tool_name)
                if finding:
                    findings.append(finding)
    except FileNotFoundError:
        pass
    return findings


def _try_parse_line(line: str, tool_name: str) -> Finding | None:
    """Try to parse a single line using multiple patterns."""

    # Try ruff pattern first (most specific)
    m = _RUFF_RE.match(line)
    if m:
        return Finding(
            tool=tool_name,
            check_id=m.group(3),
            severity='warning',
            file=normalize_path(m.group(1)),
            line=int(m.group(2)),
            message=m.group(4),
        )

    # Try parenthesized check-id pattern (cpplint, pylint)
    m = _PAREN_RE.match(line)
    if m:
        return Finding(
            tool=tool_name,
            check_id=m.group(4),
            severity='warning',
            file=normalize_path(m.group(1)),
            line=int(m.group(2)),
            message=m.group(3),
        )

    # Try full pattern with optional severity and check-id
    m = _FULL_RE.match(line)
    if m:
        sev = m.group(3) or 'warning'
        check_id = m.group(5) or f'{tool_name}-generic'
        return Finding(
            tool=tool_name,
            check_id=check_id,
            severity=normalize_severity(sev),
            file=normalize_path(m.group(1)),
            line=int(m.group(2)),
            message=m.group(4),
        )

    return None
