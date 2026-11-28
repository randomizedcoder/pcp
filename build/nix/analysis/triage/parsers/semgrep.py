"""Parse semgrep JSON reports."""

import json

from finding import Finding, normalize_path, normalize_severity


def parse(path: str) -> list[Finding]:
    """Parse semgrep JSON report."""
    findings = []
    try:
        with open(path) as f:
            content = f.read()
    except FileNotFoundError:
        return findings

    # Parse all JSON objects in the file (semgrep may output multiple)
    decoder = json.JSONDecoder()
    pos = 0
    while pos < len(content):
        try:
            idx = content.index('{', pos)
            data, end = decoder.raw_decode(content, idx)
            pos = end
        except (ValueError, json.JSONDecodeError):
            break

        for result in data.get('results', []):
            findings.append(Finding(
                tool='semgrep',
                # rules.semgrep-c.unsafe-sprintf -> semgrep.unsafe-sprintf
                check_id='semgrep.' + result.get('check_id', '').rsplit('.', 1)[-1],
                severity=normalize_severity(result.get('extra', {}).get('severity', 'warning')),
                file=normalize_path(result.get('path', '')),
                line=result.get('start', {}).get('line', 0),
                message=result.get('extra', {}).get('message', ''),
            ))

    return findings
