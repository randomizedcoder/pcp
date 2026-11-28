"""Noise constants, path classifiers, filtering, and deduplication."""

from finding import Finding


# Directories containing third-party code
THIRD_PARTY_PATTERNS = [
    'vendor/', 'src/external/', '/deps/', '/nix/store/',
]

# Generated files -- findings are not actionable
GENERATED_FILE_PATTERNS = [
    '.tab.c', '.tab.h', 'lex.yy.c', '/lex.',
    '<stdout>', '<stdin>',
]

EXCLUDED_CHECK_IDS = {
    # Known false positive categories
    'normalCheckLevelMaxBranches',
    # Cppcheck noise
    'missingIncludeSystem',
    'missingInclude',
    'unmatchedSuppression',
    'checkersReport',
    # Clang-tidy build errors (not real findings)
    'clang-diagnostic-error',
    # _FORTIFY_SOURCE warnings (build config, not code bugs)
    '-W#warnings',
    '-Wcpp',
}

EXCLUDED_MESSAGE_PATTERNS = [
    '_FORTIFY_SOURCE',
]

# Paths indicating test code
TEST_PATH_PATTERNS = [
    'qa/', '/test/', '/tests/', '_test.', '/test_', 'build/nix/fuzz/',
]

# Paths in security/privilege-sensitive areas
# (network facing daemons, PDU decoding, authentication, privileged PMDAs)
SECURITY_PATHS = [
    'src/pmcd/', 'src/pmproxy/', 'src/pmlogger/', 'src/pmdas/root/',
    'src/libpcp/src/p_', 'src/libpcp/src/pdu', 'src/libpcp/src/auth',
    'src/libpcp/src/secure', 'src/libpcp/src/endian', 'src/libpcp_web/',
    'src/libpcp_pmcd/',
]


def is_generated(path: str) -> bool:
    return any(pat in path for pat in GENERATED_FILE_PATTERNS)


def is_third_party(path: str) -> bool:
    return any(pat in path for pat in THIRD_PARTY_PATTERNS)


def is_test_code(path: str) -> bool:
    return any(pat in path for pat in TEST_PATH_PATTERNS)


def is_security_sensitive(path: str) -> bool:
    return any(pat in path for pat in SECURITY_PATHS)


def filter_findings(findings: list[Finding]) -> list[Finding]:
    """Remove third-party code and known false positive categories."""
    return [
        f for f in findings
        if not is_third_party(f.file)
        and not is_generated(f.file)
        and f.check_id not in EXCLUDED_CHECK_IDS
        and f.line > 0
        and not any(pat in f.message for pat in EXCLUDED_MESSAGE_PATTERNS)
    ]


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings by (file, line, check_id).

    clang-tidy reports the same header finding once per translation unit.
    Keep first occurrence only.
    """
    seen = set()
    result = []
    for f in findings:
        key = f.dedup_key()
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result
