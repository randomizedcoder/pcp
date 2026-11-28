"""Priority scoring, cross-tool correlation, and high-confidence filtering."""

from collections import defaultdict

from finding import Finding
from filters import is_security_sensitive, is_test_code


# flawfinder check_ids that are intentional patterns in systems software
FLAWFINDER_NOISE = {
    'race.chmod', 'race.chown', 'race.access', 'race.vfork',
    'shell.system', 'shell.execl', 'shell.execlp', 'shell.execv', 'shell.execvp',
    'buffer.read', 'buffer.char', 'buffer.equal', 'buffer.memcpy',
    'buffer.strlen', 'buffer.getenv', 'buffer.wchar_t',
    'misc.open', 'random.random', 'tmpfile.mkstemp', 'access.umask',
    'format.snprintf', 'format.vsnprintf', 'misc.chroot',
}

# cppcheck checks for "malloc() may return NULL" paths: true, but there
# are thousands and they hide the real bugs.
CPPCHECK_NOISE = {
    'nullPointerOutOfMemory', 'nullPointerArithmeticOutOfMemory',
    'ctunullpointerOutOfMemory',
}

NOISE_CHECKS = FLAWFINDER_NOISE | CPPCHECK_NOISE


def without_noise(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.check_id not in NOISE_CHECKS]


# Bug-class check IDs that represent real correctness issues (not style)
BUG_CLASS_CHECKS = {
    # cppcheck
    'nullPointer', 'nullPointerRedundantCheck', 'nullPointerArithmetic',
    'doubleFree', 'memleak', 'memleakOnRealloc', 'resourceLeak',
    'deallocuse', 'uninitvar', 'legacyUninitvar', 'uninitdata',
    'bufferAccessOutOfBounds', 'arrayIndexOutOfBounds', 'negativeIndex',
    'invalidFunctionArg', 'zerodiv', 'shiftTooManyBitsSigned',
    'identicalInnerCondition', 'IOWithoutPositioning',
    # clang-tidy
    'bugprone-use-after-move', 'bugprone-sizeof-expression',
    'bugprone-not-null-terminated-result', 'bugprone-signed-char-misuse',
    'bugprone-suspicious-memset-usage', 'bugprone-misplaced-widening-cast',
    'bugprone-infinite-loop',
    # gcc warnings
    '-Wformat-overflow=', '-Wformat-truncation=', '-Wnull-dereference',
    '-Wduplicated-cond', '-Wduplicated-branches', '-Wlogical-op',
    '-Wrestrict', '-Wstringop-overflow=', '-Wstringop-truncation',
    '-Warray-bounds=', '-Wuse-after-free=', '-Wmaybe-uninitialized',
    # coccinelle
    'cocci.use-after-free', 'cocci.double-free', 'cocci.alloc-no-check',
    # scan-build report types (not the dead store ones)
    'scan-build.dereference-of-null-pointer', 'scan-build.memory-leak',
    'scan-build.use-after-free', 'scan-build.double-free',
    'scan-build.dereference-of-undefined-pointer-value',
    'scan-build.assigned-value-is-uninitialized',
    'scan-build.uninitialized-argument-value',
    'scan-build.result-of-operation-is-garbage-or-undefined',
    'scan-build.branch-condition-evaluates-to-a-garbage-value',
    'scan-build.argument-with-nonnull-attribute-passed-null',
    'scan-build.called-function-pointer-is-null-null-dereference',
    'scan-build.resource-leak', 'scan-build.use-of-zero-allocated',
    'scan-build.allocator-sizeof-operand-mismatch',
}

# Substrings of check IDs that are bug classes, whatever the tool:
# clang analyzer (core.NullDereference, unix.Malloc ...), gcc -fanalyzer
# (-Wanalyzer-*) and fuzzer crashes.
BUG_CLASS_PATTERNS = (
    'core.', 'unix.Malloc', 'unix.MismatchedDeallocator', 'security.',
    '-Wanalyzer-', 'fuzz.',
)

# Substrings of the bug classes that are high confidence on their own,
# without a second tool: memory safety, and fuzzer crashes.
STRONG_BUG_PATTERNS = (
    'use-after-free', 'double-free', 'doubleFree', 'deallocuse',
    'out-of-bounds', 'OutOfBounds', 'fuzz.',
)

# Tools that use the same engine, or both match call patterns, are one
# family: their agreement is not a second opinion.
TOOL_FAMILY = {
    'flawfinder': 'pattern', 'semgrep': 'pattern',
    'clang-tidy': 'clang', 'scan-build': 'clang',
}


# Matches of the patterns above that are not bugs: clang's insecureAPI
# checks only say a call (strcpy, sprintf ...) is used.
NOT_BUG_PATTERNS = ('insecureAPI',)


def is_bug_class(check_id: str) -> bool:
    if any(p in check_id for p in NOT_BUG_PATTERNS):
        return False
    return (check_id in BUG_CLASS_CHECKS
            or any(p in check_id for p in BUG_CLASS_PATTERNS))


def is_strong_bug(check_id: str) -> bool:
    return is_bug_class(check_id) and any(p in check_id for p in STRONG_BUG_PATTERNS)


def family(tool: str) -> str:
    return TOOL_FAMILY.get(tool, tool)


# Style checks excluded from high-confidence
STYLE_ONLY_CHECKS = {
    'constParameterPointer', 'constVariablePointer', 'shadowVariable',
    'shadowArgument', 'shadowFunction', 'knownConditionTrueFalse',
    'unusedStructMember', 'variableScope', 'unreadVariable',
}

# Prefixes excluded from high-confidence output
_HIGH_CONF_EXCLUDED_PREFIXES = (
    'readability-', 'modernize-', 'performance-',
    'misc-include-cleaner', 'misc-use-internal-linkage',
    'misc-unused-parameters', 'misc-const-correctness',
    'misc-header-include-cycle', 'misc-no-recursion',
    'cert-',
)

# Lint tools: their findings are in the full report and the per tool
# reports, but not in the high-confidence list.
_HIGH_CONF_EXCLUDED_TOOLS = {'ruff', 'shellcheck'}


def priority_score(f: Finding, category_counts: dict[str, int]) -> int:
    """Higher score = higher priority. Range roughly 0-135."""
    score = 0

    # Severity
    if f.severity == 'error':
        score += 40
    elif f.severity == 'warning':
        score += 20

    # Correctness bug classes (null deref, leak, overflow ...) over style
    if is_bug_class(f.check_id):
        score += 25

    # Security-sensitive location
    if is_security_sensitive(f.file):
        score += 20

    # Test code is lower priority
    if is_test_code(f.file):
        score -= 15

    # Small-count categories are anomalies (more likely real bugs)
    count = category_counts.get(f.check_id, 999)
    if count <= 3:
        score += 30
    elif count <= 10:
        score += 20
    elif count <= 30:
        score += 10

    return score


def find_cross_tool_hits(findings: list[Finding], tolerance: int = 3) -> list[list[Finding]]:
    """Find file:line pairs flagged by 2+ independent tool families.

    Uses a tolerance of +/-N lines to account for minor line number differences.
    """
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_file[f.file].append(f)

    clusters = []
    for file_findings in by_file.values():
        file_findings.sort(key=lambda f: f.line)

        for i, f1 in enumerate(file_findings):
            cluster = [f1]
            for f2 in file_findings[i + 1:]:
                if f2.line > f1.line + tolerance:
                    break
                if family(f2.tool) != family(f1.tool):
                    cluster.append(f2)
            if len(set(family(f.tool) for f in cluster)) >= 2:
                clusters.append(cluster)

    # Deduplicate overlapping clusters
    seen_keys = set()
    unique_clusters = []
    for cluster in clusters:
        key = frozenset((f.tool, f.file, f.line) for f in cluster)
        if key not in seen_keys:
            seen_keys.add(key)
            unique_clusters.append(cluster)

    return unique_clusters


def get_high_confidence(findings: list[Finding]) -> list[tuple]:
    """Return high-confidence findings as (Finding, score, is_cross) tuples."""
    cat_counts = defaultdict(int)
    for f in findings:
        cat_counts[f.check_id] += 1

    # A second tool family near a bug class finding backs it up.
    cross_hits = find_cross_tool_hits(without_noise(findings))
    cross_locations = set()
    for cluster in cross_hits:
        if not any(is_bug_class(f.check_id) for f in cluster):
            continue
        for f in cluster:
            cross_locations.add((f.file, f.line))

    high_conf = []
    for f in findings:
        if f.check_id in NOISE_CHECKS or f.check_id in STYLE_ONLY_CHECKS:
            continue
        if f.tool in _HIGH_CONF_EXCLUDED_TOOLS:
            continue
        if any(f.check_id.startswith(p) for p in _HIGH_CONF_EXCLUDED_PREFIXES):
            continue

        score = priority_score(f, cat_counts)
        is_cross = (f.file, f.line) in cross_locations
        bug = is_bug_class(f.check_id)
        if is_cross:
            score += 20
        is_security_bug = (is_security_sensitive(f.file) and f.severity == 'error'
                           and f.tool in ('cppcheck', 'scan-build', 'gcc-analyzer', 'fuzz'))

        # memory safety on its own; other bug classes need a second tool
        # family or an error in a security sensitive path
        if is_strong_bug(f.check_id) or (bug and (is_cross or is_security_bug)):
            high_conf.append((f, score, is_cross))

    high_conf.sort(key=lambda x: -x[1])
    return high_conf
