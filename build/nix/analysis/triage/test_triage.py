"""Table driven tests for the triage parsers, filters, scoring, anomaly
matching, diagpaths.py and ccwrap.py.  Run: nix build .#pcp-analysis-triage-test
(or, in this directory, python3 -m unittest -v test_triage).
"""

import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import ccwrap                                       # noqa: E402
import diagpaths                                    # noqa: E402
from anomalies import Anomaly, apply_anomalies      # noqa: E402
from filters import filter_findings, deduplicate    # noqa: E402
from finding import Finding, normalize_path, normalize_severity  # noqa: E402
from parsers import clang, cppcheck, flawfinder, fuzz, generic  # noqa: E402
from scoring import is_bug_class, get_high_confidence  # noqa: E402


def write(dirpath, name, text):
    path = os.path.join(dirpath, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(text)
    return path


def parse_line(parser, line):
    """Run a file parser on one line; returns the findings."""
    with tempfile.TemporaryDirectory() as d:
        return parser(write(d, 'report.txt', line + '\n'))


def key(f):
    return (f.tool, f.check_id, f.severity, f.file, f.line) if f else None


class TestParsers(unittest.TestCase):
    CASES = [
        {
            'description': 'cppcheck text template',
            'parser': cppcheck.parse,
            'line': 'src/libpcp/src/pdu.c:12:5: error: Null pointer [nullPointer]',
            'expected': ('cppcheck', 'nullPointer', 'error', 'src/libpcp/src/pdu.c', 12),
        },
        {
            'description': 'cppcheck portability maps to warning',
            'parser': cppcheck.parse,
            'line': 'src/a.c:3:1: portability: msg [fflushOnInputStream]',
            'expected': ('cppcheck', 'fflushOnInputStream', 'warning', 'src/a.c', 3),
        },
        {
            'description': 'cppcheck line without a check id is ignored',
            'parser': cppcheck.parse,
            'line': 'src/a.c:3:1: error: no id here',
            'expected': None,
        },
        {
            'description': 'gcc-analyzer line with CWE and flag',
            'parser': lambda p: clang.parse(p, 'gcc-analyzer'),
            'line': "src/include/pcp/sds.h:99:28: warning: dereference of NULL 's' "
                    "[CWE-476] [-Wanalyzer-null-dereference]",
            'expected': ('gcc-analyzer', '-Wanalyzer-null-dereference', 'warning',
                         'src/include/pcp/sds.h', 99),
        },
        {
            'description': 'clang-tidy with /build/source prefix',
            'parser': lambda p: clang.parse(p, 'clang-tidy'),
            'line': '/build/source/src/pmcd/src/pmcd.c:7:2: warning: x [bugprone-branch-clone]',
            'expected': ('clang-tidy', 'bugprone-branch-clone', 'warning', 'src/pmcd/src/pmcd.c', 7),
        },
        {
            'description': 'scan-build line with the report name before the id',
            'parser': lambda p: clang.parse(p, 'scan-build'),
            'line': 'src/a.c:9:3: warning: Null deref (report-1.html) '
                    '[scan-build.dereference-of-null-pointer]',
            'expected': ('scan-build', 'scan-build.dereference-of-null-pointer', 'warning',
                         'src/a.c', 9),
        },
        {
            'description': 'flawfinder singleline',
            'parser': flawfinder.parse,
            'line': 'src/a.c:44:7:  [4] (buffer) strcpy:Does not check for buffer overflows',
            'expected': ('flawfinder', 'buffer.strcpy', 'error', 'src/a.c', 44),
        },
        {
            'description': 'shellcheck gcc format',
            'parser': lambda p: generic.parse(p, 'shellcheck'),
            'line': 'src/pmlogger/pmlogger_check.sh:10:5: warning: Quote this. [SC2086]',
            'expected': ('shellcheck', 'SC2086', 'warning', 'src/pmlogger/pmlogger_check.sh', 10),
        },
        {
            'description': 'ruff concise format',
            'parser': lambda p: generic.parse(p, 'ruff'),
            'line': 'src/python/pcp/pmapi.py:3:8: F401 [*] `os` imported but unused',
            'expected': ('ruff', 'F401', 'warning', 'src/python/pcp/pmapi.py', 3),
        },
        {
            'description': 'coccinelle rule output',
            'parser': lambda p: generic.parse(p, 'coccinelle'),
            'line': 'src/a.c:5:32: warning: p is used after free() at line 5 [cocci.use-after-free]',
            'expected': ('coccinelle', 'cocci.use-after-free', 'warning', 'src/a.c', 5),
        },
        {
            'description': 'bandit custom template',
            'parser': lambda p: generic.parse(p, 'bandit'),
            'line': 'src/pcp/x/pcp-x.py:20:4: warning: [HIGH] shell=True [B602]',
            'expected': ('bandit', 'B602', 'warning', 'src/pcp/x/pcp-x.py', 20),
        },
        {
            'description': 'empty line gives no finding',
            'parser': lambda p: generic.parse(p, 'shellcheck'),
            'line': '',
            'expected': None,
        },
    ]

    def test_parsers(self):
        for c in self.CASES:
            with self.subTest(c['description']):
                got = parse_line(c['parser'], c['line'])
                self.assertEqual(key(got[0]) if got else None, c['expected'])


class TestNormalize(unittest.TestCase):
    PATHS = [
        {'description': 'nix store source prefix',
         'input': '/nix/store/abc123-source/src/a.c', 'expected': 'src/a.c'},
        {'description': 'nix build directory', 'input': '/build/source/src/a.c',
         'expected': 'src/a.c'},
        {'description': 'leading ./', 'input': './src/a.c', 'expected': 'src/a.c'},
        {'description': 'already relative', 'input': 'src/a.c', 'expected': 'src/a.c'},
    ]
    SEVERITIES = [
        {'description': 'error', 'input': 'error', 'expected': 'error'},
        {'description': 'semgrep ERROR', 'input': 'ERROR', 'expected': 'error'},
        {'description': 'flawfinder level 5', 'input': '5', 'expected': 'error'},
        {'description': 'performance', 'input': 'performance', 'expected': 'warning'},
        {'description': 'note is style', 'input': 'info', 'expected': 'style'},
        {'description': 'unknown is warning', 'input': 'odd', 'expected': 'warning'},
    ]

    def test_paths(self):
        for c in self.PATHS:
            with self.subTest(c['description']):
                self.assertEqual(normalize_path(c['input']), c['expected'])

    def test_severities(self):
        for c in self.SEVERITIES:
            with self.subTest(c['description']):
                self.assertEqual(normalize_severity(c['input']), c['expected'])


def F(tool='cppcheck', check='nullPointer', sev='error', path='src/a.c', line=1):
    return Finding(tool, check, sev, path, line, 'msg')


class TestFilters(unittest.TestCase):
    CASES = [
        {'description': 'PCP code kept', 'finding': F(), 'expected': True},
        {'description': 'vendor dropped', 'finding': F(path='vendor/github.com/x/a.c'),
         'expected': False},
        {'description': 'src/external dropped', 'finding': F(path='src/external/jsonsl.c'),
         'expected': False},
        {'description': 'bison output dropped', 'finding': F(path='src/pmie/src/gram.tab.c'),
         'expected': False},
        {'description': 'flex output dropped', 'finding': F(path='<stdout>'),
         'expected': False},
        {'description': 'line 0 dropped', 'finding': F(line=0), 'expected': False},
        {'description': 'noise check dropped', 'finding': F(check='missingIncludeSystem'),
         'expected': False},
    ]

    def test_filter(self):
        for c in self.CASES:
            with self.subTest(c['description']):
                self.assertEqual(bool(filter_findings([c['finding']])), c['expected'])

    def test_dedup(self):
        self.assertEqual(len(deduplicate([F(), F(), F(line=2)])), 2)


class TestScoring(unittest.TestCase):
    BUG_CLASS = [
        {'description': 'cppcheck null pointer', 'check': 'nullPointer', 'expected': True},
        {'description': 'gcc analyzer', 'check': '-Wanalyzer-malloc-leak', 'expected': True},
        {'description': 'clang analyzer via tidy',
         'check': 'clang-analyzer-core.NullDereference', 'expected': True},
        {'description': 'fuzz crash', 'check': 'fuzz.fuzz_pdu.heap-buffer-overflow',
         'expected': True},
        {'description': 'scan-build null dereference',
         'check': 'scan-build.dereference-of-null-pointer', 'expected': True},
        {'description': 'scan-build dead store is not a bug class',
         'check': 'scan-build.dead-assignment', 'expected': False},
        {'description': 'clang array bound is a bug class',
         'check': 'clang-analyzer-security.ArrayBound', 'expected': True},
        {'description': 'clang "strcpy is used" is not a bug class',
         'check': 'clang-analyzer-security.insecureAPI.strcpy', 'expected': False},
        {'description': 'duplicate branches are not a bug class',
         'check': 'bugprone-branch-clone', 'expected': False},
        {'description': 'style check', 'check': 'variableScope', 'expected': False},
        {'description': 'shellcheck', 'check': 'SC2086', 'expected': False},
    ]

    def test_bug_class(self):
        for c in self.BUG_CLASS:
            with self.subTest(c['description']):
                self.assertEqual(is_bug_class(c['check']), c['expected'])

    HIGH_CONF = [
        {'description': 'strong bug class alone',
         'findings': [F(tool='gcc-analyzer', check='-Wanalyzer-use-after-free',
                        sev='warning')],
         'expected': 1},
        {'description': 'fuzz crash alone',
         'findings': [F(tool='fuzz', check='fuzz.fuzz_pdu.heap-buffer-overflow')],
         'expected': 1},
        {'description': 'other bug class alone is not enough',
         'findings': [F()], 'expected': 0},
        {'description': 'bug class backed by a second tool family',
         'findings': [F(),
                      F(tool='gcc-analyzer', check='-Wanalyzer-null-dereference',
                        sev='warning', line=2)],
         'expected': 2},
        {'description': 'bug class next to a non bug class: only the bug',
         'findings': [F(), F(tool='semgrep', check='semgrep.x', sev='warning')],
         'expected': 1},
        {'description': 'two non bug classes on one line',
         'findings': [F(tool='cppcheck', check='odd1', sev='style'),
                      F(tool='semgrep', check='semgrep.x', sev='style', line=2)],
         'expected': 0},
        {'description': 'same family (clang) is not a second opinion',
         'findings': [F(tool='scan-build', check='scan-build.dereference-of-null-pointer',
                        sev='warning'),
                      F(tool='clang-tidy', check='clang-analyzer-core.NullDereference',
                        sev='warning')],
         'expected': 0},
        {'description': 'bug class too far away (4 lines) is not backed up',
         'findings': [F(), F(tool='gcc-analyzer', check='-Wanalyzer-null-dereference',
                             sev='warning', line=5)],
         'expected': 0},
        {'description': 'bug class error in a security path',
         'findings': [F(path='src/pmcd/src/client.c')], 'expected': 1},
        {'description': 'lint tool left out',
         'findings': [F(tool='shellcheck', check='SC2086', sev='warning')],
         'expected': 0},
        {'description': 'style check left out',
         'findings': [F(check='variableScope', sev='style')], 'expected': 0},
    ]

    def test_high_confidence(self):
        for c in self.HIGH_CONF:
            with self.subTest(c['description']):
                self.assertEqual(len(get_high_confidence(c['findings'])), c['expected'])


class TestAnomalies(unittest.TestCase):
    SOURCE = 'int a;\nint b;\nindomtab[2] = 0;\nint c;\n'

    def anomaly(self, **kw):
        base = dict(id='T-1', tool='cppcheck', check_id='nullPointer',
                    file='src/a.c', code_anchor='', status='false-positive')
        base.update(kw)
        return Anomaly(**base)

    CASES = [
        {'description': 'no anchor, exact file: suppressed',
         'anomaly': {}, 'expected': (0, 1, 0)},
        {'description': 'anchor found near the line: suppressed',
         'anomaly': {'code_anchor': 'indomtab['}, 'expected': (0, 1, 0)},
        {'description': 'anchor not in the source: kept',
         'anomaly': {'code_anchor': 'not there'}, 'expected': (1, 0, 0)},
        {'description': 'glob file match',
         'anomaly': {'file': 'src/*.c'}, 'expected': (0, 1, 0)},
        {'description': 'other check id: kept',
         'anomaly': {'check_id': 'memleak'}, 'expected': (1, 0, 0)},
        {'description': 'confirmed bug: flagged, not suppressed',
         'anomaly': {'status': 'confirmed-bug'}, 'expected': (0, 0, 1)},
    ]

    def test_apply(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, 'src/a.c', self.SOURCE)
            for c in self.CASES:
                with self.subTest(c['description']):
                    rem, sup, flag = apply_anomalies(
                        [F(line=3)], [self.anomaly(**c['anomaly'])], root)
                    self.assertEqual((len(rem), len(sup), len(flag)), c['expected'])


class TestFuzz(unittest.TestCase):
    CASES = [
        {
            'description': 'ASan heap overflow: first PCP frame',
            'repro': '==1==ERROR: AddressSanitizer: heap-buffer-overflow\n'
                     '    #0 0x55d5 in __pmDecodeValueSet /build/source/src/libpcp/src/p_result.c:495:13\n'
                     '    #1 0x55d6 in LLVMFuzzerTestOneInput /build/harness/fuzz_pdu.c:57:7\n'
                     'SUMMARY: AddressSanitizer: heap-buffer-overflow /build/source/src/libpcp/src/p_result.c:495:13\n',
            'expected': ('fuzz', 'fuzz.fuzz_pdu.heap-buffer-overflow', 'error',
                         'src/libpcp/src/p_result.c', 495),
        },
        {
            'description': 'UBSan runtime error line',
            'repro': 'src/libpcp/src/spec.c:113:9: runtime error: signed integer overflow\n'
                     'SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/libpcp/src/spec.c:113:9\n',
            'expected': ('fuzz', 'fuzz.fuzz_pdu.undefined-behavior', 'error',
                         'src/libpcp/src/spec.c', 113),
        },
        {
            'description': 'no PCP frame: the harness file',
            'repro': 'SUMMARY: libFuzzer: timeout\n',
            'expected': ('fuzz', 'fuzz.fuzz_pdu.timeout', 'error',
                         'build/nix/fuzz/harness/fuzz_pdu.c', 1),
        },
    ]

    def test_crashes(self):
        for c in self.CASES:
            with self.subTest(c['description']):
                with tempfile.TemporaryDirectory() as d:
                    write(d, 'fuzz-run/crashes/fuzz_pdu/crash-123', 'x')
                    write(d, 'fuzz-run/crashes/fuzz_pdu/repro-123.txt', c['repro'])
                    got = fuzz.parse(d)
                    self.assertEqual([key(f) for f in got], [c['expected']])

    def test_no_crashes(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(fuzz.parse(d), [])


class TestDiagPaths(unittest.TestCase):
    ROOT = '/build/source'
    CASES = [
        {
            'description': 'file relative to the make directory',
            'log': ["make[2]: Entering directory '/build/source/src/libpcp/src'",
                    "pdu.c:10:3: warning: leak [-Wanalyzer-malloc-leak]"],
            'expected': ['src/libpcp/src/pdu.c:10:3: warning: leak [-Wanalyzer-malloc-leak]'],
        },
        {
            'description': 'header path with ..',
            'log': ["make[2]: Entering directory '/build/source/src/libpcp/src'",
                    "../../include/pcp/sds.h:99:28: warning: x [-Wanalyzer-null-dereference]"],
            'expected': ['src/include/pcp/sds.h:99:28: warning: x [-Wanalyzer-null-dereference]'],
        },
        {
            'description': 'directory popped on Leaving',
            'log': ["make[1]: Entering directory '/build/source/src'",
                    "make[2]: Entering directory '/build/source/src/pmcd'",
                    "make[2]: Leaving directory '/build/source/src/pmcd'",
                    "a.c:1:1: warning: x [-Wanalyzer-x]"],
            'expected': ['src/a.c:1:1: warning: x [-Wanalyzer-x]'],
        },
        {
            'description': 'system and nix store headers left out',
            'log': ["/nix/store/abc-perl/CORE/embed.h:92:49: warning: leak [-Wanalyzer-malloc-leak]"],
            'expected': [],
        },
        {
            'description': 'absolute path (ccwrap CCWRAP_ABSPATH)',
            'log': ["/build/source/src/pmie/src/../../include/pcp/x.h:3:1: warning: x [-Wanalyzer-x]"],
            'expected': ['src/include/pcp/x.h:3:1: warning: x [-Wanalyzer-x]'],
        },
        {
            'description': 'flex <stdout> left out',
            'log': ["<stdout>:1058:18: warning: leak [-Wanalyzer-malloc-leak]"],
            'expected': [],
        },
        {
            'description': 'flag not matching the regex left out',
            'log': ["make: Entering directory '/build/source'",
                    "a.c:1:1: warning: unused [-Wunused-variable]"],
            'expected': [],
        },
    ]

    def test_diagnostics(self):
        for c in self.CASES:
            with self.subTest(c['description']):
                got = diagpaths.diagnostics(c['log'], self.ROOT, re.compile('^-Wanalyzer-'))
                self.assertEqual(got, c['expected'])



class TestCcwrapEntries(unittest.TestCase):
    CC = '/bin/cc'
    CASES = [
        {
            'description': 'one C file, path made absolute',
            'args': ['-c', '-O2', 'pdu.c', '-o', 'pdu.o'],
            'expected': ['/build/source/src/libpcp/src/pdu.c'],
        },
        {
            'description': 'C file with ..',
            'args': ['-c', '../../x/y.c'],
            'expected': ['/build/source/src/x/y.c'],
        },
        {
            'description': 'link only: no entries',
            'args': ['-o', 'pmcd', 'pmcd.o', 'client.o'],
            'expected': [],
        },
        {
            'description': 'option ending in .c is not a file',
            'args': ['-c', '-include=foo.c', 'a.c'],
            'expected': ['/build/source/src/libpcp/src/a.c'],
        },
        {
            'description': 'two C files: two entries',
            'args': ['a.c', 'b.c', '-o', 'prog'],
            'expected': ['/build/source/src/libpcp/src/a.c',
                         '/build/source/src/libpcp/src/b.c'],
        },
    ]

    def test_entries(self):
        for c in self.CASES:
            with self.subTest(c['description']):
                got = ccwrap.entries(c['args'], '/build/source/src/libpcp/src', self.CC)
                self.assertEqual([e['file'] for e in got], c['expected'])
                for e in got:
                    self.assertEqual(e['arguments'], [self.CC] + c['args'])
                    self.assertEqual(e['directory'], '/build/source/src/libpcp/src')



class TestCcwrapAbsolute(unittest.TestCase):
    CWD = '/b/src/pmie'
    CASES = [
        {
            'description': 'relative source file',
            'args': ['-c', 'pmie.c'],
            'expected': ['-c', '/b/src/pmie/pmie.c'],
        },
        {
            'description': 'joined -I and -iquote',
            'args': ['-I../include', '-iquote.', '-I/abs/inc'],
            'expected': ['-I/b/src/pmie/../include', '-iquote/b/src/pmie/.', '-I/abs/inc'],
        },
        {
            'description': 'separate -I argument',
            'args': ['-I', '../include', '-c', 'a.c'],
            'expected': ['-I', '/b/src/pmie/../include', '-c', '/b/src/pmie/a.c'],
        },
        {
            'description': 'absolute source and other options unchanged',
            'args': ['-O2', '-DX=1', '-o', 'a.o', '/abs/a.c', 'lib.o'],
            'expected': ['-O2', '-DX=1', '-o', 'a.o', '/abs/a.c', 'lib.o'],
        },
        {
            'description': 'option ending in .c unchanged',
            'args': ['-include=foo.c'],
            'expected': ['-include=foo.c'],
        },
        {
            'description': 'no arguments',
            'args': [],
            'expected': [],
        },
    ]

    def test_absolute(self):
        for c in self.CASES:
            with self.subTest(c['description']):
                self.assertEqual(ccwrap.absolute(c['args'], self.CWD), c['expected'])


if __name__ == '__main__':
    unittest.main()
