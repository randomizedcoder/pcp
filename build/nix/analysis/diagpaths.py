"""Pick compiler diagnostics out of a PCP make log, with repo paths.

PCP's make runs gcc in each subdirectory, so a diagnostic names its file
relative to that directory ("pmda.c", "../../include/pcp/libpcp.h").
The log must come from `make -O -w`, so each target's output is in one
piece between "Entering directory" and "Leaving directory" lines.

Usage: python3 diagpaths.py <build.log> <source root> <flag regex>
Prints "path:line:col: warning: message [flag]" lines, sorted and unique,
for diagnostics whose [flag] matches the regex.  Lines for files outside
the source root (system headers, /nix/store) or with no real file
(<stdout> from flex) are left out.
"""

import os
import re
import sys

_DIR_RE = re.compile(r"^make(?:\[\d+\])?: (Entering|Leaving) directory '(.*)'")
_DIAG_RE = re.compile(r"^([^\s:<][^:]*):(\d+):(\d+): (warning|error): (.*\[([^\]]+)\])$")


def diagnostics(lines, root, flag_re):
    root = os.path.normpath(root)
    dirs = []
    seen = set()
    for line in lines:
        line = line.rstrip("\n")
        m = _DIR_RE.match(line)
        if m:
            if m.group(1) == "Entering":
                dirs.append(m.group(2))
            elif dirs:
                dirs.pop()
            continue
        m = _DIAG_RE.match(line)
        if not m or not flag_re.search(m.group(6)):
            continue
        path = m.group(1)
        if not os.path.isabs(path):
            path = os.path.join(dirs[-1] if dirs else root, path)
        path = os.path.normpath(path)
        if not path.startswith(root + os.sep):
            continue
        rel = os.path.relpath(path, root)
        seen.add(f"{rel}:{m.group(2)}:{m.group(3)}: {m.group(4)}: {m.group(5)}")
    return sorted(seen)


def main():
    log, root, flags = sys.argv[1:4]
    with open(log, errors="replace") as f:
        for d in diagnostics(f, root, re.compile(flags)):
            print(d)


if __name__ == "__main__":
    main()
