#!/usr/bin/env python3
#
# build/nix/analysis/ccwrap.py - compiler wrapper for the analysis builds,
# used as `make CC=...`.  It runs the real compiler after:
#
#   CCWRAP_ABSPATH=1   making relative .c and -I/-iquote paths absolute, so
#                      the diagnostics name full paths (PCP's sub-makes use
#                      --no-print-directory, so the make log cannot be
#                      used to find the directory).  gcc-analyzer and
#                      gcc-warnings.
#   CCWRAP_CDB=<file>  appending a compile_commands.json entry (one JSON
#                      line) for each .c file.  bear cannot see compiles
#                      through the nix cc-wrapper.  clang-tidy.
#                      Make the database with: jq -s . <file>
#
#   CCWRAP_CC          the compiler to run
import fcntl
import json
import os
import sys

PATH_OPTS = ('-I', '-iquote')


def is_source(a):
    return a.endswith('.c') and not a.startswith('-')


def absolute(args, cwd):
    """args with relative .c files and include directories made absolute."""
    out = []
    want_path = False
    for a in args:
        if want_path:
            want_path = False
            out.append(a if os.path.isabs(a) else os.path.join(cwd, a))
            continue
        if a in PATH_OPTS:
            want_path = True
            out.append(a)
            continue
        opt = next((o for o in PATH_OPTS if a.startswith(o) and len(a) > len(o)), None)
        if opt and not os.path.isabs(a[len(opt):]):
            out.append(opt + os.path.join(cwd, a[len(opt):]))
        elif is_source(a) and not os.path.isabs(a):
            out.append(os.path.join(cwd, a))
        else:
            out.append(a)
    return out


def entries(args, cwd, real):
    """compile_commands entries for the .c files in args."""
    return [{
        'directory': cwd,
        'file': os.path.normpath(os.path.join(cwd, a)),
        'arguments': [real] + args,
    } for a in args if is_source(a)]


def main():
    real = os.environ['CCWRAP_CC']
    args = sys.argv[1:]
    cwd = os.getcwd()
    if os.environ.get('CCWRAP_ABSPATH'):
        args = absolute(args, cwd)
    cdb = os.environ.get('CCWRAP_CDB')
    found = entries(args, cwd, real) if cdb else []
    if found:
        with open(cdb, 'a') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            for e in found:
                f.write(json.dumps(e) + '\n')
    os.execv(real, [real] + args)


if __name__ == '__main__':
    main()
