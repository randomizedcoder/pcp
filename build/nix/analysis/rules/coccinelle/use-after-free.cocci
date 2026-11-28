// use-after-free: a pointer is used after free() with no new value
// between the two, on every path from the free (forall: an "exists"
// match follows paths that a break or an error check never takes).
// Uses inside sizeof, and uses before the free in the file (another loop
// pass), are not reported.
@r forall@
expression E, E2;
identifier fld;
position p1, p2;
@@
free@p1(E);
... when != E = E2
    when != &E
(
E@p2->fld
|
 *E@p2
|
E@p2[...]
)

@script:python@
p1 << r.p1;
p2 << r.p2;
E << r.E;
@@
def pos(p):
    return (int(p.line), int(p.column))

def in_sizeof(p):
    try:
        with open(p.file) as f:
            text = f.readlines()[int(p.line) - 1]
    except (OSError, IndexError):
        return False
    return text[:int(p.column)].rstrip(' *&(').endswith('sizeof')

if pos(p2[0]) > pos(p1[0]) and not in_sizeof(p2[0]):
    print("%s:%s:%s: warning: %s is used after free() at line %s [cocci.use-after-free]"
          % (p2[0].file, p2[0].line, p2[0].column, E, p1[0].line))
