// double-free: free() twice on one pointer, with no new value between,
// on every path from the first free (forall, as in use-after-free.cocci:
// "exists" matches if/else branches and error paths that return).
@r forall@
expression E, E2;
position p1, p2;
@@
free@p1(E);
... when != E = E2
    when != &E
free@p2(E);

@script:python@
p1 << r.p1;
p2 << r.p2;
E << r.E;
@@
if (int(p2[0].line), int(p2[0].column)) > (int(p1[0].line), int(p1[0].column)):
    print("%s:%s:%s: warning: %s is freed again (first free() at line %s) [cocci.double-free]"
          % (p2[0].file, p2[0].line, p2[0].column, E, p1[0].line))
