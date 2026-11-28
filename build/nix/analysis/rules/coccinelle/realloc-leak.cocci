// realloc-leak: p = realloc(p, n) loses the old block when realloc fails.
@r@
expression E, N;
position p;
@@
E@p = realloc(E, N)

@script:python@
p << r.p;
E << r.E;
@@
print("%s:%s:%s: warning: %s = realloc(%s, ...) leaks the old block on failure [cocci.realloc-leak]"
      % (p[0].file, p[0].line, p[0].column, E, E))
