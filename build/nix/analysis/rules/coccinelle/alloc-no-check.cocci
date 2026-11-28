// alloc-no-check: memory from malloc()/calloc()/realloc()/strdup() is
// used before any test for NULL.
@r exists@
expression ptr;
identifier fld;
position p;
@@
ptr = \(malloc\|calloc\|realloc\|strdup\)(...);
... when != ptr
(
ptr@p->fld
|
 *ptr@p
|
ptr@p[...]
)

@script:python@
p << r.p;
ptr << r.ptr;
@@
print("%s:%s:%s: warning: %s is used before a NULL check [cocci.alloc-no-check]"
      % (p[0].file, p[0].line, p[0].column, ptr))
