/*
 * fuzz_derived: the derived metric expression parser (derive_parser.y).
 *
 * Expressions come from pmRegisterDerived(), $PCP_DERIVED_CONFIG files and
 * pmrep/pmie configs.  Each good parse stays registered, so a unique name
 * is used per call; after ~2M good parses the PMID space runs out and
 * libpcp stops parsing (a long run should use -runs or restart).
 */
#include "fuzz_common.h"
#include <stdio.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static unsigned int	seq;
    char		name[32];
    char		*expr;
    char		*err = NULL;

    if (size > 4096)
	return 0;
    expr = fuzz_cstr(data, size);
    snprintf(name, sizeof(name), "fuzz.m%u", seq++);
    pmRegisterDerivedMetric(name, expr, &err);
    free(err);
    free(expr);
    return 0;
}
