/*
 * Shared helpers for the PCP libFuzzer harnesses (build/nix/fuzz).
 *
 * Each harness defines LLVMFuzzerTestOneInput() and is linked with
 * -fsanitize=fuzzer,address,undefined against an instrumented libpcp
 * (see build/nix/fuzz/libs.nix).
 */
#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H

#include <pcp/pmapi.h>
#include <pcp/libpcp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * libpcp needs a pcp.conf; the build passes the one from the fuzz libs
 * build tree.  An already set $PCP_CONF wins.  No derived metric configs
 * are loaded.
 */
#ifndef FUZZ_PCP_CONF
#define FUZZ_PCP_CONF "/etc/pcp.conf"
#endif

/*
 * Sanitizer defaults, so a harness run by hand gives symbolized stacks.
 * $ASAN_OPTIONS / $UBSAN_OPTIONS still override these.
 */
#ifndef FUZZ_SYMBOLIZER
#define FUZZ_SYMBOLIZER "llvm-symbolizer"
#endif

const char *
__asan_default_options(void)
{
    return "detect_leaks=0:external_symbolizer_path=" FUZZ_SYMBOLIZER;
}

const char *
__ubsan_default_options(void)
{
    return "print_stacktrace=1:halt_on_error=1:external_symbolizer_path=" FUZZ_SYMBOLIZER;
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    setenv("PCP_CONF", FUZZ_PCP_CONF, 0);
    setenv("PCP_DERIVED_CONFIG", "", 1);
    return 0;
}

/* NUL terminated copy of the fuzz input; caller frees */
static inline char *
fuzz_cstr(const uint8_t *data, size_t size)
{
    char	*s = malloc(size + 1);

    if (s == NULL)
	abort();
    memcpy(s, data, size);
    s[size] = '\0';
    return s;
}

/*
 * Split the input into n NUL terminated strings at '\n' bytes.
 * Missing parts are set to "".  Returns one malloc'd block; out[] points
 * into it.  Caller frees the return value.
 */
static inline char *
fuzz_split(const uint8_t *data, size_t size, char **out, int n)
{
    char	*s = fuzz_cstr(data, size);
    char	*p = s;
    int		i;

    for (i = 0; i < n; i++) {
	out[i] = p;
	if (i < n - 1) {
	    char *nl = strchr(p, '\n');
	    if (nl != NULL) {
		*nl = '\0';
		p = nl + 1;
	    }
	    else
		p = s + size;	/* the final "" */
	}
    }
    return s;
}

#endif /* FUZZ_COMMON_H */
