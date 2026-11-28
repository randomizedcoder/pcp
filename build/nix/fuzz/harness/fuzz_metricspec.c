/*
 * fuzz_metricspec: pmParseMetricSpec(), the host:metric[inst,...] and
 * archive/metric["inst"] parser used by pmval, pmie and pmdumptext.
 * The first byte selects host (even) or archive (odd) mode.
 */
#include "fuzz_common.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char		*spec;
    char		*err = NULL;
    char		source[] = "local:";
    pmMetricSpec	*msp = NULL;
    int			isarch;

    if (size < 1 || size > 4096)
	return 0;
    isarch = data[0] & 1;
    spec = fuzz_cstr(data + 1, size - 1);
    if (pmParseMetricSpec(spec, isarch, source, &msp, &err) >= 0)
	pmFreeMetricSpec(msp);
    else
	free(err);
    free(spec);
    return 0;
}
