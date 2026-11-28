/*
 * fuzz_units: pmParseUnitsStr(), the units string parser used by
 * pmrep, pmie, derived metrics and pmlogrewrite ("Kbyte / sec" etc).
 */
#include "fuzz_common.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char	*str;
    char	*err = NULL;
    pmUnits	units;
    double	mult;

    if (size > 1024)
	return 0;
    str = fuzz_cstr(data, size);
    if (pmParseUnitsStr(str, &units, &mult, &err) < 0)
	free(err);
    free(str);
    return 0;
}
