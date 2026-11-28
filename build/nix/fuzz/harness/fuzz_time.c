/*
 * fuzz_time: time and interval parsers used by -t -S -T -A -O options
 * and by pmlogger/pmie configs.
 *
 * Input lines: interval \n start \n end \n align \n offset
 */
#include "fuzz_common.h"
#include <time.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char		*p[5];
    char		*all;
    char		*err = NULL;
    struct timespec	ts, start, end, rstart, rend, roffset;
    struct tm		tm;

    if (size > 1024)
	return 0;
    all = fuzz_split(data, size, p, 5);

    pmParseInterval(p[0], &ts, &err);
    free(err);
    err = NULL;

    memset(&tm, 0, sizeof(tm));
    __pmParseCtime(p[1], &tm, &err);
    free(err);
    err = NULL;

    start.tv_sec = 1000000000;
    start.tv_nsec = 0;
    end.tv_sec = 2000000000;
    end.tv_nsec = 0;
    pmParseTimeWindow(p[1], p[2], p[3], p[4], &start, &end,
			&rstart, &rend, &roffset, &err);
    free(err);

    free(all);
    return 0;
}
