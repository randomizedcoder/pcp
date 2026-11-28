/*
 * fuzz_series: the pmseries query language parser (query_parser.y),
 * as used by pmproxy /series/query and pmseries(1).
 *
 * series_parse() is internal to libpcp_web, so this harness links the
 * instrumented libpcp_web.a objects (see build/nix/fuzz/default.nix).
 */
#include "fuzz_common.h"
#include <pcp/pmwebapi.h>
#include "query.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    series_t	sp;
    sds		query;
    sds		err = NULL;

    if (size > 4096)
	return 0;
    query = sdsnewlen(data, size);
    memset(&sp, 0, sizeof(sp));
    if (series_parse(query, &sp, &err) != 0)
	sdsfree(err);
    sdsfree(query);
    return 0;
}
