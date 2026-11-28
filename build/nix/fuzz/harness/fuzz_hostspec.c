/*
 * fuzz_hostspec: host specification and URL parsers.
 *
 * __pmParseHostAttrsSpec() parses pcp://host:port?attr=value URLs
 * (pmNewContext, pmcd -h, PMCD_HOST style input), __pmParseHostSpec()
 * parses the older host@proxy:port form.  A good parse is unparsed
 * again, to check the round trip code too.
 */
#include "fuzz_common.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char		*spec = fuzz_cstr(data, size);
    char		*err = NULL;
    char		buf[4096];
    __pmHostSpec	*hosts = NULL;
    __pmHashCtl		attrs;
    int			count = 0;

    __pmHashInit(&attrs);
    if (__pmParseHostAttrsSpec(spec, &hosts, &count, &attrs, &err) >= 0) {
	__pmUnparseHostAttrsSpec(hosts, count, &attrs, buf, sizeof(buf));
	__pmFreeHostAttrsSpec(hosts, count, &attrs);
    }
    else
	__pmFreeAttrsSpec(&attrs);
    __pmHashClear(&attrs);
    free(err);

    hosts = NULL;
    count = 0;
    err = NULL;
    if (__pmParseHostSpec(spec, &hosts, &count, &err) >= 0) {
	__pmUnparseHostSpec(hosts, count, buf, sizeof(buf));
	__pmFreeHostSpec(hosts, count);
    }
    free(err);

    free(spec);
    return 0;
}
