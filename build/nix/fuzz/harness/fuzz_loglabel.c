/*
 * fuzz_loglabel: archive label record reader, __pmLogLoadLabel().
 *
 * This is the first thing read from every archive volume, .meta and
 * .index file (pmNewContext(PM_CONTEXT_ARCHIVE, ...), pmlogcheck, ...).
 * The input is written to a memfd and read back as a __pmFILE.
 */
#define _GNU_SOURCE
#include "fuzz_common.h"
#include <sys/mman.h>
#include <unistd.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    __pmFILE		*f;
    __pmLogLabel	label;
    int			fd;

    if (size > 65536)
	return 0;
    if ((fd = memfd_create("fuzz_loglabel", 0)) < 0)
	return 0;
    if (write(fd, data, size) != (ssize_t)size) {
	close(fd);
	return 0;
    }
    if ((f = __pmFdopen(fd, "r")) == NULL) {
	close(fd);
	return 0;
    }

    memset(&label, 0, sizeof(label));
    __pmLogLoadLabel(f, &label);
    __pmLogFreeLabel(&label);
    __pmFclose(f);
    return 0;
}
