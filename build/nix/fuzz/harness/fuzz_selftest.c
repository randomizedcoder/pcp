/*
 * fuzz_selftest: proves the fuzz build can see a bug.
 *
 * Inputs longer than SELFTEST_LEN overflow a heap buffer.  The
 * pcp-fuzz-selftest target feeds a long input and fails unless ASan
 * reports the overflow (so a broken sanitizer or harness build is found).
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef SELFTEST_LEN
#define SELFTEST_LEN 8
#endif

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char	*buf = malloc(SELFTEST_LEN);

    if (buf == NULL)
	return 0;
    if (size >= 2 && data[0] == 'P' && data[1] == 'C')
	memcpy(buf, data, size);	/* overflow when size > SELFTEST_LEN */
    /* keep the compiler from removing the unused buffer */
    __asm__ volatile("" : : "r"(buf) : "memory");
    free(buf);
    return 0;
}
