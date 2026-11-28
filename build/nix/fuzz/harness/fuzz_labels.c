/*
 * fuzz_labels: the libpcp label set JSON parser.
 *
 * __pmParseLabelSet() parses label JSON from PMDAs, pmcd and archives.
 * A good parse is then merged with itself by pmMergeLabels().
 */
#include "fuzz_common.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char	*json;
    char	*sets[2];
    char	buf[PM_MAXLABELJSONLEN];
    pmLabelSet	*lsp = NULL;

    if (size > PM_MAXLABELJSONLEN)
	return 0;
    json = fuzz_cstr(data, size);

    if (__pmParseLabelSet(json, (int)size, 0, &lsp) >= 0) {
	pmFreeLabelSets(lsp, 1);
	sets[0] = sets[1] = json;
	pmMergeLabels(sets, 2, buf, sizeof(buf));
    }

    free(json);
    return 0;
}
