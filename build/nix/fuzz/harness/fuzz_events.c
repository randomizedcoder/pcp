/*
 * fuzz_events: packed event record decoders.
 *
 * Event records (PM_TYPE_EVENT / PM_TYPE_HIGHRES_EVENT) come from PMDAs,
 * pmcd and archives as one opaque pmValueBlock.  The input is the block
 * body; byte 0 picks the old or the high resolution format.
 */
#include "fuzz_common.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    pmValueBlock	*vbp;
    pmValueSet		vs;
    pmResult_v2		**rv2 = NULL;
    pmResult		**rv = NULL;
    size_t		len;
    int			highres;

    if (size < 1 || size > 65536)
	return 0;
    highres = data[0] & 1;
    data++;
    size--;

    len = PM_VAL_HDR_SIZE + size;
    if ((vbp = calloc(1, len)) == NULL)
	return 0;
    vbp->vlen = len;
    vbp->vtype = highres ? PM_TYPE_HIGHRES_EVENT : PM_TYPE_EVENT;
    memcpy(vbp->vbuf, data, size);

    memset(&vs, 0, sizeof(vs));
    vs.pmid = PM_ID_NULL;
    vs.numval = 1;
    vs.valfmt = PM_VAL_DPTR;
    vs.vlist[0].inst = PM_IN_NULL;
    vs.vlist[0].value.pval = vbp;

    if (highres) {
	if (pmUnpackHighResEventRecords(&vs, 0, &rv) > 0)
	    pmFreeHighResEventResult(rv);
    }
    else {
	if (pmUnpackEventRecords(&vs, 0, &rv2) > 0)
	    pmFreeEventResult(rv2);
    }

    free(vbp);
    return 0;
}
