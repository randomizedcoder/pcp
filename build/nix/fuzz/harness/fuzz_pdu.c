/*
 * fuzz_pdu: feed one PDU to the libpcp __pmDecode*() routines.
 *
 * Input: a PDU as it arrives on the wire (network byte order):
 *   word 0 = len (ignored, set to the input size)
 *   word 1 = type (PDU_*), word 2 = from, then the body.
 *
 * The header is converted to host order like __pmGetPDU() does, and the
 * body stays in network order.  The PDU buffer is exactly the input size
 * (rounded up to 8 bytes, zero padded), so a read past the end is seen
 * by ASan.  Dispatch follows qa/src/pdu-gadget.c -x.
 */
#include "fuzz_common.h"
#include <arpa/inet.h>

#define MAX_PDU	(1 << 20)

/* free a PDU buffer, whatever pins the decoder left */
static void
unpin_all(__pmPDU *pb)
{
    while (__pmUnpinPDUBuf(pb) > 0)
	;
}

static void
decode(__pmPDU *pb, int type)
{
    int		a, b, n;
    char	*s;
    char	**names;
    int		*status;
    pmID	pmid;
    pmID	*pmids;
    pmDesc	desc;
    pmDesc	*descs;
    pmDesc	desclist[16];
    pmID	idlist[16];
    pmInDom	indom;
    pmProfile	*prof;
    pmInResult	*inres;
    __pmResult	*res;
    __pmCred	*creds;
    pmLabelSet	*lsp;
    pmTimeval	tv;

    switch (type) {
    case PDU_ERROR:
	__pmDecodeError(pb, &a);
	__pmDecodeXtendError(pb, &a, &b);
	break;
    case PDU_RESULT:
	if (__pmDecodeResult(pb, &res) >= 0)
	    __pmFreeResult(res);
	break;
    case PDU_HIGHRES_RESULT:
	if (__pmDecodeHighResResult(pb, &res) >= 0)
	    __pmFreeResult(res);
	break;
    case PDU_PROFILE:
	if (__pmDecodeProfile(pb, &a, &prof) >= 0)
	    __pmFreeProfile(prof);
	break;
    case PDU_FETCH:
	if (__pmDecodeFetch(pb, &a, &tv, &n, &pmids) >= 0)
	    __pmUnpinPDUBuf(pmids);
	break;
    case PDU_HIGHRES_FETCH:
	if (__pmDecodeHighResFetch(pb, &a, &n, &pmids) >= 0)
	    __pmUnpinPDUBuf(pmids);
	break;
    case PDU_DESC_REQ:
	__pmDecodeDescReq(pb, &pmid);
	break;
    case PDU_DESC:
	__pmDecodeDesc(pb, &desc);
	break;
    case PDU_DESCS:
	__pmDecodeDescs(pb, 16, desclist);
	if (__pmDecodeDescs2(pb, &n, &descs) >= 0)
	    free(descs);
	break;
    case PDU_INSTANCE_REQ:
	if (__pmDecodeInstanceReq(pb, &indom, &a, &s) >= 0)
	    free(s);
	break;
    case PDU_INSTANCE:
	if (__pmDecodeInstance(pb, &inres) >= 0)
	    __pmFreeInResult(inres);
	break;
    case PDU_TEXT_REQ:
	__pmDecodeTextReq(pb, &a, &b);
	break;
    case PDU_TEXT:
	if (__pmDecodeText(pb, &a, &s) >= 0)
	    free(s);
	break;
    case PDU_CREDS:
	if (__pmDecodeCreds(pb, &a, &n, &creds) >= 0)
	    free(creds);
	break;
    case PDU_PMNS_IDS:
    case PDU_DESC_IDS:
	__pmDecodeIDList(pb, 16, idlist, &a);
	if (__pmDecodeIDList2(pb, &n, &pmids) >= 0)
	    free(pmids);
	break;
    case PDU_PMNS_NAMES:
	if (__pmDecodeNameList(pb, &n, &names, &status) >= 0) {
	    free(names);
	    free(status);
	}
	break;
    case PDU_PMNS_CHILD:
	if (__pmDecodeChildReq(pb, &s, &a) >= 0)
	    free(s);
	break;
    case PDU_PMNS_TRAVERSE:
	if (__pmDecodeTraversePMNSReq(pb, &s) >= 0)
	    free(s);
	break;
    case PDU_ATTR:		/* == PDU_AUTH */
	__pmDecodeAttr(pb, &a, &s, &b);
	__pmDecodeAuth(pb, &a, &s, &b);
	break;
    case PDU_LABEL_REQ:
	__pmDecodeLabelReq(pb, &a, &b);
	break;
    case PDU_LABEL:
	if (__pmDecodeLabel(pb, &a, &b, &lsp, &n) >= 0)
	    pmFreeLabelSets(lsp, n);
	break;
    default:
	break;
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    __pmPDU	*pb;
    __pmPDUHdr	*php;
    size_t	alloc;
    int		type;

    if (size < sizeof(__pmPDUHdr) || size > MAX_PDU)
	return 0;
    alloc = (size + 7) & ~(size_t)7;
    if ((pb = __pmFindPDUBuf((int)alloc)) == NULL)
	return 0;
    memset(pb, 0, alloc);
    memcpy(pb, data, size);

    php = (__pmPDUHdr *)pb;
    php->len = (int)size;
    php->type = type = ntohl((unsigned int)php->type);
    php->from = ntohl((unsigned int)php->from);

    decode(pb, type);
    unpin_all(pb);
    return 0;
}
