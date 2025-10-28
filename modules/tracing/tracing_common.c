#include <stddef.h>
#include <strings.h>

#include "../../dprint.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_cseq.h"
#include "../../net/net_tcp.h"

#include "tracing_impl.h"

int tracing_conn_chunk_ref(struct sip_msg *msg, struct tracing_conn_chunk_ref *chunk_ref)
{
	unsigned long long cid = 0;
	unsigned int conn_id = 0;
	unsigned int seq_no = 0;

	if (!chunk_ref)
		return -1;

	chunk_ref->conn_id = 0;
	chunk_ref->seq_no = 0;

	if (!msg || msg == FAKED_REPLY)
		return -1;

	/* For UDP, we use proto_reserved1 to store the timestamp microseconds
	 * and proto_reserved2 for timestamp seconds */
	if (msg->rcv.proto == PROTO_UDP || is_udp_based_proto(msg->rcv.proto)) {
		/* UDP: use timestamp as correlation (stored in proto_reserved fields)
		 * Store seconds in conn_id and microseconds in seq_no */
		chunk_ref->conn_id = (unsigned long long)msg->rcv.proto_reserved2; /* seconds (high bit set to distinguish from TCP) */
		chunk_ref->seq_no = msg->rcv.proto_reserved1; /* microseconds */
		return 0;
	}

	/* TCP: use connection ID and sequence number */
	conn_id = msg->rcv.proto_reserved1;
	if (!conn_id)
		return -1;

	if (tcp_get_correlation_chunk(conn_id, &cid, &seq_no) < 0)
		return -1;

	if (seq_no > 0)
		seq_no--;

	chunk_ref->conn_id = cid;
	chunk_ref->seq_no = seq_no;

	return 0;
}

int tracing_get_via_branch(struct sip_msg *msg, str *branch)
{
	struct via_body *via;
	struct via_param *param;

	if (!branch)
		return -1;

	branch->s = NULL;
	branch->len = 0;

	if (!msg || msg == FAKED_REPLY)
		return -1;

	if (!msg->via1 && parse_headers(msg, HDR_VIA1_F, 0) < 0)
		return -1;

	via = msg->via1;
	if (!via)
		return -1;

	if (via->branch && via->branch->value.s && via->branch->value.len > 0) {
		*branch = via->branch->value;
		return 0;
	}

	for (param = via->param_lst; param; param = param->next) {
		if (param->type == PARAM_BRANCH ||
				(param->name.s && param->name.len == 6 &&
				 strncasecmp(param->name.s, "branch", 6) == 0)) {
			if (param->value.s && param->value.len > 0) {
				*branch = param->value;
				return 0;
			}
		}
	}

	return -1;
}

int tracing_get_cseq(struct sip_msg *msg, str *number, str *method)
{
	struct cseq_body *cseq;

	if (number)
		*number = STR_NULL;
	if (method)
		*method = STR_NULL;

	if (!msg || msg == FAKED_REPLY)
		return -1;

	if ((!msg->cseq || !msg->cseq->parsed) && parse_headers(msg, HDR_CSEQ_F, 0) < 0)
		return -1;

	if (!msg->cseq || !msg->cseq->parsed)
		return -1;

	cseq = get_cseq(msg);
	if (!cseq)
		return -1;

	if (number && cseq->number.s && cseq->number.len > 0)
		*number = cseq->number;

	if (method && cseq->method.s && cseq->method.len > 0)
		*method = cseq->method;

	return 0;
}

int tracing_get_callid(struct sip_msg *msg, str *callid)
{
	if (callid)
		*callid = STR_NULL;

	if (!msg || msg == FAKED_REPLY || !callid)
		return -1;

	if (get_callid(msg, callid) < 0 || !callid->s || callid->len <= 0) {
		*callid = STR_NULL;
		return -1;
	}

	return 0;
}

