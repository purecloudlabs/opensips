#include <stdio.h>
#include <string.h>

#include "../../dprint.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_cseq.h"

#include "../tm/tm_load.h"
#include "../tm/t_hooks.h"
#include "../tm/h_table.h"

#include "tracing_impl.h"

#define TRACING_TM_CB_MASK \
	(TMCB_REQUEST_FWDED | TMCB_RESPONSE_IN | TMCB_RESPONSE_FWDED | \
	TMCB_RESPONSE_PRE_OUT | TMCB_RESPONSE_OUT | TMCB_ON_FAILURE | \
	TMCB_TRANS_CANCELLED | TMCB_TRANS_DELETED | TMCB_MSG_MATCHED_IN | \
	TMCB_MSG_SENT_OUT | TMCB_REQUEST_BUILT | TMCB_LOCAL_REQUEST_OUT | \
	TMCB_LOCAL_RESPONSE | TMCB_LOCAL_COMPLETED)

static struct tm_binds tracing_tm_api;
static int tracing_tm_api_loaded;
static int tracing_tm_ctx_index = -1;

static int tracing_load_tm_api(void);
static void tracing_transaction_event_cb(const struct tracing_transaction_event *info);
static void tracing_tm_request_in_cb(struct cell *t, int type, struct tmcb_params *params);
static void tracing_tm_local_new_cb(struct cell *t, int type, struct tmcb_params *params);
static void tracing_tm_event_cb(struct cell *t, int type, struct tmcb_params *params);
static void tracing_register_tm_callbacks(struct cell *t, struct sip_msg *req);
static void tracing_emit_transaction_event(struct cell *t, int type,
	struct tmcb_params *params, const char *custom_name);
static void tracing_fill_transaction_details(struct tracing_transaction_event *info,
	struct cell *t, int type, struct tmcb_params *params, struct sip_msg *msg);
static struct sip_msg *tracing_select_tm_msg(struct cell *t, int type,
	struct tmcb_params *params);
static const char *tracing_tm_event_name(int type, char *buf, size_t len,
	const char *custom_name);
static const char *tracing_tm_direction_name(int type, int *dir_id);
static unsigned long long tracing_transaction_key(const struct cell *t);

int tracing_tm_init(void)
{
	if (register_tracing(TRACING_CB_TRANSACTION_EVENT, tracing_transaction_event_cb) < 0) {
		LM_ERR("failed to register transaction tracing\n");
		return -1;
	}

	if (tracing_load_tm_api() != 0)
		return 0;

	if (!tracing_tm_api.register_tmcb) {
		LM_ERR("TM register_tmcb API not available, cannot trace transactions\n");
		return -1;
	}

	if (tracing_tm_api.register_tmcb(0, 0, TMCB_REQUEST_IN,
			tracing_tm_request_in_cb, NULL, NULL) <= 0) {
		LM_ERR("failed to register TM request_in callback\n");
		return -1;
	}

	if (tracing_tm_api.register_tmcb(0, 0, TMCB_LOCAL_TRANS_NEW,
			tracing_tm_local_new_cb, NULL, NULL) <= 0) {
		LM_ERR("failed to register TM local_trans_new callback\n");
		return -1;
	}

	return 0;
}

void tracing_tm_destroy(void)
{
	/* nothing to clean up */
}

static void tracing_transaction_event_cb(const struct tracing_transaction_event *info)
{
	if (tracing_storage_store_transaction(info) < 0)
		LM_ERR("failed to persist transaction tracing event\n");
}

static int tracing_load_tm_api(void)
{
	if (tracing_tm_api_loaded)
		return 0;

	if (load_tm_api(&tracing_tm_api) != 0) {
		LM_INFO("TM module not available, transaction tracing disabled\n");
		return -1;
	}

	tracing_tm_api_loaded = 1;

	if (tracing_tm_api.t_ctx_register_int)
		tracing_tm_ctx_index = tracing_tm_api.t_ctx_register_int(NULL);

	return 0;
}

static void tracing_tm_request_in_cb(struct cell *t, int type, struct tmcb_params *params)
{
	struct sip_msg *req = params ? params->req : NULL;

	tracing_register_tm_callbacks(t, req);
	tracing_emit_transaction_event(t, type, params, NULL);
}

static void tracing_tm_local_new_cb(struct cell *t, int type, struct tmcb_params *params)
{
	struct sip_msg *req = params ? params->req : NULL;

	tracing_register_tm_callbacks(t, req);
	tracing_emit_transaction_event(t, type, params, NULL);
}

static void tracing_tm_event_cb(struct cell *t, int type, struct tmcb_params *params)
{
	tracing_emit_transaction_event(t, type, params, NULL);
}

static void tracing_register_tm_callbacks(struct cell *t, struct sip_msg *req)
{
	int already_registered = 0;

	if (!tracing_tm_api_loaded || !tracing_tm_api.register_tmcb || !t)
		return;

	if (tracing_tm_ctx_index >= 0 &&
			tracing_tm_api.t_ctx_get_int && tracing_tm_api.t_ctx_put_int) {
		already_registered = tracing_tm_api.t_ctx_get_int(t, tracing_tm_ctx_index);
		if (already_registered > 0)
			return;
		tracing_tm_api.t_ctx_put_int(t, tracing_tm_ctx_index, 1);
	}

	if (tracing_tm_api.register_tmcb(req, t, TRACING_TM_CB_MASK,
			tracing_tm_event_cb, NULL, NULL) <= 0) {
		LM_ERR("failed to register per-transaction TM callbacks\n");
	}
}

static unsigned long long tracing_transaction_key(const struct cell *t)
{
	if (!t)
		return 0;
	return ((unsigned long long)t->hash_index << 32) | t->label;
}

static const char *tracing_tm_event_name(int type, char *buf, size_t len,
	const char *custom_name)
{
	if (custom_name)
		return custom_name;

	switch (type) {
	case TMCB_REQUEST_IN: return "request_in";
	case TMCB_RESPONSE_IN: return "response_in";
	case TMCB_REQUEST_FWDED: return "request_forwarded";
	case TMCB_RESPONSE_FWDED: return "response_forwarded";
	case TMCB_RESPONSE_PRE_OUT: return "response_pre_out";
	case TMCB_RESPONSE_OUT: return "response_out";
	case TMCB_ON_FAILURE: return "on_failure";
	case TMCB_TRANS_CANCELLED: return "transaction_cancelled";
	case TMCB_TRANS_DELETED: return "transaction_deleted";
	case TMCB_MSG_MATCHED_IN: return "message_matched_in";
	case TMCB_MSG_SENT_OUT: return "message_sent_out";
	case TMCB_REQUEST_BUILT: return "request_built";
	case TMCB_LOCAL_TRANS_NEW: return "local_trans_new";
	case TMCB_LOCAL_REQUEST_OUT: return "local_request_out";
	case TMCB_LOCAL_RESPONSE: return "local_response";
	case TMCB_LOCAL_COMPLETED: return "local_completed";
	default:
		break;
	}

	if (!buf || len == 0)
		return "tm_event";

	snprintf(buf, len, "tmcb_%u", (unsigned int)type);
	return buf;
}

static const char *tracing_tm_direction_name(int type, int *dir_id)
{
	int id = 3;
	const char *name = "internal";

	switch (type) {
	case TMCB_REQUEST_IN:
	case TMCB_RESPONSE_IN:
	case TMCB_MSG_MATCHED_IN:
		id = 1;
		name = "incoming";
		break;
	case TMCB_REQUEST_FWDED:
	case TMCB_REQUEST_BUILT:
	case TMCB_RESPONSE_FWDED:
	case TMCB_RESPONSE_PRE_OUT:
	case TMCB_RESPONSE_OUT:
	case TMCB_MSG_SENT_OUT:
	case TMCB_LOCAL_REQUEST_OUT:
		id = 2;
		name = "outgoing";
		break;
	default:
		id = 3;
		name = "internal";
		break;
	}

	if (dir_id)
		*dir_id = id;

	return name;
}

static struct sip_msg *tracing_select_tm_msg(struct cell *t, int type,
	struct tmcb_params *params)
{
	(void)t;

	if (!params)
		return NULL;

	switch (type) {
	case TMCB_REQUEST_IN:
	case TMCB_REQUEST_BUILT:
	case TMCB_REQUEST_FWDED:
	case TMCB_LOCAL_TRANS_NEW:
	case TMCB_LOCAL_REQUEST_OUT:
		if (params->req && params->req != FAKED_REPLY)
			return params->req;
		break;
	case TMCB_RESPONSE_IN:
	case TMCB_RESPONSE_FWDED:
	case TMCB_RESPONSE_PRE_OUT:
	case TMCB_RESPONSE_OUT:
	case TMCB_LOCAL_RESPONSE:
	case TMCB_LOCAL_COMPLETED:
		if (params->rpl && params->rpl != FAKED_REPLY)
			return params->rpl;
		break;
	case TMCB_MSG_MATCHED_IN:
	case TMCB_MSG_SENT_OUT:
		if (params->req && params->req != FAKED_REPLY)
			return params->req;
		if (params->rpl && params->rpl != FAKED_REPLY)
			return params->rpl;
		break;
	default:
		if (params->req && params->req != FAKED_REPLY)
			return params->req;
		if (params->rpl && params->rpl != FAKED_REPLY)
			return params->rpl;
		break;
	}

	return NULL;
}

static void tracing_fill_transaction_details(struct tracing_transaction_event *info,
	struct cell *t, int type, struct tmcb_params *params, struct sip_msg *msg)
{
	str method = STR_NULL;
	unsigned int code = 0;
	str cseq_no = STR_NULL;
	str cseq_method = STR_NULL;

	(void)type;

	if (msg && msg != FAKED_REPLY)
		(void)tracing_get_cseq(msg, &cseq_no, &cseq_method);

	if (msg && msg != FAKED_REPLY) {
		if (msg->first_line.type == SIP_REQUEST) {
			method = msg->first_line.u.request.method;
		} else if (msg->first_line.type == SIP_REPLY) {
			code = msg->first_line.u.reply.statuscode;
		}
	}

	if (!code && params && params->code > 0)
		code = params->code;

	if ((!method.s || method.len == 0)) {
		if (t->method.s && t->method.len) {
			method = t->method;
		} else if (t->uas.request && t->uas.request != FAKED_REPLY &&
				t->uas.request->first_line.type == SIP_REQUEST) {
			method = t->uas.request->first_line.u.request.method;
		}
	}

	if ((!cseq_no.s || cseq_no.len == 0) && t->uas.request && t->uas.request != FAKED_REPLY)
		(void)tracing_get_cseq(t->uas.request, &cseq_no, &cseq_method);

	if ((!method.s || method.len == 0) && cseq_method.s && cseq_method.len > 0)
		method = cseq_method;

	info->method = method;
	info->code = code;
	info->cseq = cseq_no;
}

static void tracing_emit_transaction_event(struct cell *t, int type,
	struct tmcb_params *params, const char *custom_name)
{
	struct tracing_transaction_event info;
	struct sip_msg *msg;
	char event_buf[64];
	const char *event_name;
	struct tracing_conn_chunk_ref conn_chunk = { 0, 0 };
	str callid = STR_NULL;

	if (!t)
		return;

	memset(&info, 0, sizeof(info));
	info.event_id = type;
	info.hash_index = t->hash_index;
	info.label = t->label;
	info.is_local = is_local(t) ? 1 : 0;
	info.transaction_correlation_key = tracing_transaction_key(t);
	info.direction_name = tracing_tm_direction_name(type, &info.direction_id);

	msg = tracing_select_tm_msg(t, type, params);
	if (msg) {
		(void)tracing_get_via_branch(msg, &info.branch);
		(void)tracing_get_callid(msg, &callid);
	}
	if ((!info.branch.s || info.branch.len == 0) && t->uas.request)
		(void)tracing_get_via_branch(t->uas.request, &info.branch);
	if ((!callid.s || callid.len == 0) && t->uas.request)
		(void)tracing_get_callid(t->uas.request, &callid);
	if (!callid.s || callid.len == 0)
		callid = t->callid;
	info.callid = callid;
	if (tracing_conn_chunk_ref(msg, &conn_chunk) < 0 && msg)
		memset(&conn_chunk, 0, sizeof(conn_chunk));
	if (!conn_chunk.conn_id && t->uas.request)
		(void)tracing_conn_chunk_ref(t->uas.request, &conn_chunk);
	info.conn_chunk = conn_chunk;

	tracing_fill_transaction_details(&info, t, type, params, msg);

	event_name = tracing_tm_event_name(type, event_buf, sizeof(event_buf), custom_name);
	info.event_name = event_name;

	tracing_run_transaction_event(&info);
}

