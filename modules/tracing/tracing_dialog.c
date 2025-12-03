#include <stdio.h>
#include <string.h>

#include "../../dprint.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_cseq.h"

#include "../dialog/dlg_load.h"
#include "../dialog/dlg_hash.h"
#include "../dialog/dlg_cb.h"

#include "tracing_impl.h"

#define TRACING_DLG_CB_MASK \
	(DLGCB_REQ_WITHIN | DLGCB_RESPONSE_FWDED | DLGCB_RESPONSE_WITHIN | \
	DLGCB_CONFIRMED | DLGCB_FAILED | DLGCB_EARLY | DLGCB_TERMINATED | \
	DLGCB_EXPIRED | DLGCB_DESTROY)

static struct dlg_binds tracing_dlg_api;
static int tracing_dlg_api_loaded;
static int tracing_dlg_ctx_state = -1;

static int tracing_load_dialog_api(void);
static void tracing_dialog_created_cb(struct dlg_cell *dlg, int type, struct dlg_cb_params *params);
static void tracing_dialog_loaded_cb(struct dlg_cell *dlg, int type, struct dlg_cb_params *params);
static void tracing_dialog_events_cb(struct dlg_cell *dlg, int type, struct dlg_cb_params *params);
static void tracing_dialog_event_cb(const struct tracing_dialog_event *info);
static void tracing_emit_dialog_event(struct dlg_cell *dlg, int cb_type,
	struct dlg_cb_params *params, const char *custom_name, const str *method_hint);
static void tracing_dialog_register_per_dialog(struct dlg_cell *dlg);
static const char *tracing_state_name(int state);
static const char *tracing_direction_name(unsigned int dir);
static const char *tracing_format_event_name(int cb_type, const str *method,
	unsigned int code, char *buf, size_t len, const char *custom_name);

int tracing_dialog_init(void)
{
	if (register_tracing(TRACING_CB_DIALOG_EVENT, tracing_dialog_event_cb) < 0) {
		LM_ERR("failed to register dialog tracing\n");
		return -1;
	}

	if (tracing_load_dialog_api() == 0) {
		if (tracing_dlg_api.register_dlgcb &&
		    tracing_dlg_api.register_dlgcb(NULL, DLGCB_CREATED,
			    tracing_dialog_created_cb, NULL, NULL) != 0) {
			LM_ERR("failed to register dialog created callback\n");
			return -1;
		}

		if (tracing_dlg_api.register_dlgcb &&
		    tracing_dlg_api.register_dlgcb(NULL, DLGCB_LOADED,
			    tracing_dialog_loaded_cb, NULL, NULL) != 0) {
			LM_ERR("failed to register dialog loaded callback\n");
			return -1;
		}
	}

	return 0;
}

void tracing_dialog_destroy(void)
{
	/* nothing to clean up */
}

static void tracing_dialog_event_cb(const struct tracing_dialog_event *info)
{
	if (tracing_storage_store_dialog(info) < 0)
		LM_ERR("failed to persist dialog tracing event\n");
}

static int tracing_load_dialog_api(void)
{
	if (tracing_dlg_api_loaded)
		return 0;

	if (load_dlg_api(&tracing_dlg_api) != 0) {
		LM_INFO("dialog module not available, dialog tracing disabled\n");
		return -1;
	}

	tracing_dlg_api_loaded = 1;

	if (tracing_dlg_api.dlg_ctx_register_int)
		tracing_dlg_ctx_state = tracing_dlg_api.dlg_ctx_register_int(NULL);

	return 0;
}

static const char *tracing_state_name(int state)
{
	switch (state) {
	case DLG_STATE_UNCONFIRMED: return "unconfirmed";
	case DLG_STATE_EARLY: return "early";
	case DLG_STATE_CONFIRMED_NA: return "confirmed_na";
	case DLG_STATE_CONFIRMED: return "confirmed";
	case DLG_STATE_DELETED: return "deleted";
	default: return "unknown";
	}
}

static const char *tracing_direction_name(unsigned int dir)
{
	switch (dir) {
	case DLG_DIR_NONE: return "internal";
	case DLG_DIR_DOWNSTREAM: return "outgoing";
	case DLG_DIR_UPSTREAM: return "incoming";
	default: return "invalid";
	}
}

static void tracing_dialog_register_per_dialog(struct dlg_cell *dlg)
{
	if (!tracing_dlg_api_loaded || !tracing_dlg_api.register_dlgcb)
		return;

	if (tracing_dlg_api.register_dlgcb(dlg, TRACING_DLG_CB_MASK,
			tracing_dialog_events_cb, NULL, NULL) != 0)
		LM_ERR("failed to register per-dialog tracing callbacks\n");
}

static void tracing_dialog_created_cb(struct dlg_cell *dlg, int type, struct dlg_cb_params *params)
{
	if (!dlg)
		return;

	if (tracing_dlg_ctx_state >= 0 && tracing_dlg_api.dlg_ctx_put_int)
		tracing_dlg_api.dlg_ctx_put_int(dlg, tracing_dlg_ctx_state, dlg->state);

	tracing_emit_dialog_event(dlg, type, params, "created", NULL);
	tracing_dialog_register_per_dialog(dlg);
}

static void tracing_dialog_loaded_cb(struct dlg_cell *dlg, int type, struct dlg_cb_params *params)
{
	if (!dlg)
		return;

	if (tracing_dlg_ctx_state >= 0 && tracing_dlg_api.dlg_ctx_put_int)
		tracing_dlg_api.dlg_ctx_put_int(dlg, tracing_dlg_ctx_state, dlg->state);

	tracing_emit_dialog_event(dlg, type, params, "loaded", NULL);
	tracing_dialog_register_per_dialog(dlg);
}

static void tracing_dialog_events_cb(struct dlg_cell *dlg, int type, struct dlg_cb_params *params)
{
	const str *method_hint = NULL;

	switch (type) {
	case DLGCB_TERMINATED:
	case DLGCB_DESTROY:
	case DLGCB_EXPIRED:
		method_hint = str_static("BYE");
		break;
	default:
		break;
	}

	tracing_emit_dialog_event(dlg, type, params, NULL, method_hint);
}

static const char *tracing_format_event_name(int cb_type, const str *method,
	unsigned int code, char *buf, size_t len, const char *custom_name)
{
	if (custom_name)
		return custom_name;

	switch (cb_type) {
	case DLGCB_REQ_WITHIN:
		if (method && method->s && method->len) {
			int mlen = method->len;
			if (mlen > (int)len - 5)
				mlen = (int)len - 5;
			if (mlen < 0)
				mlen = 0;
			snprintf(buf, len, "req_%.*s", mlen, method->s);
			return buf;
		}
		return "req";
	case DLGCB_RESPONSE_FWDED:
	case DLGCB_RESPONSE_WITHIN:
		if (code) {
			snprintf(buf, len, "resp_%u", code);
			return buf;
		}
		return (cb_type == DLGCB_RESPONSE_WITHIN) ? "local_response" : "response";
	case DLGCB_CONFIRMED:
		return "confirmed";
	case DLGCB_FAILED:
		return "failed";
	case DLGCB_EARLY:
		return "early";
	case DLGCB_TERMINATED:
		return "terminated";
	case DLGCB_DESTROY:
		return "destroy";
	case DLGCB_EXPIRED:
		return "expired";
	case DLGCB_CREATED:
		return "created";
	case DLGCB_LOADED:
		return "loaded";
	default:
		return "dialog_event";
	}
}

static void tracing_emit_dialog_event(struct dlg_cell *dlg, int cb_type,
	struct dlg_cb_params *params, const char *custom_name, const str *method_hint)
{
	struct tracing_dialog_event info;
	struct sip_msg *msg = params ? params->msg : NULL;
	unsigned int direction = params ? params->direction : DLG_DIR_NONE;
	int dst_leg = -1;

	/* derive dst_leg from direction: upstream means caller (leg 0),
	 * downstream means callee (leg 1), none means unknown (-1) */
	if (direction == DLG_DIR_UPSTREAM)
		dst_leg = 0;
	else if (direction == DLG_DIR_DOWNSTREAM)
		dst_leg = 1;
	unsigned int code = 0;
	str method = STR_NULL;
	str cseq_no = STR_NULL;
	str cseq_method = STR_NULL;
	char event_buf[64];
	const char *event_name;
	int old_state = dlg ? dlg->state : DLG_STATE_UNCONFIRMED;

	if (!dlg)
		return;

	if (msg && msg != FAKED_REPLY) {
		if (msg->first_line.type == SIP_REQUEST) {
			method = msg->first_line.u.request.method;
		} else if (msg->first_line.type == SIP_REPLY) {
			code = msg->first_line.u.reply.statuscode;
		}
		(void)tracing_get_cseq(msg, &cseq_no, &cseq_method);
	}

	if ((!method.s || method.len == 0) && cseq_method.s && cseq_method.len > 0)
		method = cseq_method;

	if ((!method.s || method.len == 0) && method_hint && method_hint->s && method_hint->len)
		method = *method_hint;

	if (tracing_dlg_ctx_state >= 0 && tracing_dlg_api.dlg_ctx_get_int) {
		int stored = tracing_dlg_api.dlg_ctx_get_int(dlg, tracing_dlg_ctx_state);
		if (stored >= 0)
			old_state = stored;
		if (tracing_dlg_api.dlg_ctx_put_int)
			tracing_dlg_api.dlg_ctx_put_int(dlg, tracing_dlg_ctx_state, dlg->state);
	}

	event_name = tracing_format_event_name(cb_type, &method, code,
		event_buf, sizeof(event_buf), custom_name);

	memset(&info, 0, sizeof(info));
	info.callid = dlg->callid;

	info.parent_transaction_key =
		(((unsigned long long)dlg->initial_t_hash_index) << 32) |
		dlg->initial_t_label;

	info.event_name = event_name;
	info.event_id = cb_type;
	info.direction_id = direction;
	info.direction_name = tracing_direction_name(direction);
	info.old_state_id = old_state;
	info.old_state_name = tracing_state_name(old_state);
	info.new_state_id = dlg->state;
	info.new_state_name = tracing_state_name(dlg->state);
	info.dst_leg = dst_leg;
	info.method = method;
	info.code = code;
	info.cseq = cseq_no;
	(void)tracing_conn_chunk_ref(msg, &info.conn_chunk);
	if (msg)
		(void)tracing_get_via_branch(msg, &info.branch);

	tracing_run_dialog_event(&info);
}

