#include "tracing.h"
#include "dprint.h"

static tracing_tcp_connected_cb_t *tcp_connected_cb;
static tracing_tcp_picked_up_by_worker_cb_t *tcp_picked_up_by_worker_cb;
static tracing_tcp_disconnected_cb_t *tcp_disconnected_cb;
static tracing_tcp_chunk_event_cb_t *tcp_chunk_event_cb;
static tracing_udp_datagram_event_cb_t *udp_datagram_event_cb;
static tracing_dialog_event_cb_t *dialog_event_cb;
static tracing_transaction_event_cb_t *transaction_event_cb;
static tracing_rest_event_cb_t *rest_event_cb;
static tracing_script_function_event_cb_t *script_function_event_cb;

void unregister_tracings(void) {
	tcp_connected_cb = NULL;
	tcp_picked_up_by_worker_cb = NULL;
	tcp_disconnected_cb = NULL;
	tcp_chunk_event_cb = NULL;
	udp_datagram_event_cb = NULL;
	dialog_event_cb = NULL;
	transaction_event_cb = NULL;
	rest_event_cb = NULL;
	script_function_event_cb = NULL;
}

int register_tracing(enum tracing_cb_type type, void *callback) {
	if (type >= TRACING_CB_LAST) {
		LM_ERR("invalid tracing callback type: %d\n", type);
		return -1;
	}

	if (!callback) {
		LM_ERR("null callback function\n");
		return -1;
	}

	switch (type) {
	case TRACING_CB_TCP_CONNECTED:
		if (tcp_connected_cb)
			LM_WARN("tracing callback type %d already registered, replacing\n", type);
		tcp_connected_cb = (tracing_tcp_connected_cb_t *)callback;
		break;
	case TRACING_CB_TCP_PICKED_UP_BY_WORKER:
		if (tcp_picked_up_by_worker_cb)
			LM_WARN("tracing callback type %d already registered, replacing\n", type);
		tcp_picked_up_by_worker_cb = (tracing_tcp_picked_up_by_worker_cb_t *)callback;
		break;
	case TRACING_CB_TCP_DISCONNECTED:
		if (tcp_disconnected_cb)
			LM_WARN("tracing callback type %d already registered, replacing\n", type);
		tcp_disconnected_cb = (tracing_tcp_disconnected_cb_t *)callback;
		break;
	case TRACING_CB_TCP_CHUNK_EVENT:
		if (tcp_chunk_event_cb)
			LM_WARN("tracing callback type %d already registered, replacing\n", type);
		tcp_chunk_event_cb = (tracing_tcp_chunk_event_cb_t *)callback;
		break;
	case TRACING_CB_UDP_DATAGRAM_EVENT:
		if (udp_datagram_event_cb)
			LM_WARN("tracing callback type %d already registered, replacing\n", type);
		udp_datagram_event_cb = (tracing_udp_datagram_event_cb_t *)callback;
		break;
	case TRACING_CB_DIALOG_EVENT:
		if (dialog_event_cb)
			LM_WARN("tracing callback type %d already registered, replacing\n", type);
		dialog_event_cb = (tracing_dialog_event_cb_t *)callback;
		break;
	case TRACING_CB_TRANSACTION_EVENT:
		if (transaction_event_cb)
			LM_WARN("tracing callback type %d already registered, replacing\n", type);
		transaction_event_cb = (tracing_transaction_event_cb_t *)callback;
		break;
	case TRACING_CB_REST_EVENT:
		if (rest_event_cb)
			LM_WARN("tracing callback type %d already registered, replacing\n", type);
		rest_event_cb = (tracing_rest_event_cb_t *)callback;
		break;
	case TRACING_CB_SCRIPT_FUNCTION_EVENT:
		if (script_function_event_cb)
			LM_WARN("tracing callback type %d already registered, replacing\n", type);
		script_function_event_cb = (tracing_script_function_event_cb_t *)callback;
		break;
	default:
		LM_ERR("unknown tracing callback type: %d\n", type);
		return -1;
	}

	LM_DBG("registered tracing callback for type %d\n", type);
	return 0;
}

void tracing_run_tcp_connected(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, unsigned long long cid,
		unsigned int seq_no) {
	if (tcp_connected_cb) {
		tcp_connected_cb(src_ip, src_port, dst_ip, dst_port, proto, cid, seq_no);
	}
}

void tracing_run_tcp_picked_up_by_worker(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, int process_id,
		unsigned long long cid, unsigned int seq_no) {
	if (tcp_picked_up_by_worker_cb) {
		tcp_picked_up_by_worker_cb(src_ip, src_port, dst_ip, dst_port, proto, process_id, cid, seq_no);
	}
}

void tracing_run_tcp_disconnected(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, const char *reason,
		unsigned long long cid, unsigned int seq_no) {
	if (tcp_disconnected_cb) {
		tcp_disconnected_cb(src_ip, src_port, dst_ip, dst_port, proto, reason, cid, seq_no);
	}
}

void tracing_run_tcp_chunk_event(const struct tracing_tcp_chunk_event *info) {
	if (tcp_chunk_event_cb && info) {
		tcp_chunk_event_cb(info);
	}
}

void tracing_run_udp_datagram_event(const struct tracing_udp_datagram_event *info) {
	if (udp_datagram_event_cb && info) {
		udp_datagram_event_cb(info);
	}
}

void tracing_run_dialog_event(const struct tracing_dialog_event *info) {
	if (dialog_event_cb && info) {
		dialog_event_cb(info);
	}
}

void tracing_run_transaction_event(const struct tracing_transaction_event *info) {
	if (transaction_event_cb && info) {
		transaction_event_cb(info);
	}
}

void tracing_run_rest_event(const struct tracing_rest_event *info) {
	if (rest_event_cb && info) {
		rest_event_cb(info);
	}
}

void tracing_run_script_function_event(const struct tracing_script_function_event *info) {
	if (script_function_event_cb && info) {
		script_function_event_cb(info);
	}
}
