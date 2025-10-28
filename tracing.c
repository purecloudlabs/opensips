#include "tracing.h"
#include "dprint.h"

static tracing_tcp_connected_cb_t *tcp_connected_cb;
static tracing_tcp_picked_up_by_worker_cb_t *tcp_picked_up_by_worker_cb;
static tracing_tcp_disconnected_cb_t *tcp_disconnected_cb;

void unregister_tracings(void) {
	tcp_connected_cb = NULL;
	tcp_picked_up_by_worker_cb = NULL;
	tcp_disconnected_cb = NULL;
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
	default:
		LM_ERR("unknown tracing callback type: %d\n", type);
		return -1;
	}

	LM_DBG("registered tracing callback for type %d\n", type);
	return 0;
}

void tracing_run_tcp_connected(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, unsigned long long cid) {
	if (tcp_connected_cb) {
		tcp_connected_cb(src_ip, src_port, dst_ip, dst_port, proto, cid);
	}
}

void tracing_run_tcp_picked_up_by_worker(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, int process_id,
		unsigned long long cid) {
	if (tcp_picked_up_by_worker_cb) {
		tcp_picked_up_by_worker_cb(src_ip, src_port, dst_ip, dst_port, proto, process_id, cid);
	}
}

void tracing_run_tcp_disconnected(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, const char *reason,
		unsigned long long cid) {
	if (tcp_disconnected_cb) {
		tcp_disconnected_cb(src_ip, src_port, dst_ip, dst_port, proto, reason, cid);
	}
}
