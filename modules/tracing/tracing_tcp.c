#include <stdio.h>
#include <unistd.h>

#include "../../dprint.h"
#include "../../ip_addr.h"

#include "tracing_impl.h"

static void tracing_tcp_connected_cb(struct ip_addr *src_ip, unsigned short src_port,
	struct ip_addr *dst_ip, unsigned short dst_port, int proto, unsigned long long cid,
	unsigned int seq_no);
static void tracing_tcp_picked_up_by_worker_cb(struct ip_addr *src_ip, unsigned short src_port,
	struct ip_addr *dst_ip, unsigned short dst_port, int proto, int process_id,
	unsigned long long cid, unsigned int seq_no);
static void tracing_tcp_disconnected_cb(struct ip_addr *src_ip, unsigned short src_port,
	struct ip_addr *dst_ip, unsigned short dst_port, int proto, const char *reason,
	unsigned long long cid, unsigned int seq_no);
static void tracing_tcp_chunk_event_cb(const struct tracing_tcp_chunk_event *info);

int tracing_tcp_init(void)
{
	if (register_tracing(TRACING_CB_TCP_CONNECTED, tracing_tcp_connected_cb) < 0) {
		LM_ERR("failed to register TCP connected tracing\n");
		return -1;
	}

	if (register_tracing(TRACING_CB_TCP_PICKED_UP_BY_WORKER,
			tracing_tcp_picked_up_by_worker_cb) < 0) {
		LM_ERR("failed to register TCP picked-up-by-worker tracing\n");
		goto error;
	}

	if (register_tracing(TRACING_CB_TCP_DISCONNECTED,
			tracing_tcp_disconnected_cb) < 0) {
		LM_ERR("failed to register TCP disconnected tracing\n");
		goto error;
	}

	if (register_tracing(TRACING_CB_TCP_CHUNK_EVENT,
			tracing_tcp_chunk_event_cb) < 0) {
		LM_ERR("failed to register TCP chunk tracing\n");
		goto error;
	}

	return 0;

error:
	unregister_tracings();
	return -1;
}

void tracing_tcp_destroy(void)
{
	/* nothing to clean up */
}

static void tracing_tcp_connected_cb(struct ip_addr *src_ip, unsigned short src_port,
	struct ip_addr *dst_ip, unsigned short dst_port, int proto, unsigned long long cid,
	unsigned int seq_no)
{
	struct tracing_tcp_connection_event info = {
		.event_name = "connected",
		.conn_id = cid,
		.src_ip = src_ip,
		.src_port = src_port,
		.dst_ip = dst_ip,
		.dst_port = dst_port,
		.proto = proto,
		.extra_label = NULL,
		.extra_value = NULL,
		.worker_pid = getpid()
	};

	if (!src_ip || !dst_ip) {
		LM_ERR("tracing_tcp_connect_cb: null ip addresses\n");
		return;
	}

	(void)seq_no;

	if (tracing_storage_store_tcp_connection(&info) < 0)
		LM_ERR("failed to persist tcp_connected event\n");
}

static void tracing_tcp_picked_up_by_worker_cb(struct ip_addr *src_ip, unsigned short src_port,
	struct ip_addr *dst_ip, unsigned short dst_port, int proto, int process_id,
	unsigned long long cid, unsigned int seq_no)
{
	char extra_val[16];
	struct tracing_tcp_connection_event info;

	if (!src_ip || !dst_ip) {
		LM_ERR("tracing_tcp_worker_pickup_cb: null ip addresses\n");
		return;
	}

	snprintf(extra_val, sizeof(extra_val), "%d", process_id);

	info.event_name = "worker_pickup";
	info.conn_id = cid;
	info.src_ip = src_ip;
	info.src_port = src_port;
	info.dst_ip = dst_ip;
	info.dst_port = dst_port;
	info.proto = proto;
	info.extra_label = "internal_pid";
	info.extra_value = extra_val;
	info.worker_pid = getpid();

	(void)seq_no;

	if (tracing_storage_store_tcp_connection(&info) < 0)
		LM_ERR("failed to persist tcp_worker_pickup event\n");
}

static void tracing_tcp_disconnected_cb(struct ip_addr *src_ip, unsigned short src_port,
	struct ip_addr *dst_ip, unsigned short dst_port, int proto, const char *reason,
	unsigned long long cid, unsigned int seq_no)
{
	struct tracing_tcp_connection_event info = {
		.event_name = "disconnected",
		.conn_id = cid,
		.src_ip = src_ip,
		.src_port = src_port,
		.dst_ip = dst_ip,
		.dst_port = dst_port,
		.proto = proto,
		.extra_label = (reason && reason[0]) ? "reason" : NULL,
		.extra_value = (reason && reason[0]) ? reason : NULL,
		.worker_pid = getpid()
	};

	if (!src_ip || !dst_ip) {
		LM_ERR("tracing_tcp_disconnected_cb: null ip addresses\n");
		return;
	}

	(void)seq_no;

	if (tracing_storage_store_tcp_connection(&info) < 0)
		LM_ERR("failed to persist tcp_disconnected event\n");
}

static void tracing_tcp_chunk_event_cb(const struct tracing_tcp_chunk_event *info)
{
	if (!info)
		return;

	if (tracing_storage_store_tcp_chunk(info) < 0)
		LM_ERR("failed to persist tcp chunk event '%s'\n",
			info->event_name ? info->event_name : "unknown");
}

