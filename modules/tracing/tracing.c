#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <stdint.h>
#include <inttypes.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../pt.h"
#include "../../socket_info.h"
#include "../../ip_addr.h"
#include "../../tracing.h"
#include "../../sha1.h"

static int mod_init(void);
static void destroy(void);

static void tracing_tcp_connected_cb(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, unsigned long long cid);
static void tracing_tcp_picked_up_by_worker_cb(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, int process_id,
		unsigned long long cid);
static void tracing_tcp_disconnected_cb(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, const char *reason,
		unsigned long long cid);
static const char* proto_to_string(int proto);
struct module_exports exports= {
	"tracing",
	MOD_TYPE_DEFAULT,
	MODULE_VERSION,
	DEFAULT_DLFLAGS,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	mod_init,
	(response_function) 0,
	(destroy_function)destroy,
	0,
	0
};

static int mod_init(void) {
	if (register_tracing(TRACING_CB_TCP_CONNECTED, tracing_tcp_connected_cb) < 0) {
		LM_ERR("failed to register TCP connected tracing\n");
		return -1;
	}

	if (register_tracing(TRACING_CB_TCP_PICKED_UP_BY_WORKER, tracing_tcp_picked_up_by_worker_cb) < 0) {
		LM_ERR("failed to register TCP picked-up-by-worker tracing\n");
		return -1;
	}

	if (register_tracing(TRACING_CB_TCP_DISCONNECTED, tracing_tcp_disconnected_cb) < 0) {
		LM_ERR("failed to register TCP disconnect tracing\n");
		return -1;
	}

	return 0;
}

static void destroy(void) {
	unregister_tracings();
}

static void generate_tcp_correlation_id(unsigned long long cid, char *hash_str) {
	unsigned char hash[20];
	sha1_context ctx;
	int i;

	if (!hash_str)
		return;

	sha1_init(&ctx);
	sha1_starts(&ctx);
	sha1_update(&ctx, (unsigned char *)&cid, sizeof(cid));
	sha1_finish(&ctx, hash);
	sha1_free(&ctx);

	for (i = 0; i < 20; i++)
		sprintf(hash_str + (i * 2), "%02x", hash[i]);
	hash_str[40] = '\0';
}

static const char* proto_to_string(int proto) {
	switch (proto) {
		case PROTO_UDP: return "UDP";
		case PROTO_TCP: return "TCP";
		case PROTO_TLS: return "TLS";
		case PROTO_SCTP: return "SCTP";
		case PROTO_WS: return "WS";
		case PROTO_WSS: return "WSS";
		case PROTO_IPSEC: return "IPSEC";
		case PROTO_BIN: return "BIN";
		case PROTO_BINS: return "BINS";
		case PROTO_HEP_UDP: return "HEP_UDP";
		case PROTO_HEP_TCP: return "HEP_TCP";
		case PROTO_HEP_TLS: return "HEP_TLS";
		case PROTO_SMPP: return "SMPP";
		case PROTO_MSRP: return "MSRP";
		case PROTO_MSRPS: return "MSRPS";
		case PROTO_OTHER: return "OTHER";
		default: return "UNKNOWN";
	}
}

static void tracing_tcp_connected_cb(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, unsigned long long cid) {
	char correlation_id[41];

	if (!src_ip || !dst_ip) {
		LM_ERR("tracing_tcp_connect_cb: null ip addresses\n");
		return;
	}

	generate_tcp_correlation_id(cid, correlation_id);

	LM_INFO("TCP_CONNECTED: correlation_id=%s, pid=%d, src=%s:%d, dst=%s:%d, proto=%s\n",
		correlation_id, getpid(),
		ip_addr2a(src_ip), src_port,
		ip_addr2a(dst_ip), dst_port,
		proto_to_string(proto)
	);
}

static void tracing_tcp_picked_up_by_worker_cb(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, int process_id,
		unsigned long long cid) {
	char correlation_id[41];

	if (!src_ip || !dst_ip) {
		LM_ERR("tracing_tcp_worker_pickup_cb: null ip addresses\n");
		return;
	}

	generate_tcp_correlation_id(cid, correlation_id);

	LM_INFO("TCP_PICKED_UP_BY_WORKER: correlation_id=%s, pid=%d, src=%s:%d, dst=%s:%d, proto=%s, internal_process_id=%d\n",
		correlation_id, getpid(),
		ip_addr2a(src_ip), src_port,
		ip_addr2a(dst_ip), dst_port,
		proto_to_string(proto),
		process_id
	);
}

static void tracing_tcp_disconnected_cb(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, const char *reason,
		unsigned long long cid) {
	char correlation_id[41];
	const char *reason_str = reason ? reason : "unknown";

	if (!src_ip || !dst_ip) {
		LM_ERR("tracing_tcp_disconnect_cb: null ip addresses\n");
		return;
	}

	generate_tcp_correlation_id(cid, correlation_id);

	LM_INFO("TCP_DISCONNECT: correlation_id=%s, pid=%d, src=%s:%d, dst=%s:%d, proto=%s, reason=%s\n",
		correlation_id, getpid(),
		ip_addr2a(src_ip), src_port,
		ip_addr2a(dst_ip), dst_port,
		proto_to_string(proto),
		reason_str
	);
}
