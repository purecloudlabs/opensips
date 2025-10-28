#ifndef TRACING_H_
#define TRACING_H_

#include "str.h"
#include "ip_addr.h"
#include "socket_info.h"

enum tracing_cb_type {
	TRACING_CB_TCP_CONNECTED = 0,
	TRACING_CB_TCP_PICKED_UP_BY_WORKER,
	TRACING_CB_TCP_DISCONNECTED,
	TRACING_CB_LAST
};

typedef void (tracing_tcp_connected_cb_t)(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, unsigned long long cid);
typedef void (tracing_tcp_picked_up_by_worker_cb_t)(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, int process_id,
		unsigned long long cid);
typedef void (tracing_tcp_disconnected_cb_t)(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, const char *reason,
		unsigned long long cid);

int register_tracing(enum tracing_cb_type type, void *callback);
void unregister_tracings(void);
void tracing_run_tcp_connected(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, unsigned long long cid);
void tracing_run_tcp_picked_up_by_worker(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, int process_id,
		unsigned long long cid);
void tracing_run_tcp_disconnected(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, const char *reason,
		unsigned long long cid);

#endif
