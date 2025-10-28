#ifndef TRACING_H_
#define TRACING_H_

#include "str.h"
#include "ip_addr.h"
#include "socket_info.h"

enum tracing_cb_type {
	TRACING_CB_TCP_CONNECTED = 0,
	TRACING_CB_TCP_PICKED_UP_BY_WORKER,
	TRACING_CB_TCP_DISCONNECTED,
	TRACING_CB_TCP_CHUNK_EVENT,
	TRACING_CB_UDP_DATAGRAM_EVENT,
	TRACING_CB_DIALOG_EVENT,
	TRACING_CB_TRANSACTION_EVENT,
	TRACING_CB_REST_EVENT,
	TRACING_CB_SCRIPT_FUNCTION_EVENT,
	TRACING_CB_LAST
};

struct tracing_conn_chunk_ref {
	unsigned long long conn_id;
	unsigned int seq_no;
};

struct tracing_tcp_chunk_event {
	const char *event_name;
	unsigned long long conn_id;
	unsigned int seq_no;
	int is_write;
	unsigned int payload_len;
	const struct ip_addr *src_ip;
	unsigned short src_port;
	const struct ip_addr *dst_ip;
	unsigned short dst_port;
	int proto;
};

struct tracing_udp_datagram_event {
	const char *event_name;
	unsigned int payload_len;
	const struct ip_addr *src_ip;
	unsigned short src_port;
	const struct ip_addr *dst_ip;
	unsigned short dst_port;
	int proto;
	unsigned int tv_sec;
	unsigned int tv_usec;
};

typedef void (tracing_tcp_connected_cb_t)(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, unsigned long long cid,
		unsigned int seq_no);
typedef void (tracing_tcp_picked_up_by_worker_cb_t)(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, int process_id,
		unsigned long long cid, unsigned int seq_no);
typedef void (tracing_tcp_disconnected_cb_t)(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, const char *reason,
		unsigned long long cid, unsigned int seq_no);
typedef void (tracing_tcp_chunk_event_cb_t)(const struct tracing_tcp_chunk_event *info);
typedef void (tracing_udp_datagram_event_cb_t)(const struct tracing_udp_datagram_event *info);

struct tracing_dialog_event {
	str callid;
	str branch;
	const char *event_name;
	const char *direction_name;
	const char *old_state_name;
	const char *new_state_name;
	int event_id;
	int old_state_id;
	int new_state_id;
	unsigned int direction_id;
	int dst_leg;
	str method;
	str cseq;
	unsigned int code;
	struct tracing_conn_chunk_ref conn_chunk;
	unsigned long long parent_transaction_key;
};

typedef void (tracing_dialog_event_cb_t)(const struct tracing_dialog_event *info);
struct tracing_transaction_event {
	const char *event_name;
	int event_id;
	const char *direction_name;
	int direction_id;
	unsigned long long transaction_correlation_key;
	struct tracing_conn_chunk_ref conn_chunk;
	unsigned int hash_index;
	unsigned int label;
	int is_local;
	str branch;
	str callid;
	str method;
	str cseq;
	unsigned int code;
};

typedef void (tracing_transaction_event_cb_t)(const struct tracing_transaction_event *info);

struct tracing_rest_event {
	str callid;
	str cseq;
	const char *event_name;
	int event_id;
	const char *method;
	const char *url;
	const char *correlation_id;
	unsigned int response_code;
	unsigned int request_len;
	unsigned int response_len;
	const char *remote_ip;
	unsigned short remote_port;
};

typedef void (tracing_rest_event_cb_t)(const struct tracing_rest_event *info);

struct tracing_script_function_event {
	str callid;
	str cseq;
	const char *event_name;          /* "call" or "return" */
	const char *function_name;       /* e.g. "route[process_invite]" */
	const char *caller_function;     /* calling function, NULL if main route */
	int depth;                       /* call stack depth */
	struct tracing_conn_chunk_ref conn_chunk;
};

typedef void (tracing_script_function_event_cb_t)(const struct tracing_script_function_event *info);

int register_tracing(enum tracing_cb_type type, void *callback);
void unregister_tracings(void);
void tracing_run_tcp_connected(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, unsigned long long cid,
		unsigned int seq_no);
void tracing_run_tcp_picked_up_by_worker(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, int process_id,
		unsigned long long cid, unsigned int seq_no);
void tracing_run_tcp_disconnected(struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port, int proto, const char *reason,
		unsigned long long cid, unsigned int seq_no);
void tracing_run_tcp_chunk_event(const struct tracing_tcp_chunk_event *info);
void tracing_run_udp_datagram_event(const struct tracing_udp_datagram_event *info);
void tracing_run_dialog_event(const struct tracing_dialog_event *info);
void tracing_run_transaction_event(const struct tracing_transaction_event *info);
void tracing_run_rest_event(const struct tracing_rest_event *info);
void tracing_run_script_function_event(const struct tracing_script_function_event *info);

#endif
