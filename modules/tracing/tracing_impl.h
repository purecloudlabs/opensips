#ifndef MODULES_TRACING_TRACING_IMPL_H
#define MODULES_TRACING_TRACING_IMPL_H

#include "../../str.h"
#include "../../tracing.h"

struct ip_addr;
struct tracing_tcp_connection_event {
	const char *event_name;
	unsigned long long conn_id;
	struct ip_addr *src_ip;
	unsigned short src_port;
	struct ip_addr *dst_ip;
	unsigned short dst_port;
	int proto;
	const char *extra_label;
	const char *extra_value;
	int worker_pid;
};
struct dlg_cell;
struct dlg_cb_params;
struct cell;
struct tmcb_params;
struct sip_msg;

extern str tracing_backend;
extern str tracing_db_url;
extern str tracing_db_table;
extern str tracing_db_col_timestamp;
extern str tracing_db_col_event;
extern str tracing_db_col_kind;
extern str tracing_db_col_payload;

int tracing_storage_init(void);
void tracing_storage_destroy(void);
int tracing_storage_child_init(int rank);
int tracing_storage_store_tcp_connection(const struct tracing_tcp_connection_event *info);
int tracing_storage_store_tcp_chunk(const struct tracing_tcp_chunk_event *info);
int tracing_storage_store_udp_datagram(const struct tracing_udp_datagram_event *info);
int tracing_storage_store_dialog(const struct tracing_dialog_event *info);
int tracing_storage_store_transaction(const struct tracing_transaction_event *info);
int tracing_storage_store_rest(const struct tracing_rest_event *info);
int tracing_storage_store_script_function(const struct tracing_script_function_event *info);

int tracing_tcp_init(void);
void tracing_tcp_destroy(void);

int tracing_udp_init(void);
void tracing_udp_destroy(void);

int tracing_dialog_init(void);
void tracing_dialog_destroy(void);

int tracing_tm_init(void);
void tracing_tm_destroy(void);

int tracing_rest_init(void);
void tracing_rest_destroy(void);

int tracing_script_init(void);
void tracing_script_destroy(void);

int tracing_conn_chunk_ref(struct sip_msg *msg,
	struct tracing_conn_chunk_ref *chunk_ref);
int tracing_get_via_branch(struct sip_msg *msg, str *branch);
int tracing_get_cseq(struct sip_msg *msg, str *number, str *method);
int tracing_get_callid(struct sip_msg *msg, str *callid);

#endif /* MODULES_TRACING_TRACING_IMPL_H */

