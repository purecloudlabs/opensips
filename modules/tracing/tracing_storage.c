#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../db/db.h"
#include "../../error.h"
#include "../../socket_info.h"
#include "../../ip_addr.h"
#include "../../sha1.h"
#include "../../lib/cJSON.h"
#include "../../action.h"

#include "tracing_impl.h"

#define TRACE_ENDPOINT_BUF_LEN (IP_ADDR_MAX_STR_SIZE + 8)

str tracing_backend = STR_NULL;
str tracing_db_url = STR_NULL;
str tracing_db_table = STR_NULL;
str tracing_db_col_timestamp = STR_NULL;
str tracing_db_col_event = STR_NULL;
str tracing_db_col_kind = STR_NULL;
str tracing_db_col_payload = STR_NULL;

static db_func_t tracing_dbf;
static db_con_t *tracing_db_con;
static int tracing_db_bound;

static void tracing_db_close(void);
static int tracing_db_connect(void);
static int tracing_bind_db_module(void);
static int tracing_db_insert(const char *kind, const char *event, const char *payload);

static void tracing_json_add_str_field(cJSON *obj, const char *name, const str *value);
static void tracing_json_add_string(cJSON *obj, const char *name, const char *value);
static cJSON *tracing_json_get_or_create_parent_ids(cJSON *obj);
static void tracing_json_add_parent_ids_entry(cJSON *obj, const char *group, const char *value);
static void tracing_json_add_number_or_null(cJSON *obj, const char *name,
	long long value, int has_value);
static char *tracing_sanitize_str(const str *value, int *out_len);
static void tracing_json_add_timestamp(cJSON *obj, const struct timeval *tv);
static void tracing_json_add_datetime(cJSON *obj, const struct timeval *tv);
static cJSON *tracing_json_create_root(const char *group, const char *event);
static int tracing_store_json(const char *kind, const char *event, cJSON *payload);
static void generate_correlation_id(unsigned long long cid, unsigned int seq_no, 
	const struct timeval *tv, char *hash_str);
static void generate_connection_correlation_id(unsigned long long cid, 
	const struct timeval *tv, char *hash_str);
static void generate_hash_id(const str *input, char *hash_str, size_t len);
static void generate_transaction_hash_id(const str *callid, const str *cseq,
	char *hash_str, size_t len);
static void format_endpoint(const struct ip_addr *ip, unsigned short port, char *out, size_t len);

int tracing_storage_init(void)
{
	tracing_db_con = NULL;

	if (!tracing_db_table.s || tracing_db_table.s[0] == '\0')
		tracing_db_table = str_init("tracing_events");
	else
		tracing_db_table.len = strlen(tracing_db_table.s);

	if (!tracing_db_col_timestamp.s || tracing_db_col_timestamp.s[0] == '\0')
		tracing_db_col_timestamp = str_init("timestamp");
	else
		tracing_db_col_timestamp.len = strlen(tracing_db_col_timestamp.s);

	if (!tracing_db_col_payload.s || tracing_db_col_payload.s[0] == '\0')
		tracing_db_col_payload = str_init("payload");
	else
		tracing_db_col_payload.len = strlen(tracing_db_col_payload.s);

	if (tracing_db_col_kind.s && tracing_db_col_kind.s[0] != '\0')
		tracing_db_col_kind.len = strlen(tracing_db_col_kind.s);
	else
		tracing_db_col_kind = STR_NULL;

	if (tracing_db_col_event.s && tracing_db_col_event.s[0] != '\0')
		tracing_db_col_event.len = strlen(tracing_db_col_event.s);
	else
		tracing_db_col_event = STR_NULL;

	if (!tracing_backend.s || tracing_backend.s[0] == '\0')
		tracing_backend = str_init("db");
	else
		tracing_backend.len = strlen(tracing_backend.s);

	if (!(strcasecmp(tracing_backend.s, "flatstore") == 0 ||
			strcasecmp(tracing_backend.s, "db") == 0 ||
			strcasecmp(tracing_backend.s, "database") == 0)) {
		LM_ERR("unsupported tracing backend '%s'\n", tracing_backend.s);
		return -1;
	}

	if (!tracing_db_url.s || tracing_db_url.s[0] == '\0') {
		LM_ERR("database backend selected but db_url is not configured\n");
		return -1;
	}

	tracing_db_url.len = strlen(tracing_db_url.s);
	tracing_db_bound = 0;

	LM_INFO("tracing backend configured for database url %.*s\n",
		tracing_db_url.len, tracing_db_url.s);

	return 0;
}

void tracing_storage_destroy(void)
{
	tracing_db_close();
	tracing_db_bound = 0;
}

int tracing_storage_child_init(int rank)
{
	(void)rank;

	if (tracing_db_connect() < 0) {
		LM_ERR("unable to initialize tracing storage backend in process rank %d\n", rank);
		return -1;
	}

	return 0;
}

int tracing_storage_store_tcp_connection(const struct tracing_tcp_connection_event *info)
{
	cJSON *root;
	cJSON *data;
	char conn_corr_id[41];
	char src_ep[TRACE_ENDPOINT_BUF_LEN];
	char dst_ep[TRACE_ENDPOINT_BUF_LEN];
	struct timeval tv;

	if (!info || !info->event_name)
		return 0;

	root = tracing_json_create_root("tcp", info->event_name);
	if (!root)
		return -1;

	data = cJSON_CreateObject();
	if (!data) {
		cJSON_Delete(root);
		return -1;
	}

	gettimeofday(&tv, NULL);
	generate_connection_correlation_id(info->conn_id, &tv, conn_corr_id);

	tracing_json_add_string(root, "id", conn_corr_id);
	tracing_json_add_timestamp(root, &tv);
	tracing_json_add_datetime(root, &tv);
	tracing_json_add_string(root, "group", "tcp_connection");
	tracing_json_add_string(root, "event", info->event_name);
	cJSON_AddItemToObjectCS(root, "data", data);
	tracing_json_get_or_create_parent_ids(root);
	if (info->event_name && strcmp(info->event_name, "worker_pickup") == 0) {
		if (info->extra_label && info->extra_label[0] &&
				info->extra_value && info->extra_value[0]) {
			tracing_json_add_string(data, info->extra_label, info->extra_value);
		}
	} else {
		format_endpoint(info->src_ip, info->src_port, src_ep, sizeof(src_ep));
		format_endpoint(info->dst_ip, info->dst_port, dst_ep, sizeof(dst_ep));

		tracing_json_add_string(data, "src", src_ep);
		tracing_json_add_string(data, "dst", dst_ep);

		if (info->extra_label && info->extra_label[0] &&
				info->extra_value && info->extra_value[0]) {
			tracing_json_add_string(data, info->extra_label, info->extra_value);
		}
	}

	if (info->worker_pid > 0)
		cJSON_AddItemToObjectCS(data, "pid",
			cJSON_CreateNumber((double)info->worker_pid));

	return tracing_store_json("tcp", info->event_name, root);
}

int tracing_storage_store_tcp_chunk(const struct tracing_tcp_chunk_event *info)
{
	cJSON *root;
	cJSON *data;
	char conn_corr_id[41];
	char chunk_corr_id[41];
	unsigned int corr_seq = 0;
	const char *parent_id = NULL;
	struct timeval tv;

	if (!info || !info->event_name)
		return 0;

	root = tracing_json_create_root("tcp_chunk", info->event_name);
	if (!root)
		return -1;

	data = cJSON_CreateObject();
	if (!data) {
		cJSON_Delete(root);
		return -1;
	}

	corr_seq = info->seq_no;
	if (info->is_write)
		corr_seq |= (1U << 31);

	gettimeofday(&tv, NULL);
	generate_connection_correlation_id(info->conn_id, &tv, conn_corr_id);
	generate_correlation_id(info->conn_id, corr_seq, &tv, chunk_corr_id);

	parent_id = conn_corr_id[0] ? conn_corr_id : NULL;

	tracing_json_add_string(root, "id", chunk_corr_id);
	tracing_json_add_timestamp(root, &tv);
	tracing_json_add_datetime(root, &tv);
	tracing_json_add_string(root, "group", "tcp_chunk");
	tracing_json_add_string(root, "event", info->event_name);
	cJSON_AddItemToObjectCS(root, "data", data);
	if (parent_id)
		tracing_json_add_parent_ids_entry(root, "tcp_connection", parent_id);
	cJSON_AddItemToObjectCS(data, "payload_len",
		cJSON_CreateNumber((double)info->payload_len));

	return tracing_store_json("tcp_chunk", info->event_name, root);
}

int tracing_storage_store_udp_datagram(const struct tracing_udp_datagram_event *info)
{
	cJSON *root;
	cJSON *data;
	char src_ep[TRACE_ENDPOINT_BUF_LEN];
	char dst_ep[TRACE_ENDPOINT_BUF_LEN];
	char udp_corr_id[41];
	struct timeval tv;

	if (!info || !info->event_name)
		return 0;

	root = tracing_json_create_root("udp", info->event_name);
	if (!root)
		return -1;

	data = cJSON_CreateObject();
	if (!data) {
		cJSON_Delete(root);
		return -1;
	}

	/* Use the timestamp from the event (captured when packet was received/sent) */
	tv.tv_sec = (time_t)info->tv_sec;
	tv.tv_usec = (long)info->tv_usec;
	
	/* Generate correlation ID using the exact same timestamp */
	generate_correlation_id(0, 0, &tv, udp_corr_id);

	format_endpoint(info->src_ip, info->src_port, src_ep, sizeof(src_ep));
	format_endpoint(info->dst_ip, info->dst_port, dst_ep, sizeof(dst_ep));

	tracing_json_add_string(root, "id", udp_corr_id);
	tracing_json_add_timestamp(root, &tv);
	tracing_json_add_datetime(root, &tv);
	tracing_json_add_string(root, "group", "udp");
	tracing_json_add_string(root, "event", info->event_name);
	cJSON_AddItemToObjectCS(root, "data", data);
	tracing_json_get_or_create_parent_ids(root);

	tracing_json_add_string(data, "src", src_ep);
	tracing_json_add_string(data, "dst", dst_ep);
	cJSON_AddItemToObjectCS(data, "payload_len",
		cJSON_CreateNumber((double)info->payload_len));
	cJSON_AddItemToObjectCS(data, "pid",
		cJSON_CreateNumber((double)getpid()));

	return tracing_store_json("udp", info->event_name, root);
}

static void generate_hash_id(const str *input, char *hash_str, size_t len)
{
	unsigned char hash[20];
	sha1_context ctx;
	char local[41];
	int i;
	size_t limit;

	if (!hash_str || len == 0)
		return;

	hash_str[0] = '\0';

	if (!input || !input->s || input->len <= 0)
		return;

	sha1_init(&ctx);
	sha1_starts(&ctx);
	sha1_update(&ctx, (unsigned char *)input->s, (unsigned int)input->len);
	sha1_finish(&ctx, hash);
	sha1_free(&ctx);

	for (i = 0; i < 5; i++)
		sprintf(local + (i * 2), "%02x", hash[i]);
	local[10] = '\0';

	limit = (len - 1) < 10 ? (len - 1) : 10;
	memcpy(hash_str, local, limit);
	hash_str[limit] = '\0';
}

static void generate_transaction_hash_id(const str *callid, const str *cseq,
	char *hash_str, size_t len)
{
	unsigned char hash[20];
	sha1_context ctx;
	char local[41];
	size_t limit;
	int i;
	unsigned char sep = ':';

	if (!hash_str || len == 0)
		return;

	hash_str[0] = '\0';

	if (!callid || !callid->s || callid->len <= 0 ||
			!cseq || !cseq->s || cseq->len <= 0)
		return;

	sha1_init(&ctx);
	sha1_starts(&ctx);
	sha1_update(&ctx, (unsigned char *)callid->s, (unsigned int)callid->len);
	sha1_update(&ctx, &sep, sizeof(sep));
	sha1_update(&ctx, (unsigned char *)cseq->s, (unsigned int)cseq->len);
	sha1_finish(&ctx, hash);
	sha1_free(&ctx);

	for (i = 0; i < 5; i++)
		sprintf(local + (i * 2), "%02x", hash[i]);
	local[10] = '\0';

	limit = (len - 1) < 10 ? (len - 1) : 10;
	memcpy(hash_str, local, limit);
	hash_str[limit] = '\0';
}

int tracing_storage_store_dialog(const struct tracing_dialog_event *info)
{
	cJSON *root;
	cJSON *data;
	char id_buf[41];
	char parent_transaction_buf[41];
	char parent_corr_buf[41];
	char parent_chunk_buf[41];
	char parent_conn_buf[41];
	str callid = STR_NULL;
	struct timeval tv;
	struct parent_link {
		const char *group;
		const char *value;
	};
	struct parent_link parents[4];
	int parent_count = 0;
	int i;

	if (!info)
		return 0;

	root = tracing_json_create_root("dialog", info->event_name);
	if (!root)
		return -1;

	data = cJSON_CreateObject();
	if (!data) {
		cJSON_Delete(root);
		return -1;
	}

	generate_transaction_hash_id(&info->callid, &info->cseq,
		parent_transaction_buf, sizeof(parent_transaction_buf));
	if (!parent_transaction_buf[0]) {
		str branch = info->branch;

		generate_hash_id(&branch, parent_transaction_buf,
			sizeof(parent_transaction_buf));
	}
	if (parent_transaction_buf[0]) {
		parents[parent_count].group = "transaction";
		parents[parent_count].value = parent_transaction_buf;
		parent_count++;
	}

	parent_chunk_buf[0] = '\0';
	parent_conn_buf[0] = '\0';
	gettimeofday(&tv, NULL);
	
	/* Check if this is UDP (conn_id contains timestamp seconds) or TCP */
	/* UDP timestamps are typically > 1000000000 (year 2001), TCP conn_ids are much smaller */
	if (info->conn_chunk.conn_id > 1000000000ULL) {
		/* UDP: conn_id has seconds, seq_no has microseconds */
		struct timeval udp_tv;
		udp_tv.tv_sec = (time_t)info->conn_chunk.conn_id;
		udp_tv.tv_usec = (long)info->conn_chunk.seq_no;
		generate_correlation_id(0, 0, &udp_tv, parent_chunk_buf);
		if (parent_chunk_buf[0] && parent_count < (int)(sizeof(parents)/sizeof(parents[0]))) {
			parents[parent_count].group = "udp";
			parents[parent_count].value = parent_chunk_buf;
			parent_count++;
		}
	} else if (info->conn_chunk.conn_id) {
		/* TCP: Link to TCP chunk and connection */
		generate_correlation_id(info->conn_chunk.conn_id,
			info->conn_chunk.seq_no, &tv, parent_chunk_buf);
		if (parent_chunk_buf[0] && parent_count < (int)(sizeof(parents)/sizeof(parents[0]))) {
			parents[parent_count].group = "tcp_chunk";
			parents[parent_count].value = parent_chunk_buf;
			parent_count++;
		}
		generate_connection_correlation_id(info->conn_chunk.conn_id,
			&tv, parent_conn_buf);
		if (parent_conn_buf[0] && parent_count < (int)(sizeof(parents)/sizeof(parents[0]))) {
			parents[parent_count].group = "tcp_connection";
			parents[parent_count].value = parent_conn_buf;
			parent_count++;
		}
	}

	if (info->parent_transaction_key) {
		generate_correlation_id(info->parent_transaction_key, 0, &tv, parent_corr_buf);
		if (parent_count == 0 && parent_corr_buf[0] && parent_count < (int)(sizeof(parents)/sizeof(parents[0]))) {
			parents[parent_count].group = "transaction";
			parents[parent_count].value = parent_corr_buf;
			parent_count++;
		}
	}

	callid = info->callid;
	generate_hash_id(&callid, id_buf, sizeof(id_buf));
	tracing_json_add_string(root, "id", id_buf[0] ? id_buf : NULL);
	tracing_json_add_timestamp(root, &tv);
	tracing_json_add_datetime(root, &tv);
	tracing_json_add_string(root, "group", "dialog");
	tracing_json_add_string(root, "event", info->event_name);
	cJSON_AddItemToObjectCS(root, "data", data);

	if (parent_count == 0)
		(void)tracing_json_get_or_create_parent_ids(root);
	for (i = 0; i < parent_count; i++)
		tracing_json_add_parent_ids_entry(root, parents[i].group, parents[i].value);
	tracing_json_add_string(data, "direction", info->direction_name);
	tracing_json_add_str_field(data, "method", &info->method);
	tracing_json_add_str_field(data, "cseq", &info->cseq);
	tracing_json_add_number_or_null(data, "code", info->code, info->code > 0);
	tracing_json_add_str_field(data, "callid", &info->callid);
	tracing_json_add_str_field(data, "branch", &info->branch);

	return tracing_store_json("dialog", info->event_name, root);
}

int tracing_storage_store_transaction(const struct tracing_transaction_event *info)
{
	cJSON *root;
	cJSON *data;
	char id_buf[41];
	char conn_chunk[41];
	char conn_parent_buf[41];
	struct timeval tv;
	struct parent_link {
		const char *group;
		const char *value;
	};
	struct parent_link parents[2];
	int parent_count = 0;
	int i;

	if (!info)
		return 0;

	root = tracing_json_create_root("transaction", info->event_name);
	if (!root)
		return -1;

	data = cJSON_CreateObject();
	if (!data) {
		cJSON_Delete(root);
		return -1;
	}

	conn_chunk[0] = '\0';
	conn_parent_buf[0] = '\0';
	gettimeofday(&tv, NULL);
	
	/* Check if this is UDP (conn_id contains timestamp seconds) or TCP */
	/* UDP timestamps are typically > 1000000000 (year 2001), TCP conn_ids are much smaller */
	if (info->conn_chunk.conn_id > 1000000000ULL) {
		/* UDP: conn_id has seconds, seq_no has microseconds */
		struct timeval udp_tv;
		udp_tv.tv_sec = (time_t)info->conn_chunk.conn_id;
		udp_tv.tv_usec = (long)info->conn_chunk.seq_no;
		generate_correlation_id(0, 0, &udp_tv, conn_chunk);
		if (conn_chunk[0]) {
			parents[parent_count].group = "udp";
			parents[parent_count].value = conn_chunk;
			parent_count++;
		}
	} else if (info->conn_chunk.conn_id) {
		/* TCP: Link to TCP chunk and connection */
		generate_correlation_id(info->conn_chunk.conn_id,
			info->conn_chunk.seq_no, &tv, conn_chunk);
		if (conn_chunk[0]) {
			parents[parent_count].group = "tcp_chunk";
			parents[parent_count].value = conn_chunk;
			parent_count++;
		}
		generate_connection_correlation_id(info->conn_chunk.conn_id,
			&tv, conn_parent_buf);
		if (conn_parent_buf[0] && parent_count < (int)(sizeof(parents)/sizeof(parents[0]))) {
			parents[parent_count].group = "tcp_connection";
			parents[parent_count].value = conn_parent_buf;
			parent_count++;
		}
	}

	generate_transaction_hash_id(&info->callid, &info->cseq, id_buf, sizeof(id_buf));
	if (!id_buf[0]) {
		str branch = info->branch;

		generate_hash_id(&branch, id_buf, sizeof(id_buf));
	}
	tracing_json_add_string(root, "id", id_buf[0] ? id_buf : NULL);
	tracing_json_add_timestamp(root, &tv);
	tracing_json_add_datetime(root, &tv);
	tracing_json_add_string(root, "group", "transaction");
	tracing_json_add_string(root, "event", info->event_name);
	cJSON_AddItemToObjectCS(root, "data", data);

	if (parent_count == 0)
		(void)tracing_json_get_or_create_parent_ids(root);
	for (i = 0; i < parent_count; i++)
		tracing_json_add_parent_ids_entry(root, parents[i].group, parents[i].value);
	cJSON_AddItemToObjectCS(data, "direction", cJSON_CreateString(info->direction_name));
	tracing_json_add_str_field(data, "method", &info->method);
	tracing_json_add_str_field(data, "cseq", &info->cseq);
	tracing_json_add_number_or_null(data, "code", info->code, info->code > 0);
	tracing_json_add_str_field(data, "callid", &info->callid);
	tracing_json_add_str_field(data, "branch", &info->branch);

	return tracing_store_json("transaction", info->event_name, root);
}

int tracing_storage_store_rest(const struct tracing_rest_event *info)
{
	cJSON *root;
	cJSON *data;
	char id_buf[64];
	char parent_script_buf[41];
	str correlation_str;
	str callid_str;
	struct timeval tv;

	if (!info)
		return 0;

	root = tracing_json_create_root("rest", info->event_name);
	if (!root)
		return -1;

	data = cJSON_CreateObject();
	if (!data) {
		cJSON_Delete(root);
		return -1;
	}

	gettimeofday(&tv, NULL);

	/* Use correlation_id as input to hash - both start and complete use same input */
	if (info->correlation_id && info->correlation_id[0]) {
		/* Hash the correlation_id - both events will get the same hash */
		correlation_str.s = (char *)info->correlation_id;
		correlation_str.len = strlen(info->correlation_id);
		generate_hash_id(&correlation_str, id_buf, sizeof(id_buf));
	} else if (info->callid.s && info->callid.len > 0) {
		callid_str = info->callid;
		generate_hash_id(&callid_str, id_buf, sizeof(id_buf));
	} else {
		/* Fall back to timestamp-based ID */
		generate_correlation_id(0, 0, &tv, id_buf);
	}

	tracing_json_add_string(root, "id", id_buf[0] ? id_buf : NULL);
	tracing_json_add_timestamp(root, &tv);
	tracing_json_add_datetime(root, &tv);
	tracing_json_add_string(root, "group", "rest");
	tracing_json_add_string(root, "event", info->event_name);
	cJSON_AddItemToObjectCS(root, "data", data);

	/* Link to parent script function - REST calls are triggered by script functions */
	/* Get current route name from route stack and generate its hash as parent ID */
	parent_script_buf[0] = '\0';
	if (route_stack_size > route_stack_start) {
		const char *current_route = route_stack[route_stack_size - 1];
		if (current_route && current_route[0]) {
			char route_name_buf[256];
			str func_name_str;
			snprintf(route_name_buf, sizeof(route_name_buf), "route[%s]", current_route);
			func_name_str.s = route_name_buf;
			func_name_str.len = strlen(route_name_buf);
			generate_hash_id(&func_name_str, parent_script_buf, sizeof(parent_script_buf));
		}
	}
	if (parent_script_buf[0]) {
		tracing_json_add_parent_ids_entry(root, "script", parent_script_buf);
	} else {
		tracing_json_get_or_create_parent_ids(root);
	}

	/* Add REST specific fields */
	tracing_json_add_string(data, "method", info->method);
	tracing_json_add_string(data, "url", info->url);
	if (info->correlation_id)
		tracing_json_add_string(data, "correlation_id", info->correlation_id);
	tracing_json_add_str_field(data, "callid", &info->callid);
	tracing_json_add_str_field(data, "cseq", &info->cseq);
	tracing_json_add_number_or_null(data, "response_code", info->response_code, info->response_code > 0);
	
	if (info->request_len > 0) {
		cJSON_AddItemToObjectCS(data, "request_len",
			cJSON_CreateNumber((double)info->request_len));
	}
	if (info->response_len > 0) {
		cJSON_AddItemToObjectCS(data, "response_len",
			cJSON_CreateNumber((double)info->response_len));
	}
	
	if (info->remote_ip) {
		char remote_ep[TRACE_ENDPOINT_BUF_LEN];
		snprintf(remote_ep, sizeof(remote_ep), "%s:%d", 
			info->remote_ip, info->remote_port);
		tracing_json_add_string(data, "remote", remote_ep);
	}

	cJSON_AddItemToObjectCS(data, "pid",
		cJSON_CreateNumber((double)getpid()));

	return tracing_store_json("rest", info->event_name, root);
}

int tracing_storage_store_script_function(const struct tracing_script_function_event *info)
{
	cJSON *root;
	cJSON *data;
	char id_buf[64];
	char conn_chunk_buf[41];
	char conn_parent_buf[41];
	str func_name_str;
	struct timeval tv;
	struct parent_link {
		const char *group;
		const char *value;
	};
	struct parent_link parents[2];
	int parent_count = 0;
	int i;

	if (!info)
		return 0;

	root = tracing_json_create_root("script", info->event_name);
	if (!root)
		return -1;

	data = cJSON_CreateObject();
	if (!data) {
		cJSON_Delete(root);
		return -1;
	}

	conn_chunk_buf[0] = '\0';
	conn_parent_buf[0] = '\0';
	gettimeofday(&tv, NULL);

	/* Link to UDP or TCP based on conn_chunk */
	/* Check if this is UDP (conn_id contains timestamp seconds) or TCP */
	/* UDP timestamps are typically > 1000000000 (year 2001), TCP conn_ids are much smaller */
	if (info->conn_chunk.conn_id > 1000000000ULL) {
		/* UDP: conn_id has seconds, seq_no has microseconds */
		struct timeval udp_tv;
		udp_tv.tv_sec = (time_t)info->conn_chunk.conn_id;
		udp_tv.tv_usec = (long)info->conn_chunk.seq_no;
		generate_correlation_id(0, 0, &udp_tv, conn_chunk_buf);
		if (conn_chunk_buf[0]) {
			parents[parent_count].group = "udp";
			parents[parent_count].value = conn_chunk_buf;
			parent_count++;
		}
	} else if (info->conn_chunk.conn_id) {
		/* TCP: Link to TCP chunk and connection */
		generate_correlation_id(info->conn_chunk.conn_id,
			info->conn_chunk.seq_no, &tv, conn_chunk_buf);
		if (conn_chunk_buf[0]) {
			parents[parent_count].group = "tcp_chunk";
			parents[parent_count].value = conn_chunk_buf;
			parent_count++;
		}
		generate_connection_correlation_id(info->conn_chunk.conn_id,
			&tv, conn_parent_buf);
		if (conn_parent_buf[0] && parent_count < (int)(sizeof(parents)/sizeof(parents[0]))) {
			parents[parent_count].group = "tcp_connection";
			parents[parent_count].value = conn_parent_buf;
			parent_count++;
		}
	}

	/* Generate ID based on function name and timestamp */
	if (info->function_name && info->function_name[0]) {
		func_name_str.s = (char *)info->function_name;
		func_name_str.len = strlen(info->function_name);
		generate_hash_id(&func_name_str, id_buf, sizeof(id_buf));
	} else {
		/* Fall back to timestamp-based ID */
		generate_correlation_id(0, 0, &tv, id_buf);
	}

	tracing_json_add_string(root, "id", id_buf[0] ? id_buf : NULL);
	tracing_json_add_timestamp(root, &tv);
	tracing_json_add_datetime(root, &tv);
	tracing_json_add_string(root, "group", "script");
	tracing_json_add_string(root, "event", info->event_name);
	cJSON_AddItemToObjectCS(root, "data", data);

	/* Add parent links */
	if (parent_count == 0)
		(void)tracing_json_get_or_create_parent_ids(root);
	for (i = 0; i < parent_count; i++)
		tracing_json_add_parent_ids_entry(root, parents[i].group, parents[i].value);

	/* Add script function specific fields */
	tracing_json_add_string(data, "function", info->function_name);
	if (info->caller_function)
		tracing_json_add_string(data, "caller", info->caller_function);
	cJSON_AddItemToObjectCS(data, "depth",
		cJSON_CreateNumber((double)info->depth));
	tracing_json_add_str_field(data, "callid", &info->callid);
	tracing_json_add_str_field(data, "cseq", &info->cseq);

	cJSON_AddItemToObjectCS(data, "pid",
		cJSON_CreateNumber((double)getpid()));

	return tracing_store_json("script", info->event_name, root);
}

static void tracing_db_close(void)
{
	if (tracing_db_con) {
		if (tracing_dbf.close)
			tracing_dbf.close(tracing_db_con);
		tracing_db_con = NULL;
	}
}

static int tracing_db_connect(void)
{
	if (!tracing_db_bound) {
		if (tracing_bind_db_module() < 0)
			return -1;
	}

	if (tracing_db_con)
		return 0;

	if (!tracing_dbf.init) {
		LM_ERR("database module missing init callback\n");
		return -1;
	}

	tracing_db_con = tracing_dbf.init(&tracing_db_url);
	if (!tracing_db_con) {
		LM_ERR("failed to connect to tracing database %.*s\n",
			tracing_db_url.len, tracing_db_url.s ? tracing_db_url.s : "");
		return -1;
	}

	if (tracing_dbf.use_table && tracing_dbf.use_table(tracing_db_con, &tracing_db_table) < 0) {
		LM_ERR("failed to select tracing table %.*s\n",
			tracing_db_table.len, tracing_db_table.s ? tracing_db_table.s : "");
		tracing_db_close();
		return -1;
	}

	return 0;
}

static int tracing_bind_db_module(void)
{
	if (tracing_db_bound)
		return 0;

	if (db_bind_mod(&tracing_db_url, &tracing_dbf) < 0) {
		LM_ERR("failed to bind database module for url %.*s\n",
			tracing_db_url.len, tracing_db_url.s ? tracing_db_url.s : "");
		return -1;
	}

	if (!tracing_dbf.insert) {
		LM_ERR("database module does not expose insert callback\n");
		return -1;
	}

	if (!DB_CAPABILITY(tracing_dbf, DB_CAP_INSERT)) {
		LM_ERR("database module lacks insert capability\n");
		return -1;
	}

	tracing_db_bound = 1;

	LM_INFO("tracing backend storing events into table %.*s (url %.*s)\n",
		tracing_db_table.len, tracing_db_table.s,
		tracing_db_url.len, tracing_db_url.s);

	return 0;
}

static int tracing_db_insert(const char *kind, const char *event, const char *payload)
{
	db_key_t keys[4];
	db_val_t vals[4];
	char ts_buf[32];
	str ts_val;
	str payload_val;
	str kind_val = STR_NULL;
	str event_val = STR_NULL;
	struct timeval now;
	int ret;
	int cols = 0;

	if (tracing_db_connect() < 0)
		return -1;

	gettimeofday(&now, NULL);
	ts_val.s = ts_buf;
	snprintf(ts_buf, sizeof(ts_buf), "%ld", (long)now.tv_sec * 1000L + now.tv_usec / 1000);
	ts_val.len = strlen(ts_buf);

	keys[cols] = &tracing_db_col_timestamp;
	vals[cols].type = DB_STR;
	vals[cols].nul = 0;
	vals[cols].free = 0;
	vals[cols].val.str_val = ts_val;
	cols++;

	if (tracing_db_col_kind.s && tracing_db_col_kind.len > 0) {
		if (kind && *kind) {
			kind_val.s = (char *)kind;
			kind_val.len = (int)strlen(kind);
		}
		keys[cols] = &tracing_db_col_kind;
		vals[cols].type = DB_STR;
		vals[cols].free = 0;
		if (kind_val.s) {
			vals[cols].nul = 0;
			vals[cols].val.str_val = kind_val;
		} else {
			vals[cols].nul = 1;
			vals[cols].val.str_val = STR_NULL;
		}
		cols++;
	}

	if (tracing_db_col_event.s && tracing_db_col_event.len > 0) {
		if (event && *event) {
			event_val.s = (char *)event;
			event_val.len = (int)strlen(event);
		}
		keys[cols] = &tracing_db_col_event;
		vals[cols].type = DB_STR;
		vals[cols].free = 0;
		if (event_val.s) {
			vals[cols].nul = 0;
			vals[cols].val.str_val = event_val;
		} else {
			vals[cols].nul = 1;
			vals[cols].val.str_val = STR_NULL;
		}
		cols++;
	}

	payload_val.s = payload ? (char *)payload : "";
	payload_val.len = payload ? (int)strlen(payload) : 0;

	keys[cols] = &tracing_db_col_payload;
	vals[cols].type = DB_STR;
	vals[cols].nul = 0;
	vals[cols].free = 0;
	vals[cols].val.str_val = payload_val;
	cols++;

	ret = tracing_dbf.insert(tracing_db_con, keys, vals, cols);
	if (ret < 0) {
		LM_ERR("failed to insert tracing event into table %.*s\n",
			tracing_db_table.len, tracing_db_table.s ? tracing_db_table.s : "");
		tracing_db_close();
		return -1;
	}

	return 0;
}

static void tracing_json_add_string(cJSON *obj, const char *name, const char *value)
{
	if (!obj || !name)
		return;

	if (value)
		cJSON_AddItemToObjectCS(obj, name, cJSON_CreateString(value));
	else
		cJSON_AddItemToObjectCS(obj, name, cJSON_CreateNull());
}

static cJSON *tracing_json_get_or_create_parent_ids(cJSON *obj)
{
	cJSON *parent_ids;

	if (!obj)
		return NULL;

	parent_ids = cJSON_GetObjectItem(obj, "parent_ids");
	if (!parent_ids) {
		parent_ids = cJSON_CreateObject();
		if (!parent_ids)
			return NULL;
		cJSON_AddItemToObjectCS(obj, "parent_ids", parent_ids);
	}

	return parent_ids;
}

static void tracing_json_add_parent_ids_entry(cJSON *obj, const char *group, const char *value)
{
	cJSON *parent_ids;

	if (!group || !value)
		return;

	parent_ids = tracing_json_get_or_create_parent_ids(obj);
	if (!parent_ids)
		return;

	tracing_json_add_string(parent_ids, group, value);
}

static void tracing_json_add_str_field(cJSON *obj, const char *name, const str *value)
{
	int clean_len = 0;
	char *clean;
	cJSON *item;

	if (!obj || !name)
		return;

	if (!value || !value->s || value->len <= 0) {
		cJSON_AddItemToObjectCS(obj, name, cJSON_CreateNull());
		return;
	}

	clean = tracing_sanitize_str(value, &clean_len);
	if (!clean) {
		cJSON_AddItemToObjectCS(obj, name, cJSON_CreateNull());
		return;
	}

	if (clean_len == 0) {
		pkg_free(clean);
		cJSON_AddItemToObjectCS(obj, name, cJSON_CreateNull());
		return;
	}

	item = cJSON_CreateStr(clean, (size_t)clean_len);
	pkg_free(clean);

	if (!item) {
		cJSON_AddItemToObjectCS(obj, name, cJSON_CreateNull());
		return;
	}

	cJSON_AddItemToObjectCS(obj, name, item);
}

static void tracing_json_add_number_or_null(cJSON *obj, const char *name,
	long long value, int has_value)
{
	if (!obj || !name)
		return;

	if (has_value)
		cJSON_AddItemToObjectCS(obj, name, cJSON_CreateNumber((double)value));
	else
		cJSON_AddItemToObjectCS(obj, name, cJSON_CreateNull());
}

static char *tracing_sanitize_str(const str *value, int *out_len)
{
	int len = 0;
	int i;
	char *buf;

	if (!value || !value->s || value->len <= 0)
		return NULL;

	buf = pkg_malloc((size_t)value->len + 1);
	if (!buf)
		return NULL;

	for (i = 0; i < value->len; i++) {
		unsigned char c = (unsigned char)value->s[i];

		if (c == '\r' || c == '\n' || c == '\t')
			continue;

		if (c < 32)
			continue;

		buf[len++] = (char)c;
	}

	buf[len] = '\0';

	if (out_len)
		*out_len = len;

	return buf;
}

static void tracing_json_add_timestamp(cJSON *obj, const struct timeval *tv)
{
	char buf[32];
	long ms;

	if (!obj)
		return;

	if (!tv)
		return;

	ms = tv->tv_sec * 1000L + tv->tv_usec / 1000;
	snprintf(buf, sizeof(buf), "%ld", ms);
	cJSON_AddItemToObjectCS(obj, "timestamp", cJSON_CreateString(buf));
}

static void tracing_json_add_datetime(cJSON *obj, const struct timeval *tv)
{
	char buf[40];
	struct tm tmp;
	time_t ts;
	long msec;

	if (!obj || !tv)
		return;

	ts = tv->tv_sec;
	if (!gmtime_r(&ts, &tmp))
		return;

	if (strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tmp) == 0)
		return;

	msec = tv->tv_usec / 1000;
	if (snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), ".%03ldZ", msec) < 0)
		return;

	cJSON_AddItemToObjectCS(obj, "datetime", cJSON_CreateString(buf));
}

static cJSON *tracing_json_create_root(const char *group, const char *event)
{
	(void)group;
	(void)event;
	return cJSON_CreateObject();
}

static int tracing_store_json(const char *kind, const char *event, cJSON *payload)
{
	char *json;
	int ret;

	if (!payload)
		return -1;

	json = cJSON_PrintUnformatted(payload);
	if (!json) {
		LM_ERR("failed to serialize tracing payload\n");
		cJSON_Delete(payload);
		return -1;
	}

	ret = tracing_db_insert(kind, event, json);
	cJSON_PurgeString(json);
	cJSON_Delete(payload);

	return ret;
}

static void generate_correlation_id(unsigned long long cid, unsigned int seq_no, 
	const struct timeval *tv, char *hash_str)
{
	unsigned char hash[20];
	sha1_context ctx;
	int i;

	if (!hash_str)
		return;

	sha1_init(&ctx);
	sha1_starts(&ctx);
	sha1_update(&ctx, (unsigned char *)&cid, sizeof(cid));
	sha1_update(&ctx, (unsigned char *)&seq_no, sizeof(seq_no));
	if (tv) {
		sha1_update(&ctx, (unsigned char *)&tv->tv_sec, sizeof(tv->tv_sec));
		sha1_update(&ctx, (unsigned char *)&tv->tv_usec, sizeof(tv->tv_usec));
	}
	sha1_finish(&ctx, hash);
	sha1_free(&ctx);

	for (i = 0; i < 5; i++)
		sprintf(hash_str + (i * 2), "%02x", hash[i]);
	hash_str[10] = '\0';
}

static void generate_connection_correlation_id(unsigned long long cid, 
	const struct timeval *tv, char *hash_str)
{
	unsigned char hash[20];
	const unsigned char marker = 0xC1;
	sha1_context ctx;
	int i;

	if (!hash_str)
		return;

	sha1_init(&ctx);
	sha1_starts(&ctx);
	sha1_update(&ctx, (unsigned char *)&cid, sizeof(cid));
	sha1_update(&ctx, &marker, sizeof(marker));
	/* Don't include timestamp for connection IDs - they must be stable across chunks */
	sha1_finish(&ctx, hash);
	sha1_free(&ctx);

	for (i = 0; i < 5; i++)
		sprintf(hash_str + (i * 2), "%02x", hash[i]);
	hash_str[10] = '\0';
	
	(void)tv; /* Unused for now, kept for API consistency */
}

static void format_endpoint(const struct ip_addr *ip, unsigned short port, char *out, size_t len)
{
	char ip_buf[IP_ADDR_MAX_STR_SIZE];
	const char *ip_str;

	if (!out || len == 0)
		return;

	if (ip && ip->len) {
		ip_str = ip_addr2a((struct ip_addr *)(void *)ip);
		if (!ip_str)
			ip_str = "-";
	} else {
		ip_str = "-";
	}

	snprintf(ip_buf, sizeof(ip_buf), "%s", ip_str);

	if (port)
		snprintf(out, len, "%s:%u", ip_buf, port);
	else
		snprintf(out, len, "%s:-", ip_buf);
}

