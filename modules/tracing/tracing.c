/**
 * tracing module - storage-backed SIP tracing facility
 */

#include "../../sr_module.h"
#include "../../str.h"
#include "../../dprint.h"
#include "../../tracing.h"

#include "tracing_impl.h"

static const param_export_t mod_params[] = {
	{ "backend", STR_PARAM, &tracing_backend.s },
	{ "db_url", STR_PARAM, &tracing_db_url.s },
	{ "db_table", STR_PARAM, &tracing_db_table.s },
	{ "db_col_timestamp", STR_PARAM, &tracing_db_col_timestamp.s },
	{ "db_col_kind", STR_PARAM, &tracing_db_col_kind.s },
	{ "db_col_event", STR_PARAM, &tracing_db_col_event.s },
	{ "db_col_payload", STR_PARAM, &tracing_db_col_payload.s },
	{ 0, 0, 0 }
};

static int mod_init(void);
static void destroy(void);
static int child_init(int rank);

struct module_exports exports = {
	"tracing",
	MOD_TYPE_DEFAULT,
	MODULE_VERSION,
	DEFAULT_DLFLAGS,
	0, /* proto */
	0, /* retrans */
	0, /* receive_f */
	0, /* rpc_f */
	mod_params,
	0,
	0,
	0,
	0,
	0,
	0,
	mod_init,
	(response_function)0,
	(destroy_function)destroy,
	child_init,
	0
};

static int mod_init(void)
{
	if (tracing_tcp_init() < 0)
		goto error;

	if (tracing_udp_init() < 0)
		goto error_udp;

	if (tracing_dialog_init() < 0)
		goto error_dialog;

	if (tracing_tm_init() < 0)
		goto error_tm;

	if (tracing_rest_init() < 0)
		goto error_rest;

	if (tracing_script_init() < 0)
		goto error_script;

	if (tracing_storage_init() < 0)
		goto error_storage;

	return 0;

error_storage:
	tracing_script_destroy();
error_script:
	tracing_rest_destroy();
error_rest:
	tracing_tm_destroy();
error_tm:
	tracing_dialog_destroy();
error_dialog:
	tracing_udp_destroy();
error_udp:
	tracing_tcp_destroy();
error:
	unregister_tracings();
	return -1;
}

static void destroy(void)
{
	tracing_storage_destroy();
	tracing_script_destroy();
	tracing_rest_destroy();
	tracing_tm_destroy();
	tracing_dialog_destroy();
	tracing_udp_destroy();
	tracing_tcp_destroy();
	unregister_tracings();
}

static int child_init(int rank)
{
	if (tracing_storage_child_init(rank) < 0)
		return -1;

	return 0;
}



