#include <stdio.h>
#include <string.h>

#include "../../dprint.h"
#include "../../parser/msg_parser.h"

#include "tracing_impl.h"

static void tracing_script_function_event_cb(const struct tracing_script_function_event *info);

int tracing_script_init(void)
{
	if (register_tracing(TRACING_CB_SCRIPT_FUNCTION_EVENT, tracing_script_function_event_cb) < 0) {
		LM_ERR("failed to register script function tracing\n");
		return -1;
	}

	LM_INFO("Script function tracing initialized\n");
	return 0;
}

void tracing_script_destroy(void)
{
	/* nothing to clean up */
}

static void tracing_script_function_event_cb(const struct tracing_script_function_event *info)
{
	if (tracing_storage_store_script_function(info) < 0)
		LM_ERR("failed to persist script function tracing event\n");
}

