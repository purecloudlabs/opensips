#include <stdio.h>
#include <string.h>

#include "../../dprint.h"
#include "../../parser/msg_parser.h"

#include "tracing_impl.h"

static void tracing_rest_event_cb(const struct tracing_rest_event *info);

int tracing_rest_init(void)
{
	if (register_tracing(TRACING_CB_REST_EVENT, tracing_rest_event_cb) < 0) {
		LM_ERR("failed to register REST tracing\n");
		return -1;
	}

	LM_INFO("REST tracing initialized\n");
	return 0;
}

void tracing_rest_destroy(void)
{
	/* nothing to clean up */
}

static void tracing_rest_event_cb(const struct tracing_rest_event *info)
{
	if (tracing_storage_store_rest(info) < 0)
		LM_ERR("failed to persist REST tracing event\n");
}

