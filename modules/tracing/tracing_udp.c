#include <stdio.h>
#include <unistd.h>

#include "../../dprint.h"
#include "../../ip_addr.h"

#include "tracing_impl.h"

static void tracing_udp_datagram_event_cb(const struct tracing_udp_datagram_event *info);

int tracing_udp_init(void)
{
	if (register_tracing(TRACING_CB_UDP_DATAGRAM_EVENT, tracing_udp_datagram_event_cb) < 0) {
		LM_ERR("failed to register UDP datagram tracing\n");
		return -1;
	}

	return 0;
}

void tracing_udp_destroy(void)
{
	/* nothing to clean up */
}

static void tracing_udp_datagram_event_cb(const struct tracing_udp_datagram_event *info)
{
	if (!info)
		return;

	if (tracing_storage_store_udp_datagram(info) < 0)
		LM_ERR("failed to persist udp datagram event '%s'\n",
			info->event_name ? info->event_name : "unknown");
}



