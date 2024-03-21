/*
 * Copyright (C) 2024 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include "h2_evi.h"

#include "../../dprint.h"
#include "../../ut.h"

static event_id_t h2ev_req_id = EVI_ERROR; /* E_HTTP2_REQUEST */
static evi_params_p h2ev_req_params;

static evi_param_p h2ev_req_param_method;
static evi_param_p h2ev_req_param_path;
static evi_param_p h2ev_req_param_headers;
static evi_param_p h2ev_req_param_body;
static evi_param_p h2ev_req_param_msg;

str h2ev_req_pname_method = str_init("method");
str h2ev_req_pname_path = str_init("path");
str h2ev_req_pname_headers = str_init("headers");
str h2ev_req_pname_body = str_init("body");
str h2ev_req_pname_msg = str_init("_h2msg_");


int h2_init_evi(void)
{
	/* First publish the events */
	h2ev_req_id = evi_publish_event(str_init(H2EV_REQ_NAME));
	if (h2ev_req_id == EVI_ERROR) {
		LM_ERR("cannot register 'request' event\n");
		return -1;
	}

	h2ev_req_params = pkg_malloc(sizeof *h2ev_req_params);
	if (!h2ev_req_params) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(h2ev_req_params, 0, sizeof *h2ev_req_params);

	h2ev_req_param_method = evi_param_create(h2ev_req_params, &h2ev_req_pname_method);
	h2ev_req_param_path = evi_param_create(h2ev_req_params, &h2ev_req_pname_path);
	h2ev_req_param_headers = evi_param_create(h2ev_req_params, &h2ev_req_pname_headers);
	h2ev_req_param_body = evi_param_create(h2ev_req_params, &h2ev_req_pname_body);
	h2ev_req_param_msg = evi_param_create(h2ev_req_params, &h2ev_req_pname_msg);
	if (!h2ev_req_param_method || !h2ev_req_param_path
	        || !h2ev_req_param_headers || !h2ev_req_param_body
	        || !h2ev_req_param_msg) {
		LM_ERR("failed to create EVI params\n");
		return -1;
	}

	return 0;
}


/**
 * The purpose of this dispatched job is for the logic to be ran by a
 * process other than the Diameter peer, since PROC_MODULE workers have NULL
 * @sroutes, causing a crash when attempting to raise a script event
 */
void h2_raise_event_request(const char *method, const char *path,
		const char *headers_json, const str *body, void *msg)
{
	char buf[sizeof(long)*2 + 1], *p = buf;
	int sz = sizeof(buf);
	str st;

	init_str(&st, method);
	if (evi_param_set_str(h2ev_req_param_method, &st) < 0) {
		LM_ERR("failed to set 'method'\n");
		return;
	}

	init_str(&st, path);
	if (evi_param_set_str(h2ev_req_param_path, &st) < 0) {
		LM_ERR("failed to set 'path'\n");
		return;
	}

	init_str(&st, headers_json);
	if (evi_param_set_str(h2ev_req_param_headers, &st) < 0) {
		LM_ERR("failed to set 'headers_json'\n");
		return;
	}

	if (evi_param_set_str(h2ev_req_param_body, body) < 0) {
		LM_ERR("failed to set 'body'\n");
		return;
	}

	int64_2reverse_hex(&p, &sz, (unsigned long)msg);
	*p = '\0';
	init_str(&st, buf);

	if (evi_param_set_str(h2ev_req_param_msg, &st) < 0) {
		LM_ERR("failed to set '_h2msg_'\n");
		return;
	}

	if (evi_raise_event(h2ev_req_id, h2ev_req_params) < 0)
		LM_ERR("failed to raise '"H2EV_REQ_NAME"' event\n");
}
