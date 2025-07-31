/*
 * Copyright (C) 2013 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * -------
 * 2013-02-28: Created (Liviu)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rest_cb.h"

/**
 * write_func - callback; reallocates and extends the @body buffer each time.
 * @ptr:	pointer to the raw data
 * @size:	size of a block
 * @nmemb:	number of blocks
 * @body:	parameter previously set with the CURLOPT_WRITEDATA option
 *
 * Return: number of bytes processed (if != @len, transfer is aborted)
 */
size_t write_func(char *ptr, size_t size, size_t nmemb, void *body)
{
	unsigned int len = size * nmemb;
	str *buff = (str *)body;

#ifdef EXTRA_DEBUG
	LM_DBG("got body piece! bs: %lu, blocks: %lu\n", size, nmemb);
#endif

	if (len == 0)
		return 0;

	if (max_transfer_size && buff->len + len > max_transfer_size * 1024UL) {
		LM_ERR("max download size exceeded (%u KB, per 'max_transfer_size'), "
		       "aborting transfer\n", max_transfer_size);
		return 0;
	}

	buff->s = pkg_realloc(buff->s, buff->len + len + 1);
	if (!buff->s) {
		buff->len = 0;
		LM_ERR("No more pkg memory!\n");
		return 0;
	}

	memcpy(buff->s + buff->len, ptr, len);
	buff->len += len;
	buff->s[buff->len] = '\0';

	return len;
}

/**
 * header_func - callback; called once for each header. retrieves "Content-Type"
 * @ptr:	pointer to the current header info
 * @size:	size of a block
 * @nmemb:	number of blocks
 * @body:	parameter previously set with the CURLOPT_HEADERFUNCTION option
 */
size_t header_func(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	int len, left;
	str *st = (str *)userdata;

	len = left = size * nmemb;

	if (len > CONTENT_TYPE_HDR_LEN && *ptr == 'C' &&
	    strncasecmp(ptr, HTTP_HDR_CONTENT_TYPE, CONTENT_TYPE_HDR_LEN) == 0) {

		ptr += CONTENT_TYPE_HDR_LEN + 1;
		left -= CONTENT_TYPE_HDR_LEN + 1;

		while (*ptr == ' ') {
			ptr++;
			left--;
		}

		st->s = pkg_realloc(st->s, left);
		if (!st->s) {
			LM_ERR("no more pkg mem\n");
			return E_OUT_OF_MEM;
		}

		st->len = left;
		memcpy(st->s, ptr, left);
	}

	LM_DBG("Received: %.*s\n", len, ptr);

	return len;
}

int sock_cb(CURL *e, curl_socket_t s, int what, void *cbp, void *sockp)
{
	LM_DBG("sock_cb called %d\n", what);
	internal_curl_sock *p = (internal_curl_sock*) cbp;

	if(what == CURL_POLL_REMOVE) {
		/* remove the socket from our collection */
	}
	if(what & CURL_POLL_IN) {
		/* wait for read on this socket */
		p->sock = s;
		p->status |= CURL_REQUEST_SENDING;
	}
	if(what & CURL_POLL_OUT) {
		p->sock = s;
		p->status |= CURL_CONNECTED;
	}

  	return 0;
}

int timerfunc(CURLM *multi_handle, long timeout_ms, void *cbp)
{
	LM_DBG("timerfunc called %d\n", timeout_ms);
	internal_curl_sock *p = (internal_curl_sock*) cbp;

	if (timeout_ms == 0) {
		p->timer += 20;
	} else if (timeout_ms == -1) {
		p->status |= CURL_FINISHED;
	} else if (timeout_ms - p->timer <= 0) {
		LM_DBG("timeout %d", timeout_ms - p->timer);
		p->status |= CURL_TIMEOUT;
	}

  	return 0;
}

int prereq_callback(void *cbp,
                           char *conn_primary_ip,
                           char *conn_local_ip,
                           int conn_primary_port,
                           int conn_local_port)
{
	LM_DBG("prereq_callback called\n");
	internal_curl_sock *p = (internal_curl_sock*) cbp;
	p->status |= CURL_REQUEST_SENT;
	return CURL_PREREQFUNC_OK;
}