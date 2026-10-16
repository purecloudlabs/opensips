/**
 * Copyright (C) 2001-2003 FhG Fokus
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
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>

#include "sr_module.h"
#include "dprint.h"
#include "error.h"
#include "socket_info.h"
#include "mem/mem.h"
#include "xlog.h"

#include "pvar.h"
#include "trace_api.h"

#define XLOG_TRACE_API_MODULE "proto_hep"
#define XLOG_CORRELATION_MAGIC "XLOGCORR"

/* headroom (bytes) reserved in the JSON log line for the fixed keys and their
 * values - time, pid, level, module, function, prefix, pname, hostname and
 * the surrounding JSON punctuation - on top of the message and log_ctx blob */
#define XLOG_JSON_KEYS_OVERHEAD 1024


char *log_buf = NULL;
char *log_ctx_buf = NULL;

int xlog_buf_size = 4096;
int xlog_ctx_buf_size = 4096;
int xlog_force_color = 0;

/* the log level used when printing xlog messages */
int xlog_print_level = L_NOTICE;

/* the logging level/threshold for filtering the xlog messages for printing */
static int xlog_level_default = L_NOTICE;
static int xlog_level_local = L_NOTICE;
static int *xlog_level_shared = NULL;

/* current logging level for this process.
 * During init it points the 'xlog_level_default' in order to store the
 * original configured value
 * During runtime it may point to:
 *    - xlog_level_shared - the shared xlog level between all procs
 *    - &xlog_level_local - for a per-proc changed xlog level
 */
int *xlog_level = &xlog_level_default;

/* id with which xlog will be identified by siptrace module
 * and will identify an xlog tracing packet */
int xlog_proto_id;
/* tracing module api */
static trace_proto_t tprot;

/* xlog string identifier */
static const char* xlog_id_s="xlog";

#define is_xlog_printable(_level)  \
	(((int)(*xlog_level)) >= ((int)(_level)))


void set_shared_xlog_level(int new_level)
{
	/* do not accept setting as time the xlog_level still points to the
	 * starting/default holder as we will loose the original value */
	if (xlog_level==&xlog_level_default)
		return;

	*xlog_level_shared = new_level;
}


void set_local_xlog_level(int new_level)
{
	/* do not accept setting as time the xlog_level still points to the
	 * starting/default holder as we will loose the original value */
	if (xlog_level==&xlog_level_default)
		return;

	xlog_level_local = new_level;
	xlog_level = &xlog_level_local;
}


void reset_xlog_level(void)
{
	if (xlog_level==&xlog_level_default)
		return; /* still init, very unlikely */

	if (xlog_level==&xlog_level_local) {
		/* points a local/per-proc xlog level hodler,
		 * so reset it to the shared value */
		xlog_level = xlog_level_shared;
		return;
	}

	/* points to the shared holder, so reset the shred value */
	*xlog_level_shared = xlog_level_default;
}


static int buf_init(void)
{
	LM_DBG("initializing...\n");
	log_buf = (char*)pkg_malloc((xlog_buf_size+1)*sizeof(char));
	if(log_buf==NULL)
	{
		LM_ERR("no pkg memory left\n");
		return -1;
	}
	log_ctx_buf = (char*)pkg_malloc((xlog_ctx_buf_size+1)*sizeof(char));
	if(log_ctx_buf==NULL)
	{
		LM_ERR("no pkg memory left\n");
		return -1;
	}
	return 0;
}


int init_xlog(void)
{
	if (log_buf == NULL) {
		if (buf_init()) {
			LM_ERR("Cannot print message!\n");
			return -1;
		}
	}

	xlog_level_shared = (int*)shm_malloc(sizeof(int));
	if (xlog_level_shared==NULL) {
		LM_ERR("failed to allocate shared holder for xlog\n");
		return -1;
	}
	xlog_level = xlog_level_shared;
	*xlog_level = xlog_level_default;

	if (register_trace_type)
		xlog_proto_id = register_trace_type((char *)xlog_id_s);

	memset(&tprot, 0, sizeof(trace_proto_t));
	if (global_trace_api) {
		memcpy(&tprot, global_trace_api, sizeof(trace_proto_t));
	} else {
		if (trace_prot_bind(XLOG_TRACE_API_MODULE, &tprot)) {
			LM_DBG("failed to load trace protocol!\n");
		}
	}

	/* The JSON log line (log_json_buf) must hold the rendered message
	 * (up to xlog_buf_size) plus the raw log_ctx blob (up to
	 * xlog_ctx_buf_size) plus the fixed JSON keys/values (time, pid, level,
	 * module, func, prefix, pname, hostname, ...). If the configured
	 * log_json_buf_size is too small, large message+ctx xlog entries would
	 * be silently dropped by the JSON consumer, so raise it to a safe floor.
	 * Note: JSON escaping may still expand the message beyond its raw size;
	 * operators logging heavily-escaped messages may need a larger value. */
	{
		int min_json_buf = xlog_buf_size + xlog_ctx_buf_size +
			XLOG_JSON_KEYS_OVERHEAD;

		if (log_json_buf_size < min_json_buf) {
			LM_WARN("log_json_buf_size (%d) too small for xlog_buf_size (%d) "
				"+ xlog_ctx_buf_size (%d); raising to %d\n",
				log_json_buf_size, xlog_buf_size, xlog_ctx_buf_size,
				min_json_buf);
			log_json_buf_size = min_json_buf;
			if (init_log_json_buf(1) < 0) {
				LM_ERR("failed to grow JSON log buffer\n");
				return -1;
			}
		}
	}

	return 0;
}


static inline void add_xlog_data(trace_message message, void* param)
{
	str str_level;
	xl_trace_t* xtrace_param = param;
	static str sip_str = str_init("sip");


	switch (*xlog_level) {
		case L_ALERT:
			str_level.s = DP_ALERT_TEXT; break;
		case L_CRIT:
			str_level.s = DP_CRIT_TEXT; break;
		case L_ERR:
			str_level.s = DP_ERR_TEXT; break;
		case L_WARN:
			str_level.s = DP_WARN_TEXT; break;
		case L_NOTICE:
			str_level.s = DP_NOTICE_TEXT; break;
		case L_INFO:
			str_level.s = DP_INFO_TEXT; break;
		case L_DBG:
			str_level.s = DP_DBG_TEXT;
			str_level.len = sizeof(DP_DBG_TEXT) - 2;
			break;
		default:
			LM_BUG("Unexpected log level [%d]\n", xlog_print_level);
			return;
	}

	/* remove ':' after each level */
	str_level.len = strlen(str_level.s) - 1;

	tprot.add_payload_part( message, "Event", &str_level);

	if ( !xtrace_param )
		return;

	tprot.add_payload_part( message, "text", &xtrace_param->buf);

	if (xtrace_param->msg && xtrace_param->msg->callid)
		tprot.add_extra_correlation( message, &sip_str, &xtrace_param->msg->callid->body );
}

static inline int trace_xlog(struct sip_msg* msg, char* buf, int len)
{
	struct modify_trace mod_p;
	xl_trace_t xtrace_param;
	str correlation_str;
	union sockaddr_union su;

	if (msg == NULL || buf == NULL) {
		LM_ERR("bad input!\n");
		return -1;
	}

	/* xlog not traced; exit... */
	if (!check_is_traced || check_is_traced(xlog_proto_id) == 0)
		return 0;

	mod_p.mod_f = add_xlog_data;
	xtrace_param.msg = msg;

	xtrace_param.buf.s = buf;
	xtrace_param.buf.len = len;

	mod_p.param = &xtrace_param;

	if (msg->callid && msg->callid->body.len) {
		correlation_str = msg->callid->body;
	} else {
		correlation_str.s = "<null>";
		correlation_str.len = 6;
	}

	if (msg->rcv.bind_address && msg->rcv.bind_address->port_no)
		/* coverity[check_return] - CID #211391 */
		init_su( &su, &msg->rcv.bind_address->address,
			msg->rcv.bind_address->port_no);
	else
		su.s.sa_family = 0;

	if (sip_context_trace(xlog_proto_id,
	su.s.sa_family ? &su : NULL /*src*/, su.s.sa_family ? &su : NULL /*dst*/,
	0, IPPROTO_TCP,
	&correlation_str, &mod_p) < 0) {
		LM_ERR("failed to trace xlog message!\n");
		return -1;
	}

	return 0;
}

int xl_print_log(struct sip_msg* msg, pv_elem_p list, int *len)
{
	if (pv_printf(msg, list, log_buf, len) < 0)
		return -1;

	if (trace_xlog(msg, log_buf, *len) < 0) {
		LM_ERR("failed to trace xlog message!\n");
		return -2;
	}

	return 1;
}


int xlog_2(struct sip_msg* msg, char* lev, char* frm)
{
	int log_len, ret;
	long level;
	xl_level_p xlp;
	pv_value_t value;

	xlp = (xl_level_t*)(void*)lev;
	if(xlp->type==1)
	{
		if(pv_get_spec_value(msg, &xlp->v.sp, &value)!=0
			|| value.flags&PV_VAL_NULL || !(value.flags&PV_VAL_INT))
		{
			LM_ERR("invalid log level value [%d]\n", value.flags);
			return -1;
		}
		level = (long)value.ri;
	} else {
		level = xlp->v.level;
	}

	if(!is_xlog_printable((int)level))
		return 1;

	log_len = xlog_buf_size;

	ret = xl_print_log(msg, (pv_elem_t*)(void*)frm, &log_len);
	if (ret == -1) {
		LM_ERR("global print buffer too small, increase 'xlog_buf_size'\n");
		return -1;
	}

	/* set the xlog as log level to trick "LM_GEN" */
	set_proc_log_level( *xlog_level );

	/* log_buf[log_len] = '\0'; */
	LM_GEN1((int)level, "%.*s", log_len, log_buf);

	reset_proc_log_level();

	return ret;
}


int xlog_3(struct sip_msg* msg, char* lev, char* ctx, char* frm)
{
	int log_len, ctx_len, ret;
	long level;
	xl_level_p xlp;
	pv_value_t value;

	xlp = (xl_level_t*)(void*)lev;
	if(xlp->type==1)
	{
		if(pv_get_spec_value(msg, &xlp->v.sp, &value)!=0
			|| value.flags&PV_VAL_NULL || !(value.flags&PV_VAL_INT))
		{
			LM_ERR("invalid log level value [%d]\n", value.flags);
			return -1;
		}
		level = (long)value.ri;
	} else {
		level = xlp->v.level;
	}

	if(!is_xlog_printable((int)level))
		return 1;

	/* render the message into the shared log buffer */
	log_len = xlog_buf_size;
	ret = xl_print_log(msg, (pv_elem_t*)(void*)frm, &log_len);
	if (ret == -1) {
		LM_ERR("global print buffer too small, increase 'xlog_buf_size'\n");
		return -1;
	}

	/* render the log_ctx blob into its own buffer (NUL-terminated for the
	 * downstream strlen() in the JSON log consumers) */
	ctx_len = xlog_ctx_buf_size;
	if (pv_printf(msg, (pv_elem_t*)(void*)ctx, log_ctx_buf, &ctx_len) < 0) {
		LM_ERR("global ctx print buffer too small, "
			"increase 'xlog_ctx_buf_size'\n");
		return -1;
	}
	log_ctx_buf[ctx_len] = '\0';

	/* set the xlog as log level to trick "LM_GEN" */
	set_proc_log_level( *xlog_level );

	LM_GEN1_CTX((int)level, log_ctx_buf, "%.*s", log_len, log_buf);

	reset_proc_log_level();

	return ret;
}


int xlog_1(struct sip_msg* msg, char* frm)
{
	int log_len, ret;

	if(!is_xlog_printable(xlog_print_level))
		return 1;

	log_len = xlog_buf_size;

	ret = xl_print_log(msg, (pv_elem_t*)(void*)frm, &log_len);
	if (ret == -1) {
		LM_ERR("global print buffer too small, increase 'xlog_buf_size'\n");
		return -1;
	}

	/* set the xlog as log level to trick "LM_GEN" */
	set_proc_log_level( *xlog_level );

	/* log_buf[log_len] = '\0'; */
	LM_GEN1(xlog_print_level, "%.*s", log_len, log_buf);

	reset_proc_log_level();

	return ret;
}

/**
 */
int xdbg(struct sip_msg* msg, char* frm)
{
	int log_len, ret;

	if(!is_xlog_printable(L_DBG))
		return 1;

	log_len = xlog_buf_size;

	ret = xl_print_log(msg, (pv_elem_t*)(void*)frm, &log_len);
	if (ret == -1) {
		LM_ERR("global print buffer too small, increase 'xlog_buf_size'\n");
		return -1;
	}

	/* set the xlog as log level to trick "LM_GEN" */
	set_proc_log_level( *xlog_level );

	/* log_buf[log_len] = '\0'; */
	LM_GEN1(L_DBG, "%.*s", log_len, log_buf);

	reset_proc_log_level();

	return ret;
}

int pv_parse_color_name(pv_spec_p sp, const str *in)
{

	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;

	if(in->len != 2)
	{
		LM_ERR("color name must have two chars\n");
		return -1;
	}

	/* foreground */
	switch(in->s[0])
	{
		case 'x':
		case 's': case 'r': case 'g':
		case 'y': case 'b': case 'p':
		case 'c': case 'w': case 'S':
		case 'R': case 'G': case 'Y':
		case 'B': case 'P': case 'C':
		case 'W':
		break;
		default:
			goto error;
	}

	/* background */
	switch(in->s[1])
	{
		case 'x':
		case 's': case 'r': case 'g':
		case 'y': case 'b': case 'p':
		case 'c': case 'w':
		break;
		default:
			goto error;
	}

	sp->pvp.pvn.type = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.type = AVP_NAME_STR;
	sp->pvp.pvn.u.isname.name.s = *in;

	sp->getf = pv_get_color;

	/* force the color PV type */
	sp->type = PVT_COLOR;
	return 0;
error:
	LM_ERR("invalid color name\n");
	return -1;
}

#define COL_BUF 10

#define append_sstring(p, end, s) \
        do{\
                if ((p)+(sizeof(s)-1)<=(end)){\
                        memcpy((p), s, sizeof(s)-1); \
                        (p)+=sizeof(s)-1; \
                }else{ \
                        /* overflow */ \
                        LM_ERR("append_sstring overflow\n"); \
                        goto error;\
                } \
        } while(0)


int pv_get_color(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	static char color[COL_BUF];
	char* p;
	char* end;
	str s;

	if(xlog_force_color==0)
	{
		s.s = "";
		s.len = 0;
		return pv_get_strval(msg, param, res, &s);
	}

	p = color;
	end = p + COL_BUF;

	/* excape sequenz */
	append_sstring(p, end, "\033[");

	if(param->pvn.u.isname.name.s.s[0]!='_')
	{
		if (islower((int)param->pvn.u.isname.name.s.s[0]))
		{
			/* normal font */
			append_sstring(p, end, "0;");
		} else {
			/* bold font */
			append_sstring(p, end, "1;");
			param->pvn.u.isname.name.s.s[0] += 32;
		}
	}

	/* foreground */
	switch(param->pvn.u.isname.name.s.s[0])
	{
		case 'x':
			append_sstring(p, end, "39;");
		break;
		case 's':
			append_sstring(p, end, "30;");
		break;
		case 'r':
			append_sstring(p, end, "31;");
		break;
		case 'g':
			append_sstring(p, end, "32;");
		break;
		case 'y':
			append_sstring(p, end, "33;");
		break;
		case 'b':
			append_sstring(p, end, "34;");
		break;
		case 'p':
			append_sstring(p, end, "35;");
		break;
		case 'c':
			append_sstring(p, end, "36;");
		break;
		case 'w':
			append_sstring(p, end, "37;");
		break;
		default:
			LM_ERR("invalid foreground\n");
			return pv_get_null(msg, param, res);
	}

	/* background */
	switch(param->pvn.u.isname.name.s.s[1])
	{
		case 'x':
			append_sstring(p, end, "49");
		break;
		case 's':
			append_sstring(p, end, "40");
		break;
		case 'r':
			append_sstring(p, end, "41");
		break;
		case 'g':
			append_sstring(p, end, "42");
		break;
		case 'y':
			append_sstring(p, end, "43");
		break;
		case 'b':
			append_sstring(p, end, "44");
		break;
		case 'p':
			append_sstring(p, end, "45");
		break;
		case 'c':
			append_sstring(p, end, "46");
		break;
		case 'w':
			append_sstring(p, end, "47");
		break;
		default:
			LM_ERR("invalid background\n");
			return pv_get_null(msg, param, res);
	}

	/* end */
	append_sstring(p, end, "m");

	s.s = color;
	s.len = p-color;
	return pv_get_strval(msg, param, res, &s);

error:
	return -1;
}

