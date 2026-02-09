/**
 * Topology Hiding Module
 *
 * Copyright (C) 2015 OpenSIPS Foundation
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
 * History
 * -------
 *  2015-02-17  initial version (Vlad Paiu)
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "topo_hiding_logic.h"
#include "th_no_dlg_logic.h"

struct tm_binds tm_api;
struct dlg_binds dlg_api;

int force_dialog = 0;
str topo_hiding_ct_params = {0,0};
str topo_hiding_ct_hdr_params = {0,0};
str topo_hiding_prefix = str_init("DLGCH_");
str topo_hiding_seed = str_init("OpenSIPS");
str topo_hiding_ct_encode_pw = str_init("ToPoCtPaSS");
str th_contact_encode_param = str_init("thinfo");
str th_contact_encode_scheme = str_init("base64");
str topo_hiding_ct_encode_pw_legacy = str_init("ToPoCtPaSS");
str th_contact_encode_param_legacy = str_init("thinfol");
str th_contact_encode_scheme_legacy = str_init("base64");
str th_internal_trusted_tag = STR_NULL;
int auto_route_on_trusted_socket = 1;

int th_ct_enc_scheme;
int th_ct_enc_scheme_legacy;

/* Global buffer for decoded routes */
str decoded_route_set[12];
int decoded_route_set_count = 0;

/* Context flag to track if decoded routes are valid for current message */
int ctx_decoded_routes_valid_idx = -1;

/* Route field IDs for nested property access */
#define TH_ROUTE_FULL    0  // Full URI (default)
#define TH_ROUTE_HOST    1  // Host part
#define TH_ROUTE_PORT    2  // Port part
#define TH_ROUTE_USER    3  // User part
#define TH_ROUTE_PARAMS  4  // Parameters

static int mod_init(void);
static void mod_destroy(void);
static int fixup_mmode(void **param);
int w_topology_hiding(struct sip_msg *req, str *flags_s);
int w_topology_hiding_match(struct sip_msg *req, void *seq_match_mode_val);
static int pv_topo_callee_callid(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
static int pv_get_th_decoded_routes(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
static int pv_get_th_decoded_routes_count(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
static int pv_get_th_decoded_contact(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
static int pv_parse_th_route_name(pv_spec_p sp, const str *in);

static const cmd_export_t cmds[]={
	{"topology_hiding",(cmd_function)w_topology_hiding, {
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE},
	{"topology_hiding_match",(cmd_function)w_topology_hiding_match, {
		{CMD_PARAM_STR|CMD_PARAM_OPT, fixup_mmode, 0}, {0,0,0}},
		REQUEST_ROUTE},
	{0,0,{{0,0,0}},0}
};

/* Exported parameters */
static const param_export_t params[] = {
	{ "force_dialog",                INT_PARAM, &force_dialog                },
	{ "th_passed_contact_uri_params",STR_PARAM, &topo_hiding_ct_params.s     },
	{ "th_passed_contact_params",    STR_PARAM, &topo_hiding_ct_hdr_params.s },
	{ "th_callid_passwd",            STR_PARAM, &topo_hiding_seed.s          },
	{ "th_callid_prefix",            STR_PARAM, &topo_hiding_prefix.s        },
	{ "th_contact_encode_passwd",    STR_PARAM, &topo_hiding_ct_encode_pw.s  },
	{ "th_contact_encode_param",     STR_PARAM, &th_contact_encode_param.s   },
	{ "th_contact_encode_scheme",    STR_PARAM, &th_contact_encode_scheme.s  },
	{ "th_contact_encode_passwd_legacy",    STR_PARAM, &topo_hiding_ct_encode_pw_legacy.s  },
	{ "th_contact_encode_param_legacy",     STR_PARAM, &th_contact_encode_param_legacy.s   },
	{ "th_contact_encode_scheme_legacy",    STR_PARAM, &th_contact_encode_scheme_legacy.s  },
	{ "th_internal_trusted_tag",     STR_PARAM, &th_internal_trusted_tag.s   },
	{ "th_auto_route_on_trusted_socket",                INT_PARAM, &auto_route_on_trusted_socket                },
	{0, 0, 0}
};

static const pv_export_t pvars[] = {
	{ {"TH_callee_callid",  sizeof("TH_callee_callid")-1}, 1000,
		pv_topo_callee_callid,0,0, 0, 0, 0},
	{ {"th_decoded_routes", sizeof("th_decoded_routes")-1}, 1001,
		pv_get_th_decoded_routes, 0, pv_parse_th_route_name, pv_parse_index, 0, 0},
	{ {"th_decoded_routes_count", sizeof("th_decoded_routes_count")-1}, 1002,
		pv_get_th_decoded_routes_count, 0, 0, 0, 0, 0},
	{ {"th_decoded_contact", sizeof("th_decoded_contact")-1}, 1003,
		pv_get_th_decoded_contact, 0, pv_parse_th_route_name, 0, 0, 0},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

static module_dependency_t *get_deps_dialog(const param_export_t *param)
{
	int force = *(int *)param->param_pointer;

	if (force == 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_DEFAULT, "dialog", DEP_ABORT);
}

static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm",          DEP_ABORT  },
		{ MOD_TYPE_DEFAULT, "dialog",      DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "force_dialog", get_deps_dialog },
		{ NULL, NULL },
	},
};

struct module_exports exports= {
	"topology_hiding",
	MOD_TYPE_DEFAULT, /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,  /* dlopen flags */
	0,				  /* load function */
	&deps,            /* OpenSIPS module dependencies */
	cmds,             /* exported functions */
	0,                /* exported async functions */
	params,           /* param exports */
	0,                /* exported statistics */
	0,                /* exported MI functions */
	pvars,            /* exported pseudo-variables */
	0,				  /* exported transformations */
	0,                /* extra processes */
	0,                /* module pre-initialization function */
	mod_init,         /* module initialization function */
	(response_function) 0,
	mod_destroy,
	0,                /* per-child init function */
	0                 /* reload confirm function */
};

static int mod_init(void)
{
	LM_INFO("initializing...\n");

	/* Register context for decoded routes validity flag */
	ctx_decoded_routes_valid_idx = context_register_int(CONTEXT_GLOBAL, NULL);

	/* param handling */
	topo_hiding_prefix.len = strlen(topo_hiding_prefix.s);
	topo_hiding_seed.len = strlen(topo_hiding_seed.s);
	th_contact_encode_param.len = strlen(th_contact_encode_param.s);
	topo_hiding_ct_encode_pw.len = strlen(topo_hiding_ct_encode_pw.s);
	th_contact_encode_param_legacy.len = strlen(th_contact_encode_param_legacy.s);
	topo_hiding_ct_encode_pw_legacy.len = strlen(topo_hiding_ct_encode_pw_legacy.s);
	if (topo_hiding_ct_params.s) {
		topo_hiding_ct_params.len = strlen(topo_hiding_ct_params.s);
		topo_parse_passed_ct_params(&topo_hiding_ct_params);
	}
	if (topo_hiding_ct_hdr_params.s) {
		topo_hiding_ct_hdr_params.len = strlen(topo_hiding_ct_hdr_params.s);
		topo_parse_passed_hdr_ct_params(&topo_hiding_ct_hdr_params);
	}
	th_contact_encode_scheme.len = strlen(th_contact_encode_scheme.s);
	if (!str_strcmp(&th_contact_encode_scheme, const_str("base64")))
		th_ct_enc_scheme = ENC_BASE64;
	else if (!str_strcmp(&th_contact_encode_scheme, const_str("base32")))
		th_ct_enc_scheme = ENC_BASE32;
	else {
		LM_ERR("Unsupported value for 'th_contact_encode_scheme' modparam!"
			"Use 'base64' or 'base32'\n");
		goto error;
	}
	
	th_contact_encode_scheme_legacy.len = strlen(th_contact_encode_scheme_legacy.s);
	if (!str_strcmp(&th_contact_encode_scheme_legacy, const_str("base64")))
		th_ct_enc_scheme_legacy = ENC_BASE64;
	else if (!str_strcmp(&th_contact_encode_scheme_legacy, const_str("base32")))
		th_ct_enc_scheme_legacy = ENC_BASE32;
	else {
		LM_ERR("Unsupported value for 'th_contact_encode_scheme_legacy' modparam!"
			"Use 'base64' or 'base32'\n");
		goto error;
	}

	if (th_internal_trusted_tag.s) {
		th_internal_trusted_tag.len = strlen(th_internal_trusted_tag.s);
	}

	/* loading dependencies */
	if (load_tm_api(&tm_api)!=0) {
		LM_ERR("can't load TM API\n");
		goto error;
	}

	if (load_dlg_api(&dlg_api)!=0) {
		if (force_dialog) {
			LM_ERR("cannot force dialog. dialog module not loaded\n");
			goto error;
		}
	}

	if (register_pre_raw_processing_cb(topo_callid_pre_raw, 
	PRE_RAW_PROCESSING, 0/*no free*/) < 0) {
		LM_ERR("failed to initialize pre raw support\n");
		return -1;
	}

	if (register_post_raw_processing_cb(topo_callid_post_raw,
	POST_RAW_PROCESSING, 0/*no free*/) < 0) {
		LM_ERR("failed to initialize post raw support\n");
		return -1;
	}
	/* restore dialog callbacks when restart */
	if (dlg_api.register_dlgcb && dlg_api.register_dlgcb(NULL,
				DLGCB_LOADED,th_loaded_callback, NULL, NULL) < 0)
			LM_ERR("cannot register callback for dialog loaded - topology "
					"hiding signalling for ongoing calls will be lost after "
					"restart\n");


	return 0;
error:
	return -1;
}

static void mod_destroy(void)
{
	return;
}

static int fixup_mmode(void **param)
{
	*param = (void*)(unsigned long)dlg_match_mode_str_to_int((str*)*param);

	return 0;
}

int w_topology_hiding(struct sip_msg *req, str *flags_s)
{
	int flags=0;
	char *p;

	if (flags_s)
		for (p=flags_s->s;p<flags_s->s+flags_s->len;p++)
		{
			switch (*p)
			{
				case 'U':
					flags |= TOPOH_KEEP_USER;
					LM_DBG("Will preserve usernames while doing topo hiding\n");
					break;
				case 'C':
					flags |= TOPOH_HIDE_CALLID;
					LM_DBG("Will change callid while doing topo hiding\n");
					break;
				case 'D':
					flags |= TOPOH_DID_IN_USER;
					LM_DBG("Will push DID into contact username\n");
					break;
				case 'a':
					flags |= TOPOH_KEEP_ADV_A;
					LM_DBG("Will store advertised contact for calller\n");
					break;
				case 'A':
					flags |= TOPOH_KEEP_ADV_B;
					LM_DBG("Will store advertised contact for calllee\n");
					break;
				case 'b':
					flags |= TOPOH_USE_BINARY_ENCODING;
					LM_DBG("Will encode thinfo using compact binary encoding\n");
					break;
				default:
					LM_DBG("unknown topology_hiding flag : [%c] . Skipping\n",*p);
			}
		}

	return topology_hiding(req,flags);
}

int w_topology_hiding_match(struct sip_msg *req, void *seq_match_mode_val)
{
	int mm;

	/* copy-paste from w_match_dialog() */
	if (!seq_match_mode_val)
		mm = SEQ_MATCH_DEFAULT;
	else
		mm = (int)(long)seq_match_mode_val;

	if (!dlg_api.match_dialog || dlg_api.match_dialog(req, mm) < 0)
		return topo_hiding_match_no_dlg(req);
	else
		/* we went to the dlg module, which triggered us back, all good */
		return 1;
}

static char *callid_buf=NULL;
static int callid_buf_len=0;

static int pv_parse_th_route_name(pv_spec_p sp, const str *in)
{
	if (sp == NULL || in == NULL || in->s == NULL || in->len == 0)
		return -1;

	sp->pvp.pvn.type = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.type = 0;

	if (in->len == 4 && strncasecmp(in->s, "host", 4) == 0) {
		sp->pvp.pvn.u.isname.name.n = TH_ROUTE_HOST;
	} else if (in->len == 4 && strncasecmp(in->s, "port", 4) == 0) {
		sp->pvp.pvn.u.isname.name.n = TH_ROUTE_PORT;
	} else if (in->len == 4 && strncasecmp(in->s, "user", 4) == 0) {
		sp->pvp.pvn.u.isname.name.n = TH_ROUTE_USER;
	} else if (in->len == 6 && strncasecmp(in->s, "params", 6) == 0) {
		sp->pvp.pvn.u.isname.name.n = TH_ROUTE_PARAMS;
	} else {
		LM_ERR("unsupported route field <%.*s>\n", in->len, in->s);
		return -1;
	}

	return 0;
}

static int pv_topo_callee_callid(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	struct dlg_cell *dlg;
	int req_len = 0,i;

	if(res==NULL)
		return -1;

	if ( (dlg=dlg_api.get_dlg())==NULL || 
	(!dlg_api.is_mod_flag_set(dlg,TOPOH_HIDE_CALLID))) {
		return pv_get_null( msg, param, res);
	}


	req_len = calc_word64_encode_len(dlg->callid.len) + topo_hiding_prefix.len;

	if (req_len*2 > callid_buf_len) {
		callid_buf = pkg_realloc(callid_buf,req_len*2);
		if (callid_buf == NULL) {
			LM_ERR("No more pkg\n");
			return pv_get_null( msg, param, res);
		}

		callid_buf_len = req_len*2;
	}

	memcpy(callid_buf+req_len,topo_hiding_prefix.s,topo_hiding_prefix.len);
	for (i=0;i<dlg->callid.len;i++)
		callid_buf[i] = dlg->callid.s[i] ^ topo_hiding_seed.s[i%topo_hiding_seed.len];

	word64encode((unsigned char *)(callid_buf+topo_hiding_prefix.len+req_len),
		     (unsigned char *)(callid_buf),dlg->callid.len);

	res->rs.s = callid_buf+req_len;
	res->rs.len = req_len;
	res->flags = PV_VAL_STR;

	return 0;
}

static int pv_get_th_decoded_routes(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	int idx, idxf;
	int field_id = 0;
	struct sip_uri uri;

	if (msg == NULL || res == NULL)
		return -1;

	if (!ctx_decoded_routes_is_valid()) {
		return pv_get_null(msg, param, res);
	}

	if (decoded_route_set_count <= 1)
		return pv_get_null(msg, param, res);

	if (pv_get_spec_index(msg, param, &idx, &idxf) != 0) {
		LM_ERR("invalid index\n");
		return -1;
	}

	if (param->pvn.type == PV_NAME_INTSTR) {
		field_id = param->pvn.u.isname.name.n;
	}

	if (idx < 0) {
		idx = (decoded_route_set_count - 1) + idx;
	}

	if (idx < 0 || idx >= (decoded_route_set_count - 1))
		return pv_get_null(msg, param, res);

	/* Adjust index: route 0 is at decoded_route_set[1], contact is at [0] */
	idx = idx + 1;

	/* Return full URI if no field specified */
	if (field_id == TH_ROUTE_FULL) {
		return pv_get_strval(msg, param, res, &decoded_route_set[idx]);
	}

	/* Parse URI for field access */
	if (parse_uri(decoded_route_set[idx].s, decoded_route_set[idx].len, &uri) < 0) {
		LM_ERR("Bad Route URI\n");
		return -1;
	}

	/* Return specific field from parsed URI */
	switch (field_id) {
		case TH_ROUTE_HOST:
			if (uri.host.len == 0)
				return pv_get_null(msg, param, res);
			return pv_get_strval(msg, param, res, &uri.host);

		case TH_ROUTE_PORT:
			return pv_get_uintval(msg, param, res, uri.port_no);

		case TH_ROUTE_USER:
			if (uri.user.len == 0)
				return pv_get_null(msg, param, res);
			return pv_get_strval(msg, param, res, &uri.user);

		case TH_ROUTE_PARAMS:
			if (uri.params.len == 0)
				return pv_get_null(msg, param, res);
			return pv_get_strval(msg, param, res, &uri.params);

		default:
			LM_ERR("unknown route field %d\n", field_id);
			return pv_get_null(msg, param, res);
	}
}

static int pv_get_th_decoded_routes_count(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	if (msg == NULL || res == NULL)
		return -1;

	/* Check if decoded routes are valid for this message context */
	if (!ctx_decoded_routes_is_valid()) {
		return pv_get_sintval(msg, param, res, 0);
	}

	return pv_get_sintval(msg, param, res, decoded_route_set_count - 1);
}

static int pv_get_th_decoded_contact(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	int field_id = 0;
	struct sip_uri uri;

	if (msg == NULL || res == NULL)
		return -1;

	/* Check if decoded routes are valid for this message context */
	if (!ctx_decoded_routes_is_valid()) {
		return pv_get_null(msg, param, res);
	}

	/* check if we have any decoded data (need at least contact) */
	if (decoded_route_set_count == 0)
		return pv_get_null(msg, param, res);

	/* Check if a field was specified */
	if (param->pvn.type == PV_NAME_INTSTR) {
		field_id = param->pvn.u.isname.name.n;
	}

	/* Return full URI if no field specified */
	if (field_id == TH_ROUTE_FULL) {
		return pv_get_strval(msg, param, res, &decoded_route_set[0]);
	}

	/* Parse URI for field access */
	if (parse_uri(decoded_route_set[0].s, decoded_route_set[0].len, &uri) < 0) {
		LM_ERR("Bad Contact URI\n");
		return -1;
	}

	switch (field_id) {
		case TH_ROUTE_HOST:
			if (uri.host.len == 0)
				return pv_get_null(msg, param, res);
			return pv_get_strval(msg, param, res, &uri.host);

		case TH_ROUTE_PORT:
			return pv_get_uintval(msg, param, res, uri.port_no);

		case TH_ROUTE_USER:
			if (uri.user.len == 0)
				return pv_get_null(msg, param, res);
			return pv_get_strval(msg, param, res, &uri.user);

		case TH_ROUTE_PARAMS:
			if (uri.params.len == 0)
				return pv_get_null(msg, param, res);
			return pv_get_strval(msg, param, res, &uri.params);

		default:
			LM_ERR("unknown route field %d\n", field_id);
			return pv_get_null(msg, param, res);
	}
}
