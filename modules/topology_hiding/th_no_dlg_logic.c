/*
 *
 * Copyright (C) 2026 Genesys Cloud Services, Inc.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include "th_no_dlg_logic.h"
#include "../../parser/parse_rr.h"
#include "../../parser/parse_uri.h"
#include "../../forward.h"
#include "../dialog/dlg_hash.h"
#include "../tm/tm_load.h"
#include "../rr/loose.h"
#include "../rr/api.h"
#include "../compression/compression_api.h"
#include <string.h>

#define START_THINFO_BUF_SZ 1000
#define THINFO_MAX_BUFFER_SIZE 10000

typedef struct {
	str input;
	str output;
} topology_buffer;

#define TOPOH_MATCH_SUCCESS         1
#define TOPOH_MATCH_FAILURE        -1
#define TOPOH_MATCH_ONE_WAY_HIDING -2

#define ROUTE_STR "Route: "
#define ROUTE_LEN (sizeof(ROUTE_STR) - 1)
#define ROUTE_PREF "Route: <"
#define ROUTE_PREF_LEN (sizeof(ROUTE_PREF) -1)
#define ROUTE_SUFF ">\r\n"
#define ROUTE_SUFF_LEN (sizeof(ROUTE_SUFF) -1)

extern struct tm_binds tm_api;
extern struct rr_binds rr_api;
static compression_api_t compression_api;

static int compression_enabled;
static topology_buffer th_buffer;

extern int th_ct_enc_scheme;
extern str topo_hiding_ct_encode_pw;
extern str th_contact_encode_param;
extern str th_internal_trusted_tag;
extern str th_is_self_socket_tag;

extern struct th_ct_params *th_param_list;
extern struct th_ct_params *th_hdr_param_list;

/* compression API support function signatures start */
static inline unsigned char* th_no_dlg_compress_and_encode(topology_buffer th_buffer[static 1], unsigned long input_len, unsigned long *out_len);
static inline unsigned char* th_no_dlg_decode_and_decompress(topology_buffer th_buffer[static 1], unsigned long input_len, unsigned long *out_len);
/* compression API support function signatures end */

static int th_no_dlg_encode_contact(struct sip_msg *msg, unsigned int flags, str *routes, unsigned int rrs_to_ignore);
static int th_no_dlg_rebuild_record_routes(size_t route_sets_size, str *routes[static route_sets_size], struct lump* lmp);
static void th_no_dlg_onrequest(struct cell *t, int type, struct tmcb_params *param);
static inline int _th_no_dlg_onrequest(struct sip_msg *req, union sockaddr_union *su, int proto, unsigned int flags);
static void th_no_dlg_onreply(struct cell *t, int type, struct tmcb_params *param);
static int th_no_dlg_seq_handling(struct sip_msg *msg, str *info);
static inline int th_no_dlg_one_way_hiding(struct socket_info *socket);
static inline int th_no_dlg_check_self_socket_tag(struct socket_info *socket);

int topo_hiding_no_dlg(struct sip_msg *req, struct cell* t, unsigned int extra_flags) {
	union sockaddr_union su;

	if (extra_flags & TOPOH_HIDE_CALLID)
		LM_WARN("Cannot hide callid when dialog support is not engaged!\n");
	if (extra_flags & TOPOH_DID_IN_USER)
		LM_WARN("Cannot store DID in user when dialog support is not engaged!\n");

	if (req->REQ_METHOD != METHOD_ACK) {
		tm_api.set_tmcb_flags(extra_flags);

		if (tm_api.register_tmcb(req, 0, TMCB_REQUEST_FWDED, th_no_dlg_onrequest, NULL, NULL) < 0) {
			LM_ERR("failed to register TMCB\n");
			return -1;
		}

		if (tm_api.register_tmcb(req, 0, TMCB_RESPONSE_FWDED, th_no_dlg_onreply, NULL, NULL) < 0) {
			LM_ERR("failed to register TMCB\n");
			return -1;
		}

		return 1;
	} else {
		if (init_su(&su, &req->rcv.dst_ip, req->rcv.dst_port) == 0) {
			return _th_no_dlg_onrequest(req, &su, req->rcv.proto, extra_flags);
		}

		LM_ERR("Failed to topology hide\n");
		return -1;
	}
}

int topo_hiding_match_no_dlg(struct sip_msg *msg) {
	struct sip_uri *r_uri;
	struct sip_uri rr_uri;
	str *route_set = NULL;
	int route_set_len = 0;
	int i = 0;

	if (parse_sip_msg_uri(msg) < 0) {
		LM_ERR("Failed to parse request URI\n");
		return -1;
	}

	if (parse_headers(msg, HDR_ROUTE_F, 0) == -1) {
		LM_ERR("failed to parse route headers\n");
	}

	r_uri = &msg->parsed_uri;

	if ((th_no_dlg_check_self_socket_tag(msg->rcv.bind_address) ||
		 check_self(&r_uri->host,r_uri->port_no ? r_uri->port_no : SIP_PORT, 0)) && msg->route == NULL) {
		/* topology_hiding_match with thinfo and request domain is us
		 * needs to have a thinfo to continue otherwise we cannot match */
		for (i = 0; i < r_uri->u_params_no; i++) {
			if (r_uri->u_name[i].len == th_contact_encode_param.len &&
				memcmp(th_contact_encode_param.s,r_uri->u_name[i].s,th_contact_encode_param.len) == 0) {
				LM_DBG("We found param in R-URI with value of %.*s\n",
					r_uri->u_val[i].len,r_uri->u_val[i].s);
				/* pass the param value to the matching funcs */
				return th_no_dlg_seq_handling(msg, &r_uri->u_val[i]);
			}
		}
	} else if (msg->route != NULL) {
		if (th_no_dlg_one_way_hiding(msg->rcv.bind_address)) {
			route_set = rr_api.get_route_set(msg, &route_set_len);

			if (route_set_len > 1) {
				route_set++;
				if (parse_uri(route_set->s, route_set->len, &rr_uri) < 0) {
					LM_ERR("Route header has a bad Contact URI\n");
					return TOPOH_MATCH_FAILURE;
				}

				if (!check_self(&rr_uri.host, rr_uri.port_no ? rr_uri.port_no : SIP_PORT, 0)) {
					LM_DBG("Route header not us, skip checking the next one\n");
					return TOPOH_MATCH_FAILURE;
				}

				if (rr_api.loose_route(msg) == 1) {
					LM_DBG("Route set matches one of our sockets with one way hiding\n");
					return TOPOH_MATCH_ONE_WAY_HIDING;
				}
			}
		}
	}

	LM_DBG("Topology hiding did not match\n");
	return TOPOH_MATCH_FAILURE;
}

int topo_hiding_init_no_dlg(int use_compression_api) {
	th_buffer.input.s = pkg_malloc(START_THINFO_BUF_SZ);
	th_buffer.output.s = pkg_malloc(START_THINFO_BUF_SZ);

	if (th_buffer.input.s == NULL || th_buffer.output.s == NULL) {
		LM_ERR("Error creating thinfo input/output buffer\n");
		return -1;
	}

	th_buffer.input.len = START_THINFO_BUF_SZ;
	th_buffer.output.len = START_THINFO_BUF_SZ;

	if (use_compression_api == 0) {
		LM_DBG("Not using the compression API\n");

		return 0;
	} else {
		compression_enabled = load_compression_api(&compression_api) == 0;
	}

	return compression_enabled;
}

int topo_hiding_destroy_no_dlg(void) {
	if (th_buffer.input.s)
		pkg_free(th_buffer.input.s);

	if (th_buffer.output.s)
		pkg_free(th_buffer.output.s);

	return 0;
}

static int th_no_dlg_rebuild_record_routes(size_t route_sets_size, str *routes[static route_sets_size], struct lump* lmp) {
	char *route_hdrs[route_sets_size];
	int size, i = 0, rc = 0;
	str *rr_set;

	memset(route_hdrs, 0, sizeof(route_hdrs));

	LM_DBG("Rebuilding %zu Record-Route sets\n", route_sets_size);
	for (; i < route_sets_size; i++) {
		rr_set = routes[i];

		if (rr_set->len == 0 || rr_set->s == NULL)
			continue;

		size = rr_set->len + RECORD_ROUTE_LEN + CRLF_LEN;
		route_hdrs[i] = pkg_malloc(size);
		if (route_hdrs[i] == NULL) {
			LM_ERR("no more pkg memory\n");
			rc = -1;
			goto cleanup;
		}

		memcpy(route_hdrs[i], RECORD_ROUTE, RECORD_ROUTE_LEN);
		memcpy(route_hdrs[i] + RECORD_ROUTE_LEN, rr_set->s, rr_set->len);
		memcpy(route_hdrs[i] + RECORD_ROUTE_LEN + rr_set->len, CRLF, CRLF_LEN);

		/* put after Via */
		if ((lmp = insert_new_lump_after(lmp, route_hdrs[i], size, HDR_RECORDROUTE_T)) == 0) {
			LM_ERR("failed inserting new route set\n");
			rc = -1;
			goto cleanup;
		}

		LM_DBG("Added record route [%.*s]\n", size, route_hdrs[i]);

		pkg_free(rr_set->s);
		rr_set->s = NULL;
		rr_set->len = 0;
	}

cleanup:
	for (int x = i; x < route_sets_size; x++) {
		/* Assume the first lmp successfully added so we don't want to free the header */
		if (route_hdrs[x])
			pkg_free(route_hdrs[x]);
		pkg_free(routes[x]->s);
		routes[x]->len = 0;
	}

	return rc;
}

static void th_no_dlg_onreply(struct cell *t, int type, struct tmcb_params *param) {
	struct lump* lmp;
	str rpl_rr_set = STR_NULL;
	str req_rr_set = STR_NULL;
	str *route_sets[2] = { NULL };
	str *route_s = (str *)*param->param;
	struct sip_msg *req = param->req;
	struct sip_msg *rpl = param->rpl;
	size_t route_size = 0;
	unsigned int no_req_rrs = 0;
	unsigned int flags = param->flags;
	int do_rr = 0;
	int one_way_hiding = th_no_dlg_one_way_hiding(t->uas.response.dst.send_sock);

	LM_DBG("Response callback with flags %u \n", flags);

	/* parse all headers to be sure that all RR and Contact hdrs are found */
	if (parse_headers(rpl, HDR_EOH_F, 0)< 0) {
		LM_ERR("Failed to parse reply\n");
		return;
	}

	if (parse_to_header(req) < 0 || req->to == NULL || get_to(req) == NULL) {
		LM_ERR("cannot parse TO header\n");
		return;
	}

	/* do_rr determined by if the request has a tag, don't add them on sequential */
	do_rr = get_to(req)->tag_value.len == 0 || get_to(req)->tag_value.s == NULL;

	/* pass record route headers, get them from the reply if one_way_hiding */
	if (one_way_hiding && do_rr && rpl->record_route) {
		if (print_rr_body(rpl->record_route, &rpl_rr_set, 0, 1, NULL) != 0 ){
			LM_ERR("failed to print route records \n");
			return;
		}

		route_sets[route_size++] = &rpl_rr_set;
		LM_DBG("Reply Record-Routes %.*s\n", rpl_rr_set.len, rpl_rr_set.s);
	}

	if (do_rr && req->record_route) {
		if (print_rr_body(req->record_route, &req_rr_set, 0, 1, &no_req_rrs) != 0) {
			LM_ERR("failed to print route records \n");
			return;
		}

		route_sets[route_size++] = &req_rr_set;
		LM_DBG("Request Record-Routes %.*s\n", req_rr_set.len, req_rr_set.s);
	}

	if (topo_delete_record_routes(rpl) < 0) {
		LM_ERR("Failed to remove Record Route header \n");
		return;
	}

	if (!one_way_hiding) {
		if (topo_delete_vias(rpl) < 0) {
			LM_ERR("Failed to remove via headers\n");
			return;
		}
	}

	if (!(lmp = restore_vias_from_req(req, rpl))) {
		LM_ERR("Failed to restore VIA headers from request \n");
		return;
	}

	if (!one_way_hiding) {
		if (!(rpl->REPLY_STATUS >= 300 && rpl->REPLY_STATUS < 400) ) {
			if (th_no_dlg_encode_contact(rpl, flags, route_s, no_req_rrs) < 0) {
				LM_ERR("Failed to encode contact header \n");
				return;
			}
		}
	}

	if (route_size > 0 && th_no_dlg_rebuild_record_routes(route_size, route_sets, lmp) != 0) {
		LM_ERR("failed to add route headers back in \n");
	}

	return;
}

static void th_no_dlg_onrequest(struct cell *t, int type, struct tmcb_params *param) {
	struct sip_msg *req = param->req;
	struct ua_client *uac = t->uac;
	unsigned int flags = param->flags;

	if (_th_no_dlg_onrequest(req, &uac->request.dst.to, uac->request.dst.proto, flags) < 0) {
		LM_ERR("Failed to do topology_hiding on request\n");
	}
}

static inline int _th_no_dlg_onrequest(struct sip_msg *req, union sockaddr_union *su, int proto, unsigned int flags) {
	struct socket_info *send_sock = NULL;

	LM_DBG("Request callback with flags %u\n", flags);

	/* parse all headers to be sure that all RR and Contact hdrs are found */
	if (parse_headers(req, HDR_EOH_F, 0) >= 0) {
		send_sock = get_send_socket(req, su, proto);
		if (!th_no_dlg_one_way_hiding(send_sock)) {
			if (topo_delete_record_routes(req) < 0) {
				LM_ERR("Failed to remove Record Route header \n");
				return -1;
			}

			if (topo_delete_vias(req) < 0) {
				LM_ERR("Failed to remove via headers\n");
				return -1;
			}

			if (th_no_dlg_encode_contact(req, flags, NULL, 0) < 0) {
				LM_ERR("Failed to encode contact header \n");
				return -1;
			}
		}
	} else {
		LM_ERR("Failed to parse request\n");
	}

	return 1;
}

static inline int th_no_dlg_realloc_input_buffer(topology_buffer topology_buffer[static 1], int new_size) {
	char *new_buf;

	if (new_size > THINFO_MAX_BUFFER_SIZE) {
		LM_ERR("Buffer to be realloc'd from %d larger than max size allowed %d\n", 
		       new_size, THINFO_MAX_BUFFER_SIZE);
		return -1;
	}

	new_buf = pkg_realloc(topology_buffer->input.s, new_size);
	if (new_buf == NULL) {
		LM_ERR("failed to reallocate buffer to %d bytes\n", new_size);
		return -1;
	}

	topology_buffer->input.s = new_buf;
	topology_buffer->input.len = new_size;

	return 0;
}

#define HAS_NO_CONTACT_BODY(_m) (((contact_body_t *) ((_m)->contact->parsed))->contacts == NULL || \
                              ((contact_body_t *) ((_m)->contact->parsed))->contacts->next != NULL)

/* We encode the RR headers, the actual Contact and the socket str for this leg */
/* Via headers will be restored using the TM module, no need to save anything for them */
static char* build_encoded_contact_suffix(struct sip_msg* msg, str *routes, unsigned int rrs_to_ignore, int *suffix_len, int flags) {
	short rr_len, ct_len, addr_len, flags_len, enc_len;
	char *suffix_enc = NULL, *p, *s;
	char *encoding_buffer = th_buffer.input.s;
	unsigned char *encoded;
	str rr_set = STR_NULL, contact = STR_NULL, flags_str = STR_NULL;
	int i, total_len = 0, params_len = 0;
	struct sip_uri ctu;
	struct th_ct_params* el;
	param_t *it;
	unsigned long plain_len, compressed_encoded_len;
	int is_req = (msg->first_line.type == SIP_REQUEST) ? 1 : 0;
	int local_len = sizeof(short) /* RR length */ +
					sizeof(short) /* Contact length */ +
					sizeof(short) /* Flags length */ +
					sizeof(short) /* bind addr */;

	/* parse all headers as we can have multiple
	   RR headers in the same message */
	if (parse_headers(msg,HDR_EOH_F, 0)<0 ){
		LM_ERR("failed to parse all headers\n");
		return NULL;
	}

	if (routes) {
		rr_set = *routes;
		rr_len = (short) routes->len;
	} else if(msg->record_route) {
		if (print_rr_body(msg->record_route, &rr_set, !is_req, 0, &rrs_to_ignore) != 0){
			LM_ERR("failed to print route records \n");
			return NULL;
		}
		rr_len = (short) rr_set.len;
	} else {
		rr_len = 0;
	}

	if (parse_contact(msg->contact) < 0 || HAS_NO_CONTACT_BODY(msg)) {
		LM_ERR("bad Contact HDR\n");
		goto error;
	} else {
		contact = ((contact_body_t *)msg->contact->parsed)->contacts->uri;
		if (parse_uri(contact.s, contact.len, &ctu) < 0) {
			LM_ERR("Bad Contact URI\n");
			goto error;
		} 
		ct_len = (short)contact.len;
	}

	flags_str.s = int2str(flags, &flags_str.len);
	flags_len = (short) flags_str.len;
	
	addr_len = (short) msg->rcv.bind_address->sock_str.len;
	local_len += rr_len + ct_len + flags_len + addr_len;
	enc_len = th_ct_enc_scheme == ENC_BASE64 ?
		calc_word64_encode_len(local_len) : calc_word32_encode_len(local_len);

	if (th_param_list) {
		for (el = th_param_list; el; el = el->next) {
			/* we just iterate over the unknown params */
			for (i = 0; i < ctu.u_params_no; i++) {
				if (str_match(&el->param_name, &ctu.u_name[i]))
					params_len += topo_ct_param_len(&ctu.u_name[i], &ctu.u_val[i], 0);
			}
		}
	}

	if (th_hdr_param_list) {
		for (el = th_hdr_param_list; el; el = el->next) {
			for (it = ((contact_body_t *)msg->contact->parsed)->contacts->params; it; it = it->next) {
				if (str_match(&el->param_name, &it->name))
					params_len += topo_ct_param_len(&it->name, &it->body, 1);
			}
		}
	}

	if (local_len > th_buffer.input.len || th_no_dlg_realloc_input_buffer(&th_buffer, local_len) == -1) {
		goto error;
	}

	encoding_buffer = th_buffer.input.s;

	p = encoding_buffer;
	memcpy(p, &rr_len, sizeof(short));
	p += sizeof(short);
	if (rr_len) {
		memcpy(p, rr_set.s, rr_set.len);
		p+= rr_set.len;
	}

	memcpy(p, &ct_len, sizeof(short));
	p += sizeof(short);
	if (ct_len) {
		memcpy(p, contact.s, contact.len);
		p+= contact.len;
	}

	memcpy(p, &flags_len, sizeof(short));
	p += sizeof(short);

	memcpy(p,flags_str.s, flags_str.len);
	p += flags_str.len;

	memcpy(p, &addr_len, sizeof(short));
	p += sizeof(short);

	memcpy(p, msg->rcv.bind_address->sock_str.s, msg->rcv.bind_address->sock_str.len);
	p += msg->rcv.bind_address->sock_str.len;

	plain_len = p - encoding_buffer;
	encoded = th_no_dlg_compress_and_encode(&th_buffer, plain_len, &compressed_encoded_len);
	if (!encoded) {
		LM_ERR("failed to compress and encode\n");
		goto error;
	}

	enc_len = th_ct_enc_scheme == ENC_BASE64 ?
		calc_word64_encode_len(compressed_encoded_len) : calc_word32_encode_len(compressed_encoded_len);

	total_len = enc_len +
				params_len +
			    1 /* ; */ +
				th_contact_encode_param.len +
				1 /* = */  +
				1 /* > */;

	suffix_enc = pkg_malloc(total_len + 1);
	if (!suffix_enc) {
		LM_ERR("no more pkg\n");
		goto error;
	}

	s = suffix_enc;
	*s++ = ';';
	memcpy(s, th_contact_encode_param.s, th_contact_encode_param.len);
	s+= th_contact_encode_param.len;
	*s++ = '=';

	if (th_ct_enc_scheme == ENC_BASE64)
		word64encode((unsigned char*)s, encoded, compressed_encoded_len);
	else
		word32encode((unsigned char*)s, encoded, compressed_encoded_len);

	s = s + enc_len;

	if (th_param_list) {
		for (el = th_param_list; el; el = el->next) {
			/* we just iterate over the unknown params */
			for (i = 0; i < ctu.u_params_no; i++) {
				if (str_match(&el->param_name, &ctu.u_name[i]))
					s = topo_ct_param_copy(s, &ctu.u_name[i], &ctu.u_val[i], 0);
			}
		}
	}

	*s++ = '>';
	if (th_hdr_param_list) {
		for (el = th_hdr_param_list; el; el = el->next) {
			for (it = ((contact_body_t *)msg->contact->parsed)->contacts->params; it; it = it->next) {
				if (str_match(&el->param_name, &it->name))
					s = topo_ct_param_copy(s, &it->name, &it->body, 1);
			}
		}
	}

	if (rr_set.s && !routes)
		pkg_free(rr_set.s);

	*suffix_len = s - suffix_enc;
	return suffix_enc;
error:
	if (rr_set.s && !routes)
		pkg_free(rr_set.s);
	if (suffix_enc)
		pkg_free(suffix_enc);
	return NULL;
}

static int th_no_dlg_encode_contact(struct sip_msg *msg, unsigned int flags, str *routes, unsigned int rrs_to_ignore) {
	struct lump* lump;
	char *prefix = NULL,*suffix = NULL,*ct_username = NULL;
	int prefix_len, suffix_len = 0, ct_username_len = 0;
	struct sip_uri ctu;
	str contact;

	if (!msg->contact) {
		if(parse_headers(msg, HDR_CONTACT_F, 0)< 0) {
			LM_ERR("Failed to parse headers\n");
			return -1;
		}
		if (!msg->contact)
			return 0;
	}

	if (!(lump = delete_existing_contact(msg, 0))) {
		LM_ERR("Failed to delete existing contact \n");
		goto error;
	}

	LM_DBG("Flags '%d' passed for encoding Contact\n", flags);

	prefix_len = 5; /* <sip: */
	if (flags & TOPOH_KEEP_USER) {
		if (parse_contact(msg->contact)  <0 || HAS_NO_CONTACT_BODY(msg)) {
			LM_ERR("bad Contact HDR\n");
		} else {
			contact = ((contact_body_t *)msg->contact->parsed)->contacts->uri;
			if (parse_uri(contact.s, contact.len, &ctu) < 0) {
				LM_ERR("Bad Contact URI\n");
			} else {
				ct_username = ctu.user.s;
				ct_username_len = ctu.user.len;
				LM_DBG("Trying to propagate username [%.*s]\n",ct_username_len,
									ct_username);
				if (ct_username_len > 0)
					prefix_len += 1 + /* @ */ + ct_username_len;
			}
		}
	}

	prefix = pkg_malloc(prefix_len);
	if (!prefix) {
		LM_ERR("no more pkg\n");
		goto error;
	}
	memcpy(prefix,"<sip:",5);
	if (flags & TOPOH_KEEP_USER && ct_username_len > 0) {
		memcpy(prefix+5,ct_username,ct_username_len);
		prefix[prefix_len-1] = '@';
	}

	if (!(lump = insert_new_lump_after(lump, prefix, prefix_len,0))) {
		LM_ERR("failed inserting '<sip:'\n");
		goto error;
	}
	/* make sure we do not free this string in case of a further error */
	prefix = NULL;

	if (!(suffix = build_encoded_contact_suffix(msg, routes, rrs_to_ignore, &suffix_len, flags))) {
		LM_ERR("Failed to build suffix \n");
		goto error;
	}

	if (!(lump = insert_subst_lump_after(lump, SUBST_SND_ALL, 0))) {
		LM_ERR("failed inserting SUBST_SND buf\n");
		goto error;
	}

	if (!(lump = insert_new_lump_after(lump, suffix,suffix_len, 0))) {
		LM_ERR("failed inserting '<sip:'\n");
		goto error;
	}

	return 0;
error:
	if (prefix) pkg_free(prefix);
	if (suffix) pkg_free(suffix);
	return -1;
}

static inline void topo_no_dlg_seq_free(void *p) {
	if (p)
		shm_free(p);
}

#define MAX_RR_HEADERS_TO_CHECK 3
#define RR_SUCCESS     1
#define RR_FAILURE    -1
#define RR_FREE_HEAD  -2
#define RR_FREE_ROUTE -3

static inline int topo_no_dlg_loose_route(struct sip_msg *msg, const str rr_buf[static 1], str *route_buf, rr_t head[static 1], struct lump *lmp, struct socket_info *sock) {
	rr_t *head_next = head;
	struct sip_uri rru;
	char *buf = msg->buf;
	char *route = NULL;
	int rr_headers_checked = 0, buf_start_count = 0, size = 0;

	while (head_next != NULL || rr_headers_checked == MAX_RR_HEADERS_TO_CHECK) {
		if (parse_uri(head_next->nameaddr.uri.s, head_next->nameaddr.uri.len, &rru) < 0) {
			return RR_FREE_HEAD;
		}

		if (check_self(&rru.host, rru.port_no ? rru.port_no : SIP_PORT, 0) != 1) {
			lmp = anchor_lump(msg,msg->headers->name.s - buf, 0);
			if (lmp == 0) {
				LM_ERR("failed anchoring new lump\n");
				return RR_FREE_HEAD;
			}

			size = rr_buf->len + ROUTE_LEN + CRLF_LEN - buf_start_count;
			route = pkg_malloc(size+1);
			if (route == 0) {
				LM_ERR("no more pkg memory\n");
				return RR_FREE_HEAD;
			}

			memcpy(route,ROUTE_STR,ROUTE_LEN);
			memcpy(route + ROUTE_LEN, rr_buf->s + buf_start_count, rr_buf->len - buf_start_count);
			memcpy(route + ROUTE_LEN + rr_buf->len - buf_start_count, CRLF,CRLF_LEN);

			route[size] = 0;

			if ((lmp = insert_new_lump_after(lmp,route,size,HDR_ROUTE_T)) == 0) {
				LM_ERR("failed inserting new route set\n");
				return RR_FREE_ROUTE;
			}

			LM_DBG("Setting route  header to <%s> \n", route);
			LM_DBG("setting dst_uri to <%.*s> \n", head_next->nameaddr.uri.len,
					head_next->nameaddr.uri.s);
			if (set_dst_uri(msg,&head_next->nameaddr.uri) != 0) {
				return RR_FREE_HEAD;
			}
			head = head_next;
			break;
		} else {
			LM_DBG("Route header is me not adding to message\n");

			buf_start_count += head_next->nameaddr.uri.len + 3; // 3 == ,<>
			sock = grep_sock_info(&rru.host, rru.port_no ? rru.port_no : SIP_PORT, 0);
			if (sock) {
				msg->force_send_socket = sock;
			}
		}
		rr_headers_checked++;
		memset(&rru, 0, sizeof(rru));
		head_next = head_next->next;
	}

	return RR_SUCCESS;
}

static inline int topo_no_dlg_strict_route(struct sip_msg *msg, const str rr_buf[static 1], str *route_buf, rr_t head[static 1], struct lump *lmp) {
	int i = 0, size = 0;
	rr_t *rrp = head;
	char *buf = msg->buf;
	char *route = NULL, *hdrs = NULL;

	if (set_ruri(msg,&head->nameaddr.uri) !=0 ) {
		LM_ERR("failed setting new dst uri\n");
		return RR_FREE_HEAD;
	}

	while (rrp) {
		i++;
		rrp=rrp->next;
	}

	/* If there are more routes other than the first, add them */
	if (i > 1) {
		lmp = anchor_lump(msg,msg->headers->name.s - buf, 0);
		if (lmp == 0) {
			LM_ERR("failed anchoring new lump\n");
			return RR_FREE_HEAD;
		}

		hdrs = rr_buf->s + head->len + 1;

		size = rr_buf->len - head->len - 1 + ROUTE_LEN + CRLF_LEN;
		route = pkg_malloc(size);
		if (route == 0) {
			LM_ERR("no more pkg memory\n");
			return RR_FREE_HEAD;
		}

		memcpy(route, ROUTE_STR, ROUTE_LEN);
		memcpy(route + ROUTE_LEN, hdrs, rr_buf->len - head->len - 1);
		memcpy(route + ROUTE_LEN + rr_buf->len - head->len - 1, CRLF, CRLF_LEN);

		LM_DBG("Adding Route header : [%.*s] \n",size,route);

		if ((lmp = insert_new_lump_after(lmp, route,size, HDR_ROUTE_T)) == 0) {
			LM_ERR("failed inserting new route set\n");
			return RR_FREE_ROUTE;
		}
		msg->msg_flags |= FL_HAS_ROUTE_LUMP;
		route_buf->s = route;
		route_buf->len = rr_buf->len - head->len - 1;
	}

	if (lmp == NULL) {
		lmp = anchor_lump(msg, msg->headers->name.s - buf,0);
		if (lmp == 0) {
			LM_ERR("failed anchoring new lump\n");
			return RR_FAILURE;
		}
	}

	return RR_SUCCESS;
}

static int th_no_dlg_seq_handling(struct sip_msg *msg, str *info) {
	int i, max_size, size, route_rc, port, proto, next_strict = 0;
	char *p = NULL, *route = NULL, *remote_contact = NULL, *decode_buffer = NULL, *msg_buf = NULL;
	str rr_buf, ct_buf, flags_buf, bind_buf, host, route_buf;
	struct hdr_field *it;
	rr_t *head = NULL;
	struct sip_uri fru;
	struct lump* lmp = NULL;
	struct socket_info *sock = NULL;
	str *route_s = NULL;
	unsigned long dec_len = 0;
	unsigned int flags;

	/* parse all headers to be sure that all RR and Contact hdrs are found */
	if (parse_headers(msg, HDR_EOH_F, 0)< 0) {
		LM_ERR("Failed to parse reply\n");
		return TOPOH_MATCH_FAILURE;
	}

	msg_buf = msg->buf;

	/* delete record route, shouldn't have a record-route here anyway */
	for (it = msg->record_route; it; it = it->sibling) {
		if (del_lump(msg, it->name.s - msg_buf, it->len, 0) == 0) {
			LM_ERR("del_lump failed\n");
			return TOPOH_MATCH_FAILURE;
		}
	}

	max_size = th_ct_enc_scheme == ENC_BASE64 ?
		calc_max_word64_decode_len(info->len) :
		calc_max_word32_decode_len(info->len);
	
	LM_DBG("Max Size of decoded length %d\n", max_size);
	if (max_size > th_buffer.input.len && th_no_dlg_realloc_input_buffer(&th_buffer, max_size) != 0) {
		return -1;
	}

	if (th_ct_enc_scheme == ENC_BASE64)
		dec_len = word64decode((unsigned char *) th_buffer.input.s,
			(unsigned char *)info->s, info->len);
	else
		dec_len = word32decode((unsigned char *) th_buffer.input.s,
			(unsigned char *)info->s, info->len);
	
	if (dec_len <= 0) {
		LM_ERR("Failed to decode\n");
		return -1;
	}
	
	decode_buffer = (char *) th_no_dlg_decode_and_decompress(&th_buffer, dec_len, &dec_len);

	#define __extract_len_and_buf(_p, _len, _s) \
		do { \
			(_s).len = *(short *)p;\
			if ((_s).len<0 || (_s).len>_len) {\
				LM_ERR("bad length %d in encoded contact\n", (_s).len);\
				goto err_fail_early;\
			}\
			(_s).s = _p + sizeof(short);\
			_p += sizeof(short) + (_s).len;\
			_len -= sizeof(short) + (_s).len;\
		} while(0)

	p = decode_buffer;
	size = dec_len;
	__extract_len_and_buf(p, size, rr_buf);
	__extract_len_and_buf(p, size, ct_buf);
	__extract_len_and_buf(p, size, flags_buf);
	__extract_len_and_buf(p, size, bind_buf);

	LM_DBG("extracted routes [%.*s] , ct [%.*s] , flags [%.*s] and bind [%.*s]\n",
		rr_buf.len, rr_buf.s, ct_buf.len, ct_buf.s, flags_buf.len, flags_buf.s, bind_buf.len, bind_buf.s);

	if (rr_buf.len) {
		if (parse_rr_body(rr_buf.s,rr_buf.len,&head) != 0) {
			LM_ERR("failed parsing route set\n");
			goto err_fail_early;
		}

		if (parse_uri(head->nameaddr.uri.s, head->nameaddr.uri.len, &fru) < 0) {
			LM_ERR("Failed to parse SIP uri\n");
			goto err_free_head;
		}

		next_strict = is_strict(&fru.params);
	}

	if (msg->dst_uri.s && msg->dst_uri.len) {
		/* reset dst_uri if previously set
		 * either by loose route or manually */
		pkg_free(msg->dst_uri.s);
		msg->dst_uri.s = NULL;
		msg->dst_uri.len = 0;
	}

	if (!next_strict) {
		LM_DBG("Fixing message. Next hop is Loose router\n");
		if (ct_buf.len && ct_buf.s) {
			LM_DBG("Setting new URI to  <%.*s> \n",ct_buf.len,
					ct_buf.s);

			if (set_ruri(msg,&ct_buf) != 0) {
				LM_ERR("failed setting ruri\n");
				goto err_free_head;
			}
		}

		if (parse_headers(msg, HDR_EOH_F, 0)<0 ) {
			LM_ERR("failed to parse headers when looking after ROUTEs\n");
			goto err_free_head;
		}

		if (msg->route) {
			for (it = msg->route; it; it = it->sibling) {
				if (it->parsed && ((rr_t*)it->parsed)->deleted)
					continue;
				if ((lmp = del_lump(msg,it->name.s - msg_buf,it->len,HDR_ROUTE_T)) == 0) {
					LM_ERR("del_lump failed \n");
					goto err_free_head;
				}
			}
		}

		if (rr_buf.len != 0 && rr_buf.s) {
			route_rc = topo_no_dlg_loose_route(msg, &rr_buf, &route_buf, head, lmp, sock);

			if (route_rc == RR_SUCCESS) {
				msg->msg_flags |= FL_HAS_ROUTE_LUMP;
				route_buf = rr_buf;
			} else if (route_rc == RR_FREE_HEAD) {
				goto err_free_head;
			} else {
				goto err_free_route;
			}
		}
	} else {
		LM_DBG("Fixing message. Next hop is Strict router\n");
		if (msg->route) {
			for (it = msg->route; it; it = it->sibling) {
				if (it->parsed && ((rr_t*)it->parsed)->deleted)
					continue;
				if ((lmp = del_lump(msg,it->name.s - msg_buf,it->len,HDR_ROUTE_T)) == 0) {
					LM_ERR("del_lump failed \n");
					goto err_free_head;
				}
			}
		}

		if (rr_buf.len !=0 && rr_buf.s) {
			route_rc = topo_no_dlg_strict_route(msg, &rr_buf, &route_buf, head, lmp);

			if (route_rc == RR_SUCCESS && ct_buf.len && ct_buf.s) {
				size = ct_buf.len + ROUTE_PREF_LEN + ROUTE_SUFF_LEN;
				remote_contact = pkg_malloc(size);
				if (remote_contact == NULL) {
					LM_ERR("no more pkg \n");
					goto err_free_head;
				}

				memcpy(remote_contact, ROUTE_PREF,ROUTE_PREF_LEN);
				memcpy(remote_contact + ROUTE_PREF_LEN, ct_buf.s, ct_buf.len);
				memcpy(remote_contact + ROUTE_PREF_LEN + ct_buf.len,
						ROUTE_SUFF, ROUTE_SUFF_LEN);

				LM_DBG("Adding remote contact route header : [%.*s]\n",
						size,remote_contact);

				if (insert_new_lump_after(lmp, remote_contact, size, HDR_ROUTE_T) == 0) {
					LM_ERR("failed inserting remote contact route\n");
					pkg_free(remote_contact);
					goto err_free_head;
				}
				msg->msg_flags |= FL_HAS_ROUTE_LUMP;
			} else if (route_rc == RR_FAILURE) {
				goto err_fail_early;
		    } else if (route_rc == RR_FREE_HEAD) {
				goto err_free_head;
			} else {
				goto err_free_route;
			}
		}
	}

	if (route_buf.s && route_buf.len) {
		route_s = shm_malloc(sizeof *route_s + route_buf.len);
		if (route_s) {
			route_s->s = (char *)(route_s + 1);
			memcpy(route_s->s, route_buf.s, route_buf.len);
			route_s->len = route_buf.len;
		}
	}

	if (str2int(&flags_buf, &flags) < 0) {
		LM_WARN("Failed to convert string to integer, default to no flags\n");
		flags = 0;
	}

	tm_api.set_tmcb_flags(flags);
	/* register tm callback for response in  */
	if (tm_api.register_tmcb(msg, 0, TMCB_RESPONSE_FWDED, th_no_dlg_onreply, route_s, topo_no_dlg_seq_free) < 0) {
		LM_ERR("failed to register TMCB\n");
		goto err_free_route;
	}

	route_s = NULL;

	if (sock == NULL && bind_buf.len && bind_buf.s) {
		LM_DBG("forcing send socket for req to [%.*s]\n",bind_buf.len,bind_buf.s);
		if (parse_phostport(bind_buf.s, bind_buf.len, &host.s, &host.len, &port, &proto) != 0) {
			LM_ERR("bad socket <%.*s>\n", bind_buf.len, bind_buf.s);
		} else {
			sock = grep_sock_info(&host, (unsigned short) port, proto);
			if (!sock) {
				LM_WARN("non-local socket <%.*s>...ignoring\n", bind_buf.len, bind_buf.s);
			}
			msg->force_send_socket = sock;
		}
	}

	if (rr_buf.len)
		free_rr(&head);

	if (!th_no_dlg_one_way_hiding(sock)) {
		if (topo_delete_vias(msg) < 0) {
			LM_ERR("Failed to remove via headers\n");
			return TOPOH_MATCH_FAILURE;
		}

		if (th_no_dlg_encode_contact(msg, flags, NULL, 0) < 0) {
			LM_ERR("Failed to encode contact header \n");
			return TOPOH_MATCH_FAILURE;
		}
	}

	return TOPOH_MATCH_SUCCESS;

err_free_route:
	if (route)
		pkg_free(route);
	if (route_s)
		shm_free(route_s);
err_free_head:
	if (rr_buf.len)
		free_rr(&head);
err_fail_early:
	return TOPOH_MATCH_FAILURE;
}

static inline unsigned char* th_no_dlg_encode(unsigned long input_len, unsigned char input_buffer[static input_len]) {
	int i;

	for (i = 0; i < input_len; i++)
		input_buffer[i] ^= topo_hiding_ct_encode_pw.s[i % topo_hiding_ct_encode_pw.len];

	return input_buffer;
}

static inline unsigned char* th_no_dlg_compress_and_encode(topology_buffer th_buffer[static 1], unsigned long input_len, unsigned long *out_len) {
	unsigned char *plain_data = (unsigned char*) th_buffer->input.s;
	unsigned char *out_data = plain_data;
	unsigned long compressed_len = 0;
	int rc;

	*out_len = input_len;

	if (compression_enabled) {
		rc = compression_api.compress(plain_data,
									  input_len, 
								  	  &th_buffer->output,
	                              	  &compressed_len,
								      compression_api.level);

		if (compressed_len < input_len && compression_api.check_rc(rc) == 0) {
			LM_DBG("Compressed successful\n");

			*out_len = compressed_len;
			out_data = (unsigned char*) th_buffer->output.s;
		}
	}

	return th_no_dlg_encode(*out_len, out_data);
}

static inline unsigned char* th_no_dlg_decode(unsigned long input_len, unsigned char input_buffer[static input_len]) {
	int i;

	for (i = 0; i < input_len; i++)
		input_buffer[i] ^= topo_hiding_ct_encode_pw.s[i % topo_hiding_ct_encode_pw.len];

	return input_buffer;
}

static inline unsigned char* th_no_dlg_decode_and_decompress(topology_buffer th_buffer[static 1], unsigned long input_len, unsigned long *out_len) {
	unsigned char *input_data = (unsigned char*) th_buffer->input.s;
	unsigned char *out_data = input_data;
	unsigned long decompressed_len = 0;
	int rc;

	input_data = th_no_dlg_decode(input_len, input_data);
	*out_len = input_len;

	if (compression_enabled) {
		rc = compression_api.decompress(input_data, 
										input_len,
										&th_buffer->output,
										&decompressed_len);

		if (compression_api.check_rc(rc) == 0) {
			*out_len = decompressed_len;
			
			LM_DBG("Decompression successful - decompressed len %lu\n", decompressed_len);

			out_data = (unsigned char*) th_buffer->output.s;
		}
	}

	return out_data;
}

static inline int th_no_dlg_match_socket_tag(struct socket_info *socket, str socket_tag_to_match[static 1]) {
	if (socket != NULL && socket->tag.len > 0) {
		return socket->tag.len == socket_tag_to_match->len && 
		       strncmp(socket->tag.s, socket_tag_to_match->s, socket_tag_to_match->len) == 0;
	}

	return 0;
}

static inline int th_no_dlg_one_way_hiding(struct socket_info *socket) {
	return th_no_dlg_match_socket_tag(socket, &th_internal_trusted_tag);
}

static inline int th_no_dlg_check_self_socket_tag(struct socket_info *socket) {
	return th_no_dlg_match_socket_tag(socket, &th_is_self_socket_tag);
}