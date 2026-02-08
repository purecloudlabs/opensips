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
#include "th_binary_encoder.h"
#include <stdint.h>
#include <string.h>

#define START_THINFO_BUF_SZ 1000
#define THINFO_MAX_BUFFER_SIZE 10000
#define MAX_ENCODED_SIP_URIS 12

typedef struct {
	str input;
	str output;
} topology_buffer;

#define TOPOH_MATCH_LOOSE_ROUTE    3
#define TOPOH_MATCH_ONE_WAY_HIDING 2
#define TOPOH_MATCH_SUCCESS        1
#define TOPOH_MATCH_FAILURE       -1

#define ROUTE_STR "Route: "
#define ROUTE_LEN (sizeof(ROUTE_STR) - 1)
#define ROUTE_PREF "Route: <"
#define ROUTE_PREF_LEN (sizeof(ROUTE_PREF) -1)
#define ROUTE_SUFF ">\r\n"
#define ROUTE_SUFF_LEN (sizeof(ROUTE_SUFF) -1)

#define ROUTE_SUCCESS   (1<<0)
#define ROUTE_LOOSE     (1<<1)
#define ROUTE_SELF      (1<<2)
#define ROUTE_DOUBLE_RR (1<<3)
#define ROUTE_STRICT    (1<<4)
#define ROUTE_FAILURE   (1<<5)

extern struct tm_binds tm_api;
struct rr_binds rr_api;
static compression_api_t compression_api;

static int compression_enabled;
static int rr_enabled;
static topology_buffer th_buffer;

static encoded_uri_t encoded_uri_buf = { 0 };
static encoded_uri_t decoded_uri_buf = { 0 };

static char decoded_uri_str[MAX_ENCODED_URI_SIZE * 3];

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

static int th_no_dlg_encode_contact(struct sip_msg *msg, uint16_t flags, str *routes, unsigned int rrs_to_ignore);
static int th_no_dlg_rebuild_record_routes(size_t route_sets_size, str *routes[static route_sets_size], struct lump* lmp);
static void th_no_dlg_onrequest(struct cell *t, int type, struct tmcb_params *param);
static inline int _th_no_dlg_onrequest(struct sip_msg *req, union sockaddr_union *su, int proto, uint16_t flags);
static inline int _th_no_dlg_onrequest2(struct sip_msg *req, uint16_t flags, struct socket_info *send_socket);
static void th_no_dlg_onreply(struct cell *t, int type, struct tmcb_params *param);
static int th_no_dlg_seq_handling(struct sip_msg *msg, str *info);
static inline int th_no_dlg_one_way_hiding(struct socket_info *socket);
static inline int th_no_dlg_check_self_socket_tag(struct socket_info *socket);
static inline int topo_no_dlg_classify_route(rr_t head[static 1]);

static char* build_encoded_contact_suffix(struct sip_msg* msg, str *routes, unsigned int rrs_to_ignore, int *suffix_len, uint16_t flags, int socket_only);

int topo_hiding_no_dlg(struct sip_msg *req, struct cell* t, unsigned int extra_flags) {
	union sockaddr_union su;
	struct ua_client *uac;;

	if (t == NULL) {
		LM_ERR("Must create transaction before calling topology_hiding\n");
		return -2;
	}

	uac = t->uac;

	if (extra_flags & TOPOH_HIDE_CALLID)
		LM_WARN("Cannot hide callid when dialog support is not engaged!\n");
	if (extra_flags & TOPOH_DID_IN_USER)
		LM_WARN("Cannot store DID in user when dialog support is not engaged!\n");

	if (req->REQ_METHOD != METHOD_ACK) {
		tm_api.set_tmcb_flags(extra_flags);

		if (_th_no_dlg_onrequest(req, &uac->request.dst.to, uac->request.dst.proto, extra_flags) < 0) {
			LM_ERR("Failed to do topology_hiding on request\n");
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
	struct sip_uri *request_uri;
	struct sip_uri route_uri = { 0 };
	rr_t *auto_route = NULL, *after_auto = NULL;
	struct hdr_field *after_route_sibling = NULL;
	int i;
	struct socket_info *sock = NULL;
	int proto = 0;
	str ip = STR_NULL;
	unsigned short port = 0;
	int max_size, dec_len;
	uint16_t flags;

	if (parse_sip_msg_uri(msg) < 0) {
		LM_ERR("Failed to parse request URI\n");
		return -1;
	}

	if (parse_headers(msg, HDR_EOH_F, 0) == -1) {
		LM_ERR("failed to parse route headers\n");
	}

	request_uri = &msg->parsed_uri;

	if (msg->route == NULL && (th_no_dlg_check_self_socket_tag(msg->rcv.bind_address) ||
		 check_self(&request_uri->host, request_uri->port_no ? request_uri->port_no : SIP_PORT, 0))) {
		/* topology_hiding_match with thinfo and request domain is us
		 * needs to have a thinfo to continue otherwise we cannot match */
		for (i = 0; i < request_uri->u_params_no; i++) {
			if (request_uri->u_name[i].len == th_contact_encode_param.len &&
				memcmp(th_contact_encode_param.s, request_uri->u_name[i].s, th_contact_encode_param.len) == 0) {
				LM_DBG("We found param in R-URI with value of %.*s\n",
					request_uri->u_val[i].len, request_uri->u_val[i].s);
				/* pass the param value to the matching funcs */
				return th_no_dlg_seq_handling(msg, &request_uri->u_val[i]);
			}
		}
	} else if (msg->route != NULL) {
		LM_DBG("Route header found, checking params\n");

		if (!msg->route->parsed && parse_rr(msg->route) != 0) {
			LM_ERR("failed to parse Route header\n");
			return -1;
		}

		auto_route = (rr_t *) msg->route->parsed;
		after_route_sibling = msg->route->sibling;

		if (parse_uri(auto_route->nameaddr.uri.s, auto_route->nameaddr.uri.len, &route_uri) < 0) {
			LM_ERR("Bad Route URI\n");
			return TOPOH_MATCH_FAILURE;
		}

		// TODO implement tag matching
		if (!check_self(&route_uri.host, route_uri.port_no ? route_uri.port_no : SIP_PORT, 0)) {
			LM_DBG("Route URI does match any known socket or alias\n");
			return TOPOH_MATCH_FAILURE;
		}

		if (!th_no_dlg_one_way_hiding(msg->rcv.bind_address)) {
			LM_ERR("Inbound socket is not a trusted internal socket\n");
			return TOPOH_MATCH_FAILURE;
		}

		LM_DBG("Auto Route header has '%d' params\n", route_uri.u_params_no);
		for (i = 0; i < route_uri.u_params_no; i++) {
			if (route_uri.u_name[i].len == th_contact_encode_param.len &&
				memcmp(th_contact_encode_param.s, route_uri.u_name[i].s, th_contact_encode_param.len) == 0) {
				LM_DBG("We found param in the first Route header with value of %.*s\n",
					route_uri.u_val[i].len, route_uri.u_val[i].s); // TODO validate value is non NULL or empty string

				max_size = th_ct_enc_scheme == ENC_BASE64 ?
					calc_max_word64_decode_len(route_uri.u_val[i].len) :
					calc_max_word32_decode_len(route_uri.u_val[i].len);
				
				if (max_size > MAX_THINFO_BUFFER_SIZE) {
					return -1;
				}

				if (th_ct_enc_scheme == ENC_BASE64)
					dec_len = word64decode(decoded_uri_buf.buf, (unsigned char *) route_uri.u_val[i].s, route_uri.u_val[i].len);
				else
					dec_len = word32decode(decoded_uri_buf.buf, (unsigned char *) route_uri.u_val[i].s, route_uri.u_val[i].len);

				if (dec_len <= 0) {
					LM_ERR("Failed to decode\n");
					return -1;
				}

				LM_DBG("Size of base64 decoded length %d and size of param len %d\n", dec_len, route_uri.u_val[i].len);

				for (i = 0; i < dec_len; i++)
					decoded_uri_buf.buf[i] ^= topo_hiding_ct_encode_pw.s[i % topo_hiding_ct_encode_pw.len];

				decoded_uri_buf.len = dec_len;
				decoded_uri_buf.pos = 0;
				if (decode_socket(&decoded_uri_buf, &proto, &ip, &port) <= 0) {
					LM_ERR("Failed to decode socket 0\n");
					return -1;
				}

				LM_DBG("Decoded socket host [%.*s] - Port - %d - Proto %d\n", ip.len, ip.s, port, proto);

				sock = grep_sock_info(&ip, port, proto);

				if (get_uri_count(&decoded_uri_buf) != 0) {
					LM_ERR("Encoded URI count is invalid, can only be 0 in auto Route\n");
					return -1;
				}

				flags = get_flags(&decoded_uri_buf);

				if (sock != NULL) { // TODO implement tag matching, need to decode the tag, first need to encode it
					msg->force_send_socket = sock;

					if (topo_delete_record_routes(msg) < 0) {
						LM_ERR("Failed to remove Record Route header \n");
						return -1;
					}

					if (topo_delete_vias(msg) < 0) {
						LM_ERR("Failed to remove via headers\n");
						return -1;
					}

					if (th_no_dlg_encode_contact(msg, flags, NULL, 0) < 0) {
						LM_ERR("Failed to encode contact header\n");
						return -1;
					}

					after_auto = auto_route->next;

					if (after_auto == NULL && after_route_sibling != NULL) {
						if (!after_route_sibling->parsed && parse_rr(after_route_sibling) != 0) {
							LM_ERR("failed to parse Route header\n");
							return -1;
						}

						LM_DBG("Parsed sibling Route header\n");

						after_auto = (rr_t *) after_route_sibling->parsed;

						if (!auto_route->deleted) {
							if (del_lump(msg, msg->route->name.s - msg->buf, msg->route->len, HDR_ROUTE_T) == NULL) {
								LM_ERR("del_lump failed \n");
								return -1;
							}
						}
					} else if (after_auto != NULL) {
						if (!auto_route->deleted) {
							if (!del_lump(msg, msg->route->body.s - msg->buf, after_auto->nameaddr.name.s - msg->route->body.s, 0)) {
								LM_ERR("failed to remove Route HF\n");
								return -1;
							}
						}
					}

					if (after_auto != NULL && set_dst_uri(msg, &after_auto->nameaddr.uri) !=0) {
						LM_ERR("Error set_dst_uri\n");
						return -1;
					}

					tm_api.set_tmcb_flags(flags);
					/* register tm callback for response in  */
					if (tm_api.register_tmcb(msg, 0, TMCB_RESPONSE_FWDED, th_no_dlg_onreply, NULL, NULL) < 0) {
						LM_ERR("failed to register TMCB\n");
						return -1;
					}

					return TOPOH_MATCH_SUCCESS;
				} else {
					LM_ERR("Socket does not match any local socket and tag matching disabled\n");
					return TOPOH_MATCH_FAILURE;
				}
			}
		}
	}

	LM_DBG("Topology hiding did not match\n");
	return TOPOH_MATCH_FAILURE;
}

int topo_hiding_init_no_dlg(int use_rr_api, int use_compression_api) {
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

		compression_enabled = 0;
	} else {
		if (load_compression_api(&compression_api) == -1) {
			LM_ERR("Error loading compression API\n");
			goto error;
		}

		compression_enabled = 1;
	}

	if (use_rr_api == 0) {
		rr_enabled = 0;
	} else {
		if (load_rr_api(&rr_api) == -1) {
			LM_ERR("Error loading rr API\n");
			goto error;
		}

		rr_enabled = 1;
	}

	return 1;
error:
	return -1;
}

int topo_hiding_destroy_no_dlg(void) {
	if (th_buffer.input.s)
		pkg_free(th_buffer.input.s);

	if (th_buffer.output.s)
		pkg_free(th_buffer.output.s);

	return 0;
}

#define RR_PREFIX "Record-Route: <sip:"
#define RR_PREFIX_LEN (sizeof(RR_PREFIX)-1)

#define RR_LR ";lr"
#define RR_LR_LEN (sizeof(RR_LR)-1)

#define RR_LR_FULL ";lr=on"
#define RR_LR_FULL_LEN (sizeof(RR_LR_FULL)-1)

#define RR_FROMTAG ";ftag="
#define RR_FROMTAG_LEN (sizeof(RR_FROMTAG)-1)

#define RR_R2 ";r2=on"
#define RR_R2_LEN (sizeof(RR_R2)-1)

#define RR_TERM ">"CRLF
#define RR_TERM_LEN (sizeof(RR_TERM)-1)

int add_custom_record_route(struct sip_msg* msg, int thinfo_len, char thinfo[static thinfo_len]) {
    struct lump *l, *l2;
    char *prefix, *suffix, *term;
    int prefix_len, suffix_len;
    struct hdr_field *hdr;
    char *anchor_pos;
    
    // Find the first Record-Route header if it exists
    if (parse_headers(msg, HDR_RECORDROUTE_F, 0) < 0) {
        LM_ERR("failed to parse headers\n");
        return -1;
    }
    
    // Determine anchor position
    if (msg->record_route) {
        // Insert before the first Record-Route header
        anchor_pos = msg->record_route->name.s;
    } else {
        // No Record-Route exists, insert at the beginning of headers
        anchor_pos = msg->headers->name.s;
    }
    
    // Anchor the lump at the determined position
    l = anchor_lump(msg, anchor_pos - msg->buf, HDR_RECORDROUTE_T);
    l2 = anchor_lump(msg, anchor_pos - msg->buf, HDR_RECORDROUTE_T);
    
    if (!l || !l2) {
        LM_ERR("failed to create anchor\n");
        return -1;
    }
    
    // Build prefix: "Record-Route: <sip:"
    prefix_len = RR_PREFIX_LEN;
    prefix = pkg_malloc(prefix_len);
    if (!prefix) {
        LM_ERR("no pkg memory\n");
        return -1;
    }
    memcpy(prefix, RR_PREFIX, RR_PREFIX_LEN);
    
    // Build suffix: ";lr>"CRLF
    suffix_len = RR_LR_LEN;
    suffix = pkg_malloc(suffix_len);
    term = pkg_malloc(RR_TERM_LEN);
    
    if (!suffix || !term) {
        LM_ERR("no pkg memory\n");
        pkg_free(prefix);
        if (suffix) pkg_free(suffix);
        if (term) pkg_free(term);
        return -1;
    }
    
    memcpy(suffix, RR_LR, RR_LR_LEN);
    memcpy(term, RR_TERM, RR_TERM_LEN);
    
    // Insert prefix
    if (!(l = insert_new_lump_after(l, prefix, prefix_len, 0))) {
        LM_ERR("failed to insert prefix\n");
        goto error;
    }
    
    // Insert substitution lump - this will be replaced with socket info
    // Use SUBST_RCV_ALL for received socket, SUBST_SND_ALL for sending socket
    l = insert_subst_lump_after(l, SUBST_SND_ALL, 0);
    if (!l) {
        LM_ERR("failed to insert subst lump\n");
        goto error;
    }
    
    // Insert thinfo buffer after socket info, before ;lr
    if (!(l = insert_new_lump_after(l, thinfo, thinfo_len, 0))) {
        LM_ERR("failed to insert thinfo param\n");
        goto error;
    }
    
    // Insert suffix
    l2 = insert_new_lump_before(l2, suffix, suffix_len, 0);
    if (!l2) {
        LM_ERR("failed to insert suffix\n");
        goto error;
    }
    
    // Insert terminator
    if (!(l2 = insert_new_lump_before(l2, term, RR_TERM_LEN, 0))) {
        LM_ERR("failed to insert term\n");
        goto error;
    }
    
    return 0;
    
error:
    // Memory cleanup handled by lump system
    return -1;
}


static int th_no_dlg_rebuild_record_routes(size_t route_sets_size, str *routes[static route_sets_size], struct lump* lmp) {
	char *route_hdrs[route_sets_size];
	int size, x, i, rc = 0;
	str *rr_set;

	memset(route_hdrs, 0, sizeof(route_hdrs));

	LM_DBG("Rebuilding %zu Record-Route sets\n", route_sets_size);
	for (i = 0; i < route_sets_size; i++) {
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
	for (x = i; x < route_sets_size; x++) {
		/* Assume the first lmp successfully added so we don't want to free the header */
		if (route_hdrs[x])
			pkg_free(route_hdrs[x]);
		pkg_free(routes[x]->s);
		routes[x]->s = NULL;
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
		goto cleanup;
	}

	if (parse_to_header(req) < 0 || req->to == NULL || get_to(req) == NULL) {
		LM_ERR("cannot parse TO header\n");
		goto cleanup;
	}

	/* do_rr determined by if the request has a tag, don't add them on sequential */
	do_rr = get_to(req)->tag_value.len == 0 || get_to(req)->tag_value.s == NULL;

	/* pass record route headers, get them from the reply if one_way_hiding */
	if (one_way_hiding && do_rr && rpl->record_route) {
		if (print_rr_body(rpl->record_route, &rpl_rr_set, 0, 1, NULL) != 0 ){
			LM_ERR("failed to print route records \n");
			goto cleanup;
		}

		route_sets[route_size++] = &rpl_rr_set;
		LM_DBG("Reply Record-Routes %.*s\n", rpl_rr_set.len, rpl_rr_set.s);
	}

	if (do_rr && req->record_route) {
		if (print_rr_body(req->record_route, &req_rr_set, 0, 1, &no_req_rrs) != 0) {
			LM_ERR("failed to print route records \n");
			goto cleanup;
		}

		route_sets[route_size++] = &req_rr_set;
		LM_DBG("Request Record-Routes %.*s\n", req_rr_set.len, req_rr_set.s);
	}

	if (!one_way_hiding) {
		if (topo_delete_vias(rpl) < 0) {
			LM_ERR("Failed to remove via headers\n");
			goto cleanup;
		}
	}

	if (!(lmp = restore_vias_from_req(req, rpl))) {
		LM_ERR("Failed to restore VIA headers from request \n");
		goto cleanup;
	}

    if (!one_way_hiding && !(rpl->REPLY_STATUS >= 300 && rpl->REPLY_STATUS < 400)) {
        if (th_no_dlg_encode_contact(rpl, flags, route_s, no_req_rrs) < 0) {
            LM_ERR("Failed to encode contact header \n");
            goto cleanup;
        }
    }

    if (topo_delete_record_routes(rpl) < 0) {
		LM_ERR("Failed to remove Record Route header \n");
		goto cleanup;
	}

    
	if (route_size > 0 && th_no_dlg_rebuild_record_routes(route_size, route_sets, lmp) != 0) {
		LM_ERR("failed to add route headers back in \n");
	}

cleanup: /* th_no_dlg_rebuild_record_routes sets the str pointer to NULL so these won't freed after */
    if (rpl_rr_set.s) pkg_free(rpl_rr_set.s);
    if (req_rr_set.s) pkg_free(req_rr_set.s);
}

static void th_no_dlg_onrequest(struct cell *t, int type, struct tmcb_params *param) {
	struct sip_msg *req = param->req;
	struct ua_client *uac = t->uac;
	unsigned int flags = param->flags;

	if (_th_no_dlg_onrequest(req, &uac->request.dst.to, uac->request.dst.proto, flags) < 0) {
		LM_ERR("Failed to do topology_hiding on request\n");
	}
}

static inline int _th_no_dlg_onrequest(struct sip_msg *req, union sockaddr_union *su, int proto, uint16_t flags) {
	struct socket_info *send_sock = NULL;
	char *suffix = NULL;
	int suffix_len = 0;
    int one_way_hiding = 0;
    int do_rr = 0;

	LM_DBG("Request callback with flags %u\n", flags);

	/* parse all headers to be sure that all RR and Contact hdrs are found */
	if (parse_headers(req, HDR_EOH_F, 0) >= 0) {
		send_sock = get_send_socket(req, su, proto);
        one_way_hiding = th_no_dlg_one_way_hiding(send_sock);
        do_rr = get_to(req)->tag_value.len == 0 || get_to(req)->tag_value.s == NULL;
		if (!one_way_hiding) {
			if (topo_delete_record_routes(req) < 0) {
				LM_ERR("Failed to remove Record Route header \n");
				return -1;
			}

			if (topo_delete_vias(req) < 0) {
				LM_ERR("Failed to remove via headers\n");
				return -1;
            }

            if (th_no_dlg_encode_contact(req, flags, NULL, 0) < 0) {
                LM_ERR("Failed to encode contact header\n");
                return -1;
            }
		} else if (do_rr) {
			if (!(suffix = build_encoded_contact_suffix(req, NULL, 0, &suffix_len, flags, 1))) {
				LM_ERR("Failed to add build Record-Route suffix\n");
                return -1;
			}

            if (add_custom_record_route(req, suffix_len, suffix)) {
                LM_ERR("Failed to add Record-Route header\n");
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

static char* build_encoded_contact_suffix(struct sip_msg* msg, str *routes, unsigned int rrs_to_ignore, int *suffix_len, uint16_t flags, int socket_only) {
	uint16_t enc_len = 0;
	char *suffix_enc, *s;
    rr_t *next = NULL, *head = NULL;
	str contact = STR_NULL;
	int i, params_len = 0;
	struct sip_uri ctu = { 0 }, rr_uri = { 0 }, rr_uri_r2 = { 0 };
	struct th_ct_params* el;
	param_t *it;
    uint16_t encoded_uris = 0;
    str rr_set = STR_NULL;
    int is_req = (msg->first_line.type == SIP_REQUEST) ? 1 : 0;

	/* parse all headers as we can have multiple
	   RR headers in the same message */
	if (parse_headers(msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("failed to parse all headers\n");
		return NULL;
	}

    reset_encode_buffer(&encoded_uri_buf);

    if (socket_only == 1) {
		goto socket_only;
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

        // TODO encode only parameters not allowed through
        if (encode_uri(&encoded_uri_buf, &ctu) == -1) {
            LM_ERR("Error encoding Contact URI\n");
            goto error;
        }

		encoded_uris++;
	}

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

    if (routes && routes->len > 0) {
        LM_DBG("Parsing Route string [%.*s]\n", routes->len, routes->s);
        rr_set = *routes;
    } else if (msg->record_route) {
		if (print_rr_body(msg->record_route, &rr_set, !is_req, 0, &rrs_to_ignore) != 0){
			LM_ERR("failed to print route records \n");
            goto error;
		}
	}

    if (rr_set.len > 0) {
        if (parse_rr_body(rr_set.s, rr_set.len, &head) != 0) {
            LM_ERR("failed parsing route set\n");
            goto error;
        }

        next = head;
    }

    while (next != NULL) {
        if (parse_uri(next->nameaddr.uri.s, next->nameaddr.uri.len, &rr_uri) < 0) {
            LM_ERR("Failed to parse SIP uri\n");
            goto error;
        }

		struct socket_info *rr_sock = grep_sock_info(&rr_uri.host, rr_uri.port_no ? rr_uri.port_no : SIP_PORT, rr_uri.proto);

        if (!th_no_dlg_one_way_hiding(rr_sock)) {
			if (!is_2rr(&rr_uri.params)) {
				if (encode_uri(&encoded_uri_buf, &rr_uri) == -1) {
					LM_ERR("Error encoding Route URI\n");
					goto error;
				}

				encoded_uris++;
			} else {
				next = next->next;
				if (next != NULL && parse_uri(next->nameaddr.uri.s, next->nameaddr.uri.len, &rr_uri_r2) < 0) {
					LM_ERR("Failed to parse SIP uri\n");
					goto error;
				}

				// TODO refactor to be permissive here and allow the second one to have no r2 and also check hosts
				if (!is_2rr(&rr_uri_r2.params)) {
					LM_ERR("Second SIP uri is not r2=on when the first one is\n");
					goto error;
				}

				if (encode_dual_uri(&encoded_uri_buf, &rr_uri, &rr_uri_r2) == -1) {
					LM_ERR("Error encoding Route URI\n");
					goto error;
				}

				encoded_uris += 2;

				memset(&rr_uri_r2, 0, sizeof(rr_uri_r2));
			}
        }

        memset(&rr_uri, 0, sizeof(rr_uri));
        next = next->next;
    }

    LM_DBG("Encoding %u URIs\n", encoded_uris);

socket_only: // TODO need to verify buffers potentially
    if (encode_socket(&encoded_uri_buf, msg->rcv.bind_address) < 0) {
        LM_ERR("Error encoding socket\n");
        goto error;
    }

    if (head != NULL)
        pkg_free(head);

    enc_len = th_ct_enc_scheme == ENC_BASE64 ?
		calc_word64_encode_len(encoded_uri_buf.len) : calc_word32_encode_len(encoded_uri_buf.len);
    
    finalize_encode_buffer(&encoded_uri_buf, flags, encoded_uris);

	for (i = 0; i < encoded_uri_buf.len; i++)
    	encoded_uri_buf.buf[i] ^= topo_hiding_ct_encode_pw.s[i % topo_hiding_ct_encode_pw.len];

    suffix_enc = pkg_malloc(1 + th_contact_encode_param.len + 1 + enc_len + params_len + 1);
    if (!suffix_enc) {
        LM_ERR("no more pkg\n");
        goto error;
    }

    s = suffix_enc;
    *s++ = ';';
    memcpy(s, th_contact_encode_param.s, th_contact_encode_param.len);
    s += th_contact_encode_param.len;
    *s++ = '=';

    if (th_ct_enc_scheme == ENC_BASE64)
        word64encode((unsigned char*)s, encoded_uri_buf.buf, encoded_uri_buf.len);
    else
        word32encode((unsigned char*)s, encoded_uri_buf.buf, encoded_uri_buf.len);

    s += enc_len;

	if (!socket_only)
		*s++ = '>';

	if (socket_only != 1 && th_hdr_param_list) {
		for (el = th_hdr_param_list; el; el = el->next) {
			for (it = ((contact_body_t *)msg->contact->parsed)->contacts->params; it; it = it->next) {
				if (str_match(&el->param_name, &it->name))
					s = topo_ct_param_copy(s, &it->name, &it->body, 1);
			}
		}
	}

	*suffix_len = s - suffix_enc;

    LM_DBG("Encoded suffix [%.*s]\n", *suffix_len, (char*) s);
	return suffix_enc;
error:
    if (head != NULL)
        pkg_free(head);
	if (suffix_enc)
		pkg_free(suffix_enc);
	return NULL;
}

static int th_no_dlg_encode_contact(struct sip_msg *msg, uint16_t flags, str *routes, unsigned int rrs_to_ignore) {
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
		if (parse_contact(msg->contact) < 0 || HAS_NO_CONTACT_BODY(msg)) {
			LM_ERR("bad Contact HDR\n");
		} else {
			contact = ((contact_body_t *)msg->contact->parsed)->contacts->uri;
			if (parse_uri(contact.s, contact.len, &ctu) < 0) {
				LM_ERR("Bad Contact URI\n");
			} else {
				ct_username = ctu.user.s;
				ct_username_len = ctu.user.len;
				LM_DBG("Trying to propagate username [%.*s]\n", ct_username_len,
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
		memcpy(prefix + 5, ct_username, ct_username_len);
		prefix[prefix_len - 1] = '@';
	}

	if (!(lump = insert_new_lump_after(lump, prefix, prefix_len,0))) {
		LM_ERR("failed inserting '<sip:'\n");
		goto error;
	}

	/* make sure we do not free this string in case of a further error */
	prefix = NULL;

	if (!(suffix = build_encoded_contact_suffix(msg, routes, rrs_to_ignore, &suffix_len, flags, 0))) {
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

static inline int topo_no_dlg_classify_route(rr_t *head) {
	struct sip_uri rr_uri;
	int flags = 0;

	if (parse_uri(head->nameaddr.uri.s, head->nameaddr.uri.len, &rr_uri) < 0) {
		LM_ERR("Failed to parse SIP uri\n");
		return -1;
	}

	if (!is_strict(&rr_uri.params)) {
		flags |= ROUTE_LOOSE;
	} else {
		flags |= ROUTE_STRICT;
	}

	// TODO refactor this
	if (check_self(&rr_uri.host, rr_uri.port_no ? rr_uri.port_no : SIP_PORT, 0) == 1) {
		flags |= ROUTE_SELF;
	}

	if (is_2rr(&rr_uri.params)) {
		flags |= ROUTE_DOUBLE_RR;
	}

	return flags;
}


static inline int topo_no_dlg_route(struct sip_msg *msg, str rr_buf[static 1], struct lump lmp[static 1]) {
	rr_t *head = NULL, *rrp = NULL;
	char *route = NULL, *hdrs = NULL;
	int size = 0, start_index = 0;
	int route_flags;

	if (parse_rr_body(rr_buf->s, rr_buf->len, &head) != 0) {
		LM_ERR("failed parsing route set\n");
		route_flags = ROUTE_FAILURE;
		return -1;
	}

	rrp = head;
	route_flags = topo_no_dlg_classify_route(rrp);

	if (route_flags & (ROUTE_STRICT | ROUTE_SELF)) {
		LM_DBG("First Route header is a strict router\n");

		if (route_flags & ROUTE_STRICT && set_ruri(msg, &rrp->nameaddr.uri) != 0) {
			LM_ERR("failed setting new dst uri\n");
			route_flags = ROUTE_FAILURE;
			goto cleanup;
		}

		start_index = rrp->nameaddr.uri.len + 3; /* 3 = <>,*/	
		rrp = head->next;
	}

	if (rrp != NULL && start_index < rr_buf->len) {
		hdrs = rr_buf->s + start_index;

		size = rr_buf->len - start_index + ROUTE_LEN + CRLF_LEN;
		route = pkg_malloc(size);
		if (route == 0) {
			LM_ERR("no more pkg memory\n");
			route_flags = ROUTE_FAILURE;
		}

		memcpy(route, ROUTE_STR, ROUTE_LEN);
		memcpy(route + ROUTE_LEN, hdrs, rr_buf->len - start_index);
		memcpy(route + ROUTE_LEN + rr_buf->len - start_index, CRLF, CRLF_LEN);

		LM_DBG("Adding Route header: [%.*s] \n", size, route);

		if (insert_new_lump_after(lmp, route, size, HDR_ROUTE_T) == 0) {
			LM_ERR("failed inserting new route set\n");
			pkg_free(route);
			route_flags = ROUTE_FAILURE;
			goto cleanup;
		}

		msg->msg_flags |= FL_HAS_ROUTE_LUMP;
		rr_buf->len = rr_buf->len - start_index;
		rr_buf->s = memcpy(rr_buf->s, hdrs, rr_buf->len);

		LM_DBG("setting dst_uri to <%.*s> \n", rrp->nameaddr.uri.len, rrp->nameaddr.uri.s);

		if (route_flags & ROUTE_LOOSE && set_dst_uri(msg, &rrp->nameaddr.uri) !=0 ) {
			route_flags = ROUTE_FAILURE;
			LM_ERR("Error set_dst_uri\n");
		}
	}

cleanup:
	if (head != NULL)
		free_rr(&head);

	return route_flags;
}

static inline int topo_no_dlg_rewrite_contact_as_next_route(struct sip_msg *msg, const str contact_buf[static 1], struct lump lmp[static 1]) {
	char *remote_contact = NULL;
	int size = 0;

	size = contact_buf->len + ROUTE_PREF_LEN + ROUTE_SUFF_LEN;
	remote_contact = pkg_malloc(size);
	if (remote_contact == NULL) {
		LM_ERR("no more pkg \n");
		return -1;
	}

	memcpy(remote_contact, ROUTE_PREF,ROUTE_PREF_LEN);
	memcpy(remote_contact + ROUTE_PREF_LEN, contact_buf->s, contact_buf->len);
	memcpy(remote_contact + ROUTE_PREF_LEN + contact_buf->len,
			ROUTE_SUFF, ROUTE_SUFF_LEN);

	LM_DBG("Adding remote contact route header : [%.*s]\n",
			size, remote_contact);

	if (insert_new_lump_after(lmp, remote_contact, size, HDR_ROUTE_T) == 0) {
		LM_ERR("failed inserting remote contact route\n");
		pkg_free(remote_contact);
		return -1;
	}

	msg->msg_flags |= FL_HAS_ROUTE_LUMP;
	return 1;
}

int decode_info_buffer(str *info, str rr_buf[static 1], str ct_buf[static 1], struct socket_info **sock, uint16_t *flags) {
	int max_size, dec_len, decoded_len, i;
	uint8_t uri_count;
	str sip_uris[MAX_ENCODED_SIP_URIS];
	int proto = 0;
	str host = STR_NULL;
	unsigned short port = 0;

	max_size = th_ct_enc_scheme == ENC_BASE64 ?
		calc_max_word64_decode_len(info->len) :
		calc_max_word32_decode_len(info->len);
	
	LM_DBG("Size of decoded length %d\n", max_size);
	if (max_size > MAX_THINFO_BUFFER_SIZE) {
		return -1;
	}

	if (th_ct_enc_scheme == ENC_BASE64)
		dec_len = word64decode(decoded_uri_buf.buf, (unsigned char *)info->s, info->len);
	else
		dec_len = word32decode(decoded_uri_buf.buf, (unsigned char *)info->s, info->len);

	if (dec_len <= 0) {
		LM_ERR("Failed to decode\n");
		return -1;
	}

	for (i = 0; i < dec_len; i++)
        decoded_uri_buf.buf[i] ^= topo_hiding_ct_encode_pw.s[i % topo_hiding_ct_encode_pw.len];

    decoded_uri_buf.len = dec_len;
    decoded_uri_buf.pos = 0;

    uri_count = get_uri_count(&decoded_uri_buf);
    if (uri_count == 0 || uri_count > MAX_ENCODED_SIP_URIS) {
        LM_ERR("Encoded URI count is invalid, count=%u\n", uri_count);
        return -1;
    }

	LM_DBG("Decoded URI count %u\n", uri_count);

    *flags = get_flags(&decoded_uri_buf);
    decoded_len = decode_uris(&decoded_uri_buf, decoded_uri_str, uri_count, sip_uris);

	if (decoded_len < 0) {
        LM_ERR("Decoded len less than 0\n");
        return -1;
    }

    if (decode_socket(&decoded_uri_buf, &proto, &host, &port) <= 0) {
		LM_ERR("Failed to decode socket 0\n");
        return -1;
	}

    if (host.len > 0 && host.s != NULL) {
        *sock = grep_sock_info(&host, port, proto);
        if (!*sock) {
            LM_WARN("non-local socket <%.*s:%d>...ignoring\n", host.len, host.s, port);
        }
    }

    ct_buf->s = sip_uris[0].s;
    ct_buf->len = sip_uris[0].len;
    
    if (uri_count > 1) {
        rr_buf->s = sip_uris[1].s;
        rr_buf->len = decoded_len - ct_buf->len;
    }

	ct_buf->s = ct_buf->s + 1; // remove < but lets do this better in the future
	ct_buf->len = ct_buf->len - 3; // Removing <>,

	LM_DBG("extracted routes [%.*s], ct [%.*s], flags [%u] and bind socket address [%.*s:%d] and proto %d\n",
		rr_buf->len, rr_buf->s, ct_buf->len, ct_buf->s, *flags, host.len, host.s, port, proto);

	return 1;
}

int decode_info_buffer_legacy(str *info, str rr_buf[static 1], str ct_buf[static 1], struct socket_info **sock, uint16_t *flags) {
    str flags_buf = STR_NULL, bind_buf = STR_NULL, host = STR_NULL;
    int max_size, port, proto;
    char *dec_buf = NULL, *p;
    int i, dec_len, size;
    unsigned int parsed_flags;
    int ret = 1;
    
    max_size = th_ct_enc_scheme == ENC_BASE64 ?
        calc_max_word64_decode_len(info->len) :
        calc_max_word32_decode_len(info->len);
    dec_buf = pkg_malloc(max_size);
    if (dec_buf == NULL) {
        LM_ERR("No more pkg\n");
        return -1;
    }

    if (th_ct_enc_scheme == ENC_BASE64)
        dec_len = word64decode((unsigned char *)dec_buf,
            (unsigned char *)info->s, info->len);
    else
        dec_len = word32decode((unsigned char *)dec_buf,
            (unsigned char *)info->s, info->len);

    for (i = 0; i < dec_len; i++)
        dec_buf[i] ^= topo_hiding_ct_encode_pw.s[i % topo_hiding_ct_encode_pw.len];

    #define __extract_len_and_buf(_p, _len, _s) \
        do { \
            (_s).len = *(short *)p;\
            if ((_s).len < 0 || (_s).len > _len) {\
                LM_ERR("bad length %d in encoded contact\n", (_s).len);\
                ret = -1;\
                goto cleanup;\
            }\
            (_s).s = _p + sizeof(short);\
            _p += sizeof(short) + (_s).len;\
            _len -= sizeof(short) + (_s).len;\
        } while(0)

    p = dec_buf;
    size = dec_len;
    __extract_len_and_buf(p, size, *rr_buf);
    __extract_len_and_buf(p, size, *ct_buf);
    __extract_len_and_buf(p, size, flags_buf);
    __extract_len_and_buf(p, size, bind_buf);

	LM_DBG("extracted routes [%.*s] , ct [%.*s] , flags [%.*s] and bind [%.*s]\n",
		rr_buf->len, rr_buf->s, ct_buf->len, ct_buf->s, flags_buf.len, flags_buf.s, bind_buf.len, bind_buf.s);

    if (str2int(&flags_buf, &parsed_flags) < 0) {
        LM_WARN("Failed to convert string to integer, default to no flags\n");
        parsed_flags = 0;
    }

    *flags = (uint8_t)(parsed_flags & 0xFF);  // Explicit cast and mask

    if (bind_buf.len && bind_buf.s) {
        LM_DBG("forcing send socket for req to [%.*s]\n", bind_buf.len, bind_buf.s);

        if (parse_phostport(bind_buf.s, bind_buf.len, &host.s, &host.len, &port, &proto) != 0) {
            LM_ERR("bad socket <%.*s>\n", bind_buf.len, bind_buf.s);
        } else {
            *sock = grep_sock_info(&host, (unsigned short) port, proto);
            if (!*sock) {
                LM_WARN("non-local socket <%.*s>...ignoring\n", bind_buf.len, bind_buf.s);
            }
        }
    }

cleanup:
    if (dec_buf)
        pkg_free(dec_buf);
    return ret;
}


static int th_no_dlg_seq_handling(struct sip_msg *msg, str *info) {
	char *route = NULL, *msg_buf = NULL;
	str rr_buf = STR_NULL, ct_buf = STR_NULL;
	struct hdr_field *it;
	struct lump* lmp = NULL;
	struct socket_info *sock = NULL;
	str *route_s = NULL;
	uint16_t flags;
	int route_flags = ROUTE_SUCCESS;
    int one_way_hiding = 0;

	/* parse all headers to be sure that all RR and Contact hdrs are found */
	if (parse_headers(msg, HDR_EOH_F, 0) < 0) {
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

	if (msg->dst_uri.s && msg->dst_uri.len) {
		/* reset dst_uri if previously set
		 * either by loose route or manually */
		pkg_free(msg->dst_uri.s);
		msg->dst_uri.s = NULL;
		msg->dst_uri.len = 0;
	}

	if (msg->route) {
		for (it = msg->route; it; it = it->sibling) {
			if (it->parsed && ((rr_t*)it->parsed)->deleted)
				continue;
			if ((lmp = del_lump(msg, it->name.s - msg_buf, it->len, HDR_ROUTE_T)) == 0) {
				LM_ERR("del_lump failed \n");
				goto err_fail_early;
			}
		}
	}

	// TODO have some switch here
	// if (decode_info_buffer_legacy(info, &rr_buf, &ct_buf, &sock, &flags) < 1) {
	// 	LM_ERR("Failed to decode buffer\n");
	// 	return -1;
	// }

	if (decode_info_buffer(info, &rr_buf, &ct_buf, &sock, &flags) < 1) {
		LM_ERR("Failed to decode buffer\n");
		return -1;
	}

	lmp = anchor_lump(msg, msg->headers->name.s - msg_buf, 0);
	if (lmp == NULL) {
		LM_ERR("failed anchoring new lump\n");
		goto err_fail_early;
	}

	if (rr_buf.len) {
		route_flags = topo_no_dlg_route(msg, &rr_buf, lmp);
		if (route_flags & ROUTE_FAILURE) {
			LM_ERR("Failure to Route\n");
			goto err_fail_early;
		}
	}

	if (!(route_flags & ROUTE_FAILURE) && !(route_flags & ROUTE_STRICT) && ct_buf.len && ct_buf.s) {
		LM_DBG("Setting new URI to  <%.*s> \n", ct_buf.len, ct_buf.s);

		if (set_ruri(msg, &ct_buf) != 0) {
			LM_ERR("failed setting ruri\n");
			goto err_fail_early;
		}
	} else if (!(route_flags & ROUTE_FAILURE) && (route_flags & ROUTE_STRICT) && ct_buf.len && ct_buf.s) {
		if (topo_no_dlg_rewrite_contact_as_next_route(msg, &ct_buf, lmp) != 1) {
			LM_ERR("Failure to rewrite Contact header as next Route\n");
			goto err_fail_early;
		}
	}

	if (rr_buf.s && rr_buf.len) {
		route_s = shm_malloc(sizeof *route_s + rr_buf.len);
		if (route_s) {
			route_s->s = (char *)(route_s + 1);
			memcpy(route_s->s, rr_buf.s, rr_buf.len);
			route_s->len = rr_buf.len;
		}
	}

	tm_api.set_tmcb_flags(flags);
	/* register tm callback for response in  */
	if (tm_api.register_tmcb(msg, 0, TMCB_RESPONSE_FWDED, th_no_dlg_onreply, route_s, topo_no_dlg_seq_free) < 0) {
		LM_ERR("failed to register TMCB\n");
		goto err_free_route;
	}

	route_s = NULL;

	if (!sock) {
		sock = msg->force_send_socket;
	}

    one_way_hiding = th_no_dlg_one_way_hiding(sock);

	if (!one_way_hiding) {
		if (topo_delete_vias(msg) < 0) {
			LM_ERR("Failed to remove via headers\n");
			return TOPOH_MATCH_FAILURE;
		}

        if (th_no_dlg_encode_contact(msg, flags, NULL, NULL) < 0) {
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