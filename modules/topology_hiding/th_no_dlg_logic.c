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
static void th_no_dlg_onreply(struct cell *t, int type, struct tmcb_params *param);
static int th_no_dlg_seq_handling(struct sip_msg *msg, str *info);
static int th_no_dlg_seq_handling2(struct sip_msg *msg, str *info);
static inline int th_no_dlg_one_way_hiding(struct socket_info *socket);
static inline int th_no_dlg_check_self_socket_tag(struct socket_info *socket);
static inline int topo_no_dlg_classify_route(rr_t head[static 1]);

static char* build_encoded_contact_suffix2(struct sip_msg* msg, str *routes, unsigned int rrs_to_ignore, int *suffix_len, uint16_t flags, int socket_only);

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

#define SCHEME_MASK    0x0007
#define SCHEME_SIP     0x0000
#define SCHEME_SIPS    0x0001
#define SCHEME_TEL     0x0002
#define SCHEME_TELS    0x0003
#define SCHEME_URN_S   0x0004
#define SCHEME_URN_N   0x0005

#define TRANSPORT_MASK 0x0038
#define TRANSPORT_UDP  0x0000
#define TRANSPORT_TCP  0x0008
#define TRANSPORT_TLS  0x0010
#define TRANSPORT_SCTP 0x0018
#define TRANSPORT_WS   0x0020
#define TRANSPORT_WSS  0x0028

#define DOMAIN_MASK    0x00C0
#define DOMAIN_IPV4    0x0000
#define DOMAIN_IPV6    0x0040
#define DOMAIN_FQDN    0x0080

#define HAS_USERNAME   0x0100
#define HAS_PASSWORD   0x0200
#define HAS_PORT       0x0400
#define HAS_PARAMS     0x0800  // Now means "has OTHER params" (not lr/r2)
#define HAS_HEADERS    0x1000
#define HAS_TRANSPORT  0x2000
#define HAS_LR         0x4000  // NEW: lr or lr=on present
#define HAS_R2         0x8000  // NEW: r2 or r2=on present

// typedef struct {
//     uint8_t len;
//     unsigned char s[UINT8_MAX];
// } uri_property;

#define MAX_ENCODED_URI_SIZE ( \
    sizeof(uint16_t) +             /* uri properties */ \
    sizeof(uint8_t)  + UINT8_MAX + /* username */ \
    sizeof(uint8_t)  + UINT8_MAX + /* password */ \
    sizeof(uint8_t)  + UINT8_MAX + /* domain */ \
    sizeof(uint16_t) +             /* port */ \
    sizeof(uint8_t)  + UINT8_MAX + /* params */ \
    sizeof(uint8_t)  + UINT8_MAX   /* headers */ \
)

#define MAX_THINFO_BUFFER_SIZE 4096

typedef struct {
    uint16_t len;
    unsigned char buf[MAX_THINFO_BUFFER_SIZE];
    int pos;
} encoded_uri_t;

// typedef struct {
//     uint16_t props;
//     uri_property username;
//     uri_property password;
//     union {
//         unsigned char ipv4[4];
//         unsigned char ipv6[16];
//         uri_property fqdn;
//     } domain;
//     uint16_t port;
//     uri_property params;
//     uri_property headers;
//     encoded_uri_buffer_t encoded;
// } encoded_sip_uri_t;

uint8_t SCHEMES[] = {
    [ERROR_URI_T]            = 0,
    [SIP_URI_T]              = SCHEME_SIP,
    [SIPS_URI_T]             = SCHEME_SIPS,
    [TEL_URI_T]              = SCHEME_TEL,
    [TELS_URI_T]             = SCHEME_TELS,
    [URN_SERVICE_URI_T]      = SCHEME_URN_N,
    [URN_NENA_SERVICE_URI_T] = SCHEME_URN_S
};

enum _uri_type SCHEME_TO_ENUM[] = {
    [SCHEME_SIP]   = SIP_URI_T,
    [SCHEME_SIPS]  = SIPS_URI_T,
    [SCHEME_TEL]   = TEL_URI_T,
    [SCHEME_TELS]  = TELS_URI_T,
    [SCHEME_URN_N] = URN_SERVICE_URI_T,
    [SCHEME_URN_S] = URN_NENA_SERVICE_URI_T
};

static const str SCHEME_STRINGS[] = {
    [SCHEME_SIP]   = str_init("sip"),
    [SCHEME_SIPS]  = str_init("sips"),
    [SCHEME_TEL]   = str_init("tel"),
    [SCHEME_TELS]  = str_init("tels"),
    [SCHEME_URN_N] = str_init("urn:service"),
    [SCHEME_URN_S] = str_init("urn:nena:service")
};

uint8_t TRANSPORTS[] = {
    [PROTO_NONE]    = 0,
    [PROTO_UDP]     = TRANSPORT_UDP,
    [PROTO_TCP]     = TRANSPORT_TCP,
    [PROTO_TLS]     = TRANSPORT_TLS,
    [PROTO_SCTP]    = TRANSPORT_SCTP,
    [PROTO_WS]      = TRANSPORT_WS,
    [PROTO_WSS]     = TRANSPORT_WSS
};

enum sip_protos TRANSPORT_TO_ENUM[] = {
    [TRANSPORT_UDP]  = PROTO_UDP,
    [TRANSPORT_TCP]  = PROTO_TCP,
    [TRANSPORT_TLS]  = PROTO_TLS,
    [TRANSPORT_SCTP] = PROTO_SCTP,
    [TRANSPORT_WS]   = PROTO_WS,
    [TRANSPORT_WSS]  = PROTO_WSS
};

static const char *TRANSPORT_STRINGS[] = {
    [TRANSPORT_UDP]  = "transport=udp",
    [TRANSPORT_TCP]  = "transport=tcp",
    [TRANSPORT_TLS]  = "transport=tls",
    [TRANSPORT_SCTP] = "transport=sctp",
    [TRANSPORT_WS]   = "transport=ws",
    [TRANSPORT_WSS]  = "transport=wss"
};

static encoded_uri_t encoded_uri_buf = { 0 };
static encoded_uri_t decoded_uri_buf = { 0 };

// Dual URI encoding - simplified approach
// Use HAS_R2 bit (0x8000) to indicate dual URI encoding
// Single URIs: r2 param is kept as a string in params (NOT extracted to flag)
// Dual URIs: r2 flag is encoded in URI2 properties byte
#define IS_DUAL_URI         0x8000  // Same as HAS_R2, but only dual URIs set this

// URI2 properties byte (1 byte following URI1 data)
#define URI2_SCHEME_MASK    0x07    // Bits 0-2: scheme for URI2
#define URI2_TRANSPORT_MASK 0x38    // Bits 3-5: transport for URI2
#define URI2_TRANSPORT_SHIFT 3
#define URI2_HAS_PORT       0x40    // Bit 6: URI2 has port
#define URI2_HAS_R2         0x80    // Bit 7: r2 flag for both URIs in dual encoding

int encode_dual_uri(struct sip_uri *uri1, struct sip_uri *uri2) {
    unsigned char *p, *props_ptr, *param_len_ptr, *uri2_props_ptr;
    uint16_t props;
    uint8_t uri2_props;
    char tmp[256];
    uint8_t param_len;
    char *src, *end;
    int remaining, param_len_current;
    size_t start_pos;
    int has_lr = 0, has_r2 = 0;
    
    // Caller should validate: same host, same params (except transport), same username, etc.
    // This function assumes those are validated and encodes them once
    
    if (encoded_uri_buf.len + MAX_ENCODED_URI_SIZE * 2 > MAX_THINFO_BUFFER_SIZE) {
        return -1;
    }
    
    if (encoded_uri_buf.len == 0) {
        p = encoded_uri_buf.buf + 3;
        encoded_uri_buf.len = 3;
        encoded_uri_buf.pos = 0;
    } else {
        p = encoded_uri_buf.buf + encoded_uri_buf.len;
    }
    
    start_pos = p - encoded_uri_buf.buf;
    
    // Initialize URI1 properties with IS_DUAL_URI flag
    props = IS_DUAL_URI;
    props_ptr = p;
    p += 2;
    
    // Set URI1 scheme and transport
    props |= SCHEMES[uri1->type];
    if (uri1->proto >= PROTO_UDP && uri1->proto <= PROTO_WSS) {
        props = (props & ~TRANSPORT_MASK) | TRANSPORTS[uri1->proto];
    } else {
        props = (props & ~TRANSPORT_MASK) | TRANSPORTS[PROTO_UDP];
    }
    
    // Encode username if present (shared between both URIs)
    if (uri1->user.len > 0 && uri1->user.len <= UINT8_MAX) {
        props |= HAS_USERNAME;
        *p++ = (uint8_t)uri1->user.len;
        memcpy(p, uri1->user.s, uri1->user.len);
        p += uri1->user.len;
    }
    
    // Encode password if present (shared between both URIs)
    if (uri1->passwd.len > 0 && uri1->passwd.len <= UINT8_MAX) {
        props |= HAS_PASSWORD;
        *p++ = (uint8_t)uri1->passwd.len;
        memcpy(p, uri1->passwd.s, uri1->passwd.len);
        p += uri1->passwd.len;
    }
    
    // Encode host (shared between both URIs)
    if (uri1->host.len > 0 && uri1->host.len < sizeof(tmp)) {
        memcpy(tmp, uri1->host.s, uri1->host.len);
        tmp[uri1->host.len] = '\0';
        
        if (inet_pton(AF_INET, tmp, p) == 1) {
            props = (props & ~DOMAIN_MASK) | DOMAIN_IPV4;
            p += 4;
        } else if (inet_pton(AF_INET6, tmp, p) == 1) {
            props = (props & ~DOMAIN_MASK) | DOMAIN_IPV6;
            p += 16;
        } else if (uri1->host.len <= UINT8_MAX) {
            props = (props & ~DOMAIN_MASK) | DOMAIN_FQDN;
            *p++ = (uint8_t)uri1->host.len;
            memcpy(p, uri1->host.s, uri1->host.len);
            p += uri1->host.len;
        } else {
            return -1;
        }
    } else {
        return -1;
    }
    
    // Encode URI1 port
    if (uri1->port_no > 0) {
        props |= HAS_PORT;
        *p++ = (uri1->port_no >> 8) & 0xFF;
        *p++ = uri1->port_no & 0xFF;
    }
    
    // Now encode URI2 properties byte
    uri2_props = 0;
    uri2_props_ptr = p;
    p += 1;
    
    // Set URI2 scheme and transport
    uri2_props |= SCHEMES[uri2->type] & URI2_SCHEME_MASK;
    if (uri2->proto >= PROTO_UDP && uri2->proto <= PROTO_WSS) {
        uri2_props |= (TRANSPORTS[uri2->proto] >> 3) & URI2_TRANSPORT_MASK;
    }
    
    // Encode URI2 port if present
    if (uri2->port_no > 0) {
        uri2_props |= URI2_HAS_PORT;
        *p++ = (uri2->port_no >> 8) & 0xFF;
        *p++ = uri2->port_no & 0xFF;
    }
    
    // Parse params from uri1 and extract lr/r2, keep others (shared between both URIs)
    if (uri1->params.len > 0 && uri1->params.len <= UINT8_MAX) {
        param_len_ptr = p++;
        param_len = 0;
        src = uri1->params.s;
        remaining = uri1->params.len;
        
        // Skip leading semicolon if present
        if (remaining > 0 && *src == ';') {
            src++;
            remaining--;
        }
        
        while (remaining > 0) {
            // Skip leading semicolon for each param
            if (*src == ';') {
                src++;
                remaining--;
                if (remaining == 0) break;
            }
            
            // Find end of this param
            end = memchr(src, ';', remaining);
            param_len_current = end ? (end - src) : remaining;
            
            // Check for transport=
            if (param_len_current >= 10 && strncmp(src, "transport=", 10) == 0) {
                src += param_len_current;
                remaining -= param_len_current;
                continue;
            }
            
            // Check for lr or lr=on
            if ((param_len_current == 2 && strncmp(src, "lr", 2) == 0) ||
                (param_len_current == 5 && strncmp(src, "lr=on", 5) == 0)) {
                has_lr = 1;
                src += param_len_current;
                remaining -= param_len_current;
                continue;
            }
            
            // Check for r2 or r2=on
            if ((param_len_current == 2 && strncmp(src, "r2", 2) == 0) ||
                (param_len_current == 5 && strncmp(src, "r2=on", 5) == 0)) {
                has_r2 = 1;
                src += param_len_current;
                remaining -= param_len_current;
                continue;
            }
            
            // Copy other params
            if (param_len > 0) {
                *p++ = ';';
                param_len++;
            }
            memcpy(p, src, param_len_current);
            p += param_len_current;
            param_len += param_len_current;
            
            src += param_len_current;
            remaining -= param_len_current;
        }
        
        if (param_len > 0) {
            *param_len_ptr = param_len;
            props |= HAS_PARAMS;
        } else {
            p = param_len_ptr;
        }
    }
    
    // Encode headers if present (shared between both URIs)
    if (uri1->headers.len > 0 && uri1->headers.len <= UINT8_MAX) {
        props |= HAS_HEADERS;
        *p++ = (uint8_t)uri1->headers.len;
        memcpy(p, uri1->headers.s, uri1->headers.len);
        p += uri1->headers.len;
    }
    
    // Set lr flag in props (shared between both URIs)
    if (has_lr) props |= HAS_LR;
    
    // Set r2 flag in URI2 properties byte (shared between both URIs)
    if (has_r2) uri2_props |= URI2_HAS_R2;
    
    // Write URI1 props
    props_ptr[0] = (props >> 8) & 0xFF;
    props_ptr[1] = props & 0xFF;
    
    // Write URI2 properties byte
    *uri2_props_ptr = uri2_props;
    
    encoded_uri_buf.len = p - encoded_uri_buf.buf;
    return p - (encoded_uri_buf.buf + start_pos);
}


int encode_uri(struct sip_uri *uri) {
    unsigned char *p, *props_ptr, *param_len_ptr;
    uint16_t props;
    char tmp[256];
    uint8_t param_len;
    char *src, *param_start;
    int remaining, skip;
    char *end;
    size_t start_pos;
    int has_lr = 0;
    
    if (encoded_uri_buf.len + MAX_ENCODED_URI_SIZE > MAX_THINFO_BUFFER_SIZE) {
        return -1;
    }
    
    if (encoded_uri_buf.len == 0) {
        p = encoded_uri_buf.buf + 3;
        encoded_uri_buf.len = 3;
        encoded_uri_buf.pos = 0;
    } else {
        p = encoded_uri_buf.buf + encoded_uri_buf.len;
    }
    
    start_pos = p - encoded_uri_buf.buf;
    props = 0;
    props_ptr = p;
    p += 2;
    
    props = (props & ~SCHEME_MASK) | SCHEMES[uri->type];
    
    if (uri->user.len > 0 && uri->user.len <= UINT8_MAX) {
        props |= HAS_USERNAME;
        *p++ = (uint8_t)uri->user.len;
        memcpy(p, uri->user.s, uri->user.len);
        p += uri->user.len;
    }
    
    if (uri->passwd.len > 0 && uri->passwd.len <= UINT8_MAX) {
        props |= HAS_PASSWORD;
        *p++ = (uint8_t)uri->passwd.len;
        memcpy(p, uri->passwd.s, uri->passwd.len);
        p += uri->passwd.len;
    }
    
    if (uri->host.len > 0 && uri->host.len < sizeof(tmp)) {
        memcpy(tmp, uri->host.s, uri->host.len);
        tmp[uri->host.len] = '\0';
        
        if (inet_pton(AF_INET, tmp, p) == 1) {
            props = (props & ~DOMAIN_MASK) | DOMAIN_IPV4;
            p += 4;
        } else if (inet_pton(AF_INET6, tmp, p) == 1) {
            props = (props & ~DOMAIN_MASK) | DOMAIN_IPV6;
            p += 16;
        } else if (uri->host.len <= UINT8_MAX) {
            props = (props & ~DOMAIN_MASK) | DOMAIN_FQDN;
            *p++ = (uint8_t)uri->host.len;
            memcpy(p, uri->host.s, uri->host.len);
            p += uri->host.len;
        } else {
            return -1;
        }
    } else {
        return -1;
    }
    
    if (uri->port_no > 0) {
        props |= HAS_PORT;
        *p++ = (uri->port_no >> 8) & 0xFF;
        *p++ = uri->port_no & 0xFF;
    }
    
    if (uri->proto >= PROTO_UDP && uri->proto <= PROTO_WSS) {
        props = (props & ~TRANSPORT_MASK) | TRANSPORTS[uri->proto];
    } else {
        props = (props & ~TRANSPORT_MASK) | TRANSPORTS[PROTO_UDP];
    }
    
    if (uri->transport_val.len > 0) {
        props |= HAS_TRANSPORT;
    }
    
    // Parse params and extract lr, keep others (including r2)
    if (uri->params.len > 0 && uri->params.len <= UINT8_MAX) {
		param_len_ptr = p++;
		param_len = 0;
		src = uri->params.s;
		remaining = uri->params.len;
		
		// Skip leading semicolon if present
		if (remaining > 0 && *src == ';') {
			src++;
			remaining--;
		}
		
		while (remaining > 0) {
			// Skip leading semicolon for each param
			if (*src == ';') {
				src++;
				remaining--;
				if (remaining == 0) break;
			}
			
			// Find end of this param (next ; or end of string)
			end = memchr(src, ';', remaining);
			int param_len_current = end ? (end - src) : remaining;
			
			// Check for transport=
			if (param_len_current >= 10 && strncmp(src, "transport=", 10) == 0) {
				src += param_len_current;
				remaining -= param_len_current;
				continue;
			}
			
			// Check for lr or lr=on (extract to flag)
			if ((param_len_current == 2 && strncmp(src, "lr", 2) == 0) ||
				(param_len_current == 5 && strncmp(src, "lr=on", 5) == 0)) {
				has_lr = 1;
				src += param_len_current;
				remaining -= param_len_current;
				continue;
			}
			
			// NOTE: r2 is NOT extracted - it stays in params as a string
			// This allows us to use HAS_R2 bit for IS_DUAL_URI flag
			
			// Copy other params (add semicolon separator if not first)
			if (param_len > 0) {
				*p++ = ';';
				param_len++;
			}
			memcpy(p, src, param_len_current);
			p += param_len_current;
			param_len += param_len_current;
			
			src += param_len_current;
			remaining -= param_len_current;
		}
		
		if (param_len > 0) {
			*param_len_ptr = param_len;
			props |= HAS_PARAMS;
		} else {
			p = param_len_ptr;  // Rewind if no params left
		}
	}

    if (uri->headers.len > 0 && uri->headers.len <= UINT8_MAX) {
        props |= HAS_HEADERS;
        *p++ = (uint8_t)uri->headers.len;
        memcpy(p, uri->headers.s, uri->headers.len);
        p += uri->headers.len;
    }
    
    // Set lr and r2 flags
    if (has_lr) props |= HAS_LR;

	LM_ERR("ENCODE URI: props=0x%04x, has_lr=%d, buffer_pos=%ld, bytes_written=%ld\n",
    	props, has_lr, (long)(props_ptr - encoded_uri_buf.buf), (long)(p - props_ptr));
    
    props_ptr[0] = (props >> 8) & 0xFF;
    props_ptr[1] = props & 0xFF;
    
    encoded_uri_buf.len = p - encoded_uri_buf.buf;
    return p - (encoded_uri_buf.buf + start_pos);
}


// Socket encoding/decoding functions

#define SOCKET_PROTO_MASK  0x07  // 3 bits for protocol
#define SOCKET_IP_MASK     0x18  // 2 bits for IP type (shifted left 3)
#define SOCKET_IPV4        0x00
#define SOCKET_IPV6        0x08

int encode_socket(struct socket_info *si) {
    unsigned char *p;
    uint8_t flags = 0;
    
    if (encoded_uri_buf.len + MAX_ENCODED_URI_SIZE > MAX_THINFO_BUFFER_SIZE) {
        return -1; // TODO change this to different code to ensure we don't try to use a full buffer
    }
    
    if (encoded_uri_buf.len == 0) {
        p = encoded_uri_buf.buf + 3;
        encoded_uri_buf.len = 3;
        encoded_uri_buf.pos = 0;
    } else {
        p = encoded_uri_buf.buf + encoded_uri_buf.len;
    }
    
    if (si->proto >= PROTO_UDP && si->proto <= PROTO_WSS) {
        flags |= (TRANSPORTS[si->proto] >> 3) & SOCKET_PROTO_MASK;  // Shift transport bits to lower 3 bits
    } else {
        return -1;
    }
    
    unsigned char *flags_ptr = p++;
    
    // Write port
    *p++ = (si->port_no >> 8) & 0xFF;
    *p++ = si->port_no & 0xFF;
    
    if (si->address.af == AF_INET) {
        flags |= SOCKET_IPV4;
        memcpy(p, si->address.u.addr, 4);
        p += 4;
        *flags_ptr = flags;
        encoded_uri_buf.len = p - encoded_uri_buf.buf;
        return 7;  // Total bytes
    } else if (si->address.af == AF_INET6) {
        flags |= SOCKET_IPV6;
        memcpy(p, si->address.u.addr, 16);
        p += 16;
        *flags_ptr = flags;
        encoded_uri_buf.len = p - encoded_uri_buf.buf;
        return 19;  // Total bytes
    }
    
    return -1;
}

int decode_socket(encoded_uri_t *encoded_uri, int *proto, str *ip, unsigned short *port) {
    static char ip_str[INET6_ADDRSTRLEN];
    unsigned char *p;
    uint8_t flags, proto_bits, ip_type;
    int remaining;
    
    if (!encoded_uri || encoded_uri->pos >= encoded_uri->len) return -1;
    
    remaining = encoded_uri->len - encoded_uri->pos;
    if (remaining < 7) return -1;  // Minimum size for IPv4
    
    p = encoded_uri->buf + encoded_uri->pos;
    
    flags = *p++;
    *port = (p[0] << 8) | p[1];
    p += 2;
    
    // Extract protocol
    proto_bits = (flags & SOCKET_PROTO_MASK) << 3;  // Shift back to TRANSPORT position
    switch (proto_bits) {
        case TRANSPORT_UDP:  *proto = PROTO_UDP; break;
        case TRANSPORT_TCP:  *proto = PROTO_TCP; break;
        case TRANSPORT_TLS:  *proto = PROTO_TLS; break;
        case TRANSPORT_SCTP: *proto = PROTO_SCTP; break;
        case TRANSPORT_WS:   *proto = PROTO_WS; break;
        case TRANSPORT_WSS:  *proto = PROTO_WSS; break;
        default: return -1;
    }

    ip_type = flags & SOCKET_IP_MASK;
    if (ip_type == SOCKET_IPV4) {
        if (remaining < 7) return -1;
        inet_ntop(AF_INET, p, ip_str, INET_ADDRSTRLEN);
        ip->s = ip_str;
        ip->len = strlen(ip_str);
        encoded_uri->pos += 7;
        return 1;
    } else if (ip_type == SOCKET_IPV6) {
        if (remaining < 19) return -1;
        inet_ntop(AF_INET6, p, ip_str, INET6_ADDRSTRLEN);
        ip->s = ip_str;
        ip->len = strlen(ip_str);
        encoded_uri->pos += 19;
        return 2;
    }
    
    return -1;
}


void reset_encode_buffer(void) {
    encoded_uri_buf.len = 0;
}

void finalize_encode_buffer(uint16_t flags, uint8_t count) {
    encoded_uri_buf.buf[0] = (flags >> 8) & 0xFF;
    encoded_uri_buf.buf[1] = flags & 0xFF;
    encoded_uri_buf.buf[2] = count;
}

uint8_t get_uri_count(encoded_uri_t *encoded_uri) {
    return encoded_uri->buf[2];
}

uint16_t get_flags(encoded_uri_t *encoded_uri) {
    return (encoded_uri->buf[0] << 8) | encoded_uri->buf[1];
}

static char decoded_uri_str[MAX_ENCODED_URI_SIZE * 3];

int decode_uris(encoded_uri_t *encoded_uri, uint16_t uri_count, str uris[static uri_count]) {
    unsigned char *p;
    uint16_t props;
    uint8_t domain_type, len, scheme, scheme2, transport_bits;
    char *s, *uri_start;
    int t_len;
    int uri_idx;
    char host_buf[256];
    int host_len;
    uint16_t port1, port2;
    char params_buf[256];
    int params_len;
    
    if (!encoded_uri || encoded_uri->len < 3 || uri_count == 0) return -1;
    
    if (encoded_uri->pos == 0) {
        encoded_uri->pos = 3;
    }
    
    p = encoded_uri->buf + encoded_uri->pos;
    s = decoded_uri_str;
    
    uri_idx = 0;
    while (uri_idx < uri_count) {
        if ((p - encoded_uri->buf) >= encoded_uri->len) return -1;
        
        props = (p[0] << 8) | p[1];
        p += 2;

        LM_ERR("DECODE URI[%d]: props=0x%04x, HAS_LR=%d, HAS_R2=%d, IS_DUAL=%d, buffer_pos=%ld\n",
            uri_idx, props, !!(props & HAS_LR), !!(props & HAS_R2), !!(props & IS_DUAL_URI), (long)(p - encoded_uri->buf));
        
        if (props & IS_DUAL_URI) {
            // DUAL URI DECODING - New simplified format
            // Format: [2 bytes URI1 props][shared data][2 bytes port1][1 byte URI2 props][optional 2 bytes port2]
            
            uint8_t uri2_props;
            uint16_t port1 = 0, port2 = 0;
            uint8_t scheme1, scheme2, transport1, transport2;
            
            // Extract URI1 scheme and transport from props
            scheme1 = props & SCHEME_MASK;
            transport1 = props & TRANSPORT_MASK;  // Don't shift - TRANSPORT_STRINGS is indexed by the mask value
            
            // Decode shared username if present
            char username_buf[256];
            int username_len = 0;
            if (props & HAS_USERNAME) {
                username_len = *p++;
                memcpy(username_buf, p, username_len);
                p += username_len;
            }
            
            // Decode shared password if present
            char password_buf[256];
            int password_len = 0;
            if (props & HAS_PASSWORD) {
                password_len = *p++;
                memcpy(password_buf, p, password_len);
                p += password_len;
            }
            
            // Decode shared host
            domain_type = (props & DOMAIN_MASK);
            if (domain_type == DOMAIN_IPV4) {
                char tmp[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, p, tmp, sizeof(tmp));
                host_len = strlen(tmp);
                memcpy(host_buf, tmp, host_len);
                p += 4;
            } else if (domain_type == DOMAIN_IPV6) {
                char tmp[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, p, tmp, sizeof(tmp));
                host_len = strlen(tmp);
                memcpy(host_buf, tmp, host_len);
                p += 16;
            } else {
                len = *p++;
                host_len = len;
                memcpy(host_buf, p, len);
                p += len;
            }
            
            // Decode URI1 port
            if (props & HAS_PORT) {
                port1 = (p[0] << 8) | p[1];
                p += 2;
            }
            
            // Read URI2 properties byte
            uri2_props = *p++;
            scheme2 = uri2_props & URI2_SCHEME_MASK;
            transport2 = uri2_props & URI2_TRANSPORT_MASK;  // Extract transport bits (already in correct position)
            int has_r2 = (uri2_props & URI2_HAS_R2) ? 1 : 0;
            
            // Decode URI2 port if present
            if (uri2_props & URI2_HAS_PORT) {
                port2 = (p[0] << 8) | p[1];
                p += 2;
            }
            
            // Decode shared params
            params_len = 0;
            if (props & HAS_PARAMS) {
                params_len = *p++;
                memcpy(params_buf, p, params_len);
                p += params_len;
            }
            
            // Decode shared headers
            char headers_buf[256];
            int headers_len = 0;
            if (props & HAS_HEADERS) {
                headers_len = *p++;
                memcpy(headers_buf, p, headers_len);
                p += headers_len;
            }
            
            // Build FIRST URI string
            *s++ = '<';
            uri_start = s;
            memcpy(s, SCHEME_STRINGS[scheme1].s, SCHEME_STRINGS[scheme1].len);
            s += SCHEME_STRINGS[scheme1].len;
            *s++ = ':';
            
            // Add username/password if present
            if (username_len > 0) {
                memcpy(s, username_buf, username_len);
                s += username_len;
                if (password_len > 0) {
                    *s++ = ':';
                    memcpy(s, password_buf, password_len);
                    s += password_len;
                }
                *s++ = '@';
            }
            
            // Add host
            if (domain_type == DOMAIN_IPV6) *s++ = '[';
            memcpy(s, host_buf, host_len);
            s += host_len;
            if (domain_type == DOMAIN_IPV6) *s++ = ']';
            
            // Add port
            if (port1 > 0) {
                s += sprintf(s, ":%u", port1);
            }
            
            // Add transport for URI1
            if (transport1 < sizeof(TRANSPORT_STRINGS)/sizeof(TRANSPORT_STRINGS[0]) && 
                TRANSPORT_STRINGS[transport1] != NULL) {
                *s++ = ';';
                t_len = strlen(TRANSPORT_STRINGS[transport1]);
                memcpy(s, TRANSPORT_STRINGS[transport1], t_len);
                s += t_len;
            }
            
            // Add lr flag
            if (props & HAS_LR) {
                memcpy(s, ";lr", 3);
                s += 3;
            }
            
            // Add r2 flag (from URI2 props, not from HAS_R2)
            if (has_r2) {
                memcpy(s, ";r2=on", 6);
                s += 6;
            }
            
            // Add other params
            if (params_len > 0) {
                *s++ = ';';
                memcpy(s, params_buf, params_len);
                s += params_len;
            }
            
            // Add headers
            if (headers_len > 0) {
                *s++ = '?';
                memcpy(s, headers_buf, headers_len);
                s += headers_len;
            }
            
            *s++ = '>';
            
            if (uri_idx < uri_count - 1) {
                *s++ = ',';
            }
            
            uris[uri_idx].s = uri_start - 1;
            uris[uri_idx].len = s - uris[uri_idx].s;
            
            LM_ERR("DEBUG decode_uris[%d]: s=%p, len=%d, content=[%.*s]\n",
                uri_idx, uris[uri_idx].s, uris[uri_idx].len, 
                uris[uri_idx].len, uris[uri_idx].s);
            
            // Build SECOND URI string
            uri_idx++;
            if (uri_idx < uri_count) {
                *s++ = '<';
                uri_start = s;
                memcpy(s, SCHEME_STRINGS[scheme2].s, SCHEME_STRINGS[scheme2].len);
                s += SCHEME_STRINGS[scheme2].len;
                *s++ = ':';
                
                // Add username/password if present (shared)
                if (username_len > 0) {
                    memcpy(s, username_buf, username_len);
                    s += username_len;
                    if (password_len > 0) {
                        *s++ = ':';
                        memcpy(s, password_buf, password_len);
                        s += password_len;
                    }
                    *s++ = '@';
                }
                
                // Add host (shared)
                if (domain_type == DOMAIN_IPV6) *s++ = '[';
                memcpy(s, host_buf, host_len);
                s += host_len;
                if (domain_type == DOMAIN_IPV6) *s++ = ']';
                
                // Add port
                if (port2 > 0) {
                    s += sprintf(s, ":%u", port2);
                }
                
                // Add transport for URI2
                if (transport2 < sizeof(TRANSPORT_STRINGS)/sizeof(TRANSPORT_STRINGS[0]) && 
                    TRANSPORT_STRINGS[transport2] != NULL) {
                    *s++ = ';';
                    t_len = strlen(TRANSPORT_STRINGS[transport2]);
                    memcpy(s, TRANSPORT_STRINGS[transport2], t_len);
                    s += t_len;
                }
                
                // Add lr flag (shared)
                if (props & HAS_LR) {
                    memcpy(s, ";lr", 3);
                    s += 3;
                }
                
                // Add r2 flag (from URI2 props, not from HAS_R2)
                if (has_r2) {
                    memcpy(s, ";r2=on", 6);
                    s += 6;
                }
                
                // Add other params (shared)
                if (params_len > 0) {
                    *s++ = ';';
                    memcpy(s, params_buf, params_len);
                    s += params_len;
                }
                
                // Add headers (shared)
                if (headers_len > 0) {
                    *s++ = '?';
                    memcpy(s, headers_buf, headers_len);
                    s += headers_len;
                }
                
                *s++ = '>';
                
                if (uri_idx < uri_count - 1) {
                    *s++ = ',';
                }
                
                uris[uri_idx].s = uri_start - 1;
                uris[uri_idx].len = s - uris[uri_idx].s;
                
                LM_ERR("DEBUG decode_uris[%d]: s=%p, len=%d, content=[%.*s]\n",
                    uri_idx, uris[uri_idx].s, uris[uri_idx].len, 
                    uris[uri_idx].len, uris[uri_idx].s);
            }
            
            // Dual URI: we decoded 2 URIs, so increment uri_idx by 2
            uri_idx += 2;
            
        } else {
            // SINGLE URI DECODING (existing logic)
            *s++ = '<';
            uri_start = s;
            
            scheme = props & SCHEME_MASK;
            memcpy(s, SCHEME_STRINGS[scheme].s, SCHEME_STRINGS[scheme].len);
            s += SCHEME_STRINGS[scheme].len;
            *s++ = ':';
            
            if (props & HAS_USERNAME) {
                len = *p++;
                memcpy(s, p, len);
                s += len;
                p += len;
                
                if (props & HAS_PASSWORD) {
                    *s++ = ':';
                    len = *p++;
                    memcpy(s, p, len);
                    s += len;
                    p += len;
                }
                
                *s++ = '@';
            } else if (props & HAS_PASSWORD) {
                len = *p++;
                p += len;
            }
            
            domain_type = (props & DOMAIN_MASK);
            
            if (domain_type == DOMAIN_IPV4) {
                char tmp[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, p, tmp, sizeof(tmp));
                int ip_len = strlen(tmp);
                memcpy(s, tmp, ip_len);
                s += ip_len;
                p += 4;
            } else if (domain_type == DOMAIN_IPV6) {
                char tmp[INET6_ADDRSTRLEN];
                *s++ = '[';
                inet_ntop(AF_INET6, p, tmp, sizeof(tmp));
                int ip_len = strlen(tmp);
                memcpy(s, tmp, ip_len);
                s += ip_len;
                *s++ = ']';
                p += 16;
            } else {
                len = *p++;
                memcpy(s, p, len);
                s += len;
                p += len;
            }
            
            if (props & HAS_PORT) {
                uint16_t port = (p[0] << 8) | p[1];
                s += sprintf(s, ":%u", port);
                p += 2;
            }
            
            if (props & HAS_TRANSPORT) {
                transport_bits = (props & TRANSPORT_MASK);
                if (transport_bits >= sizeof(TRANSPORT_STRINGS)/sizeof(TRANSPORT_STRINGS[0]) || 
                    TRANSPORT_STRINGS[transport_bits] == NULL) {
                    return -1;
                }
                
                *s++ = ';';
                t_len = strlen(TRANSPORT_STRINGS[transport_bits]);
                memcpy(s, TRANSPORT_STRINGS[transport_bits], t_len);
                s += t_len;
            }
            
            if (props & HAS_LR) {
                memcpy(s, ";lr", 3);
                s += 3;
            }
            
            // Note: r2 is NOT decoded from HAS_R2 flag for single URIs
            // It stays in the params string
            
            if (props & HAS_PARAMS) {
                *s++ = ';';
                len = *p++;
                memcpy(s, p, len);
                s += len;
                p += len;
            }
            
            if (props & HAS_HEADERS) {
                *s++ = '?';
                len = *p++;
                memcpy(s, p, len);
                s += len;
                p += len;
            }
            
            *s++ = '>';
            
            if (uri_idx < uri_count - 1) {
                *s++ = ',';
            }
            
            uris[uri_idx].s = uri_start - 1;
            uris[uri_idx].len = s - uris[uri_idx].s;
            
            LM_ERR("DEBUG decode_uris[%d]: s=%p, len=%d, content=[%.*s]\n",
                uri_idx, uris[uri_idx].s, uris[uri_idx].len, 
                uris[uri_idx].len, uris[uri_idx].s);
            
            // Single URI: increment uri_idx by 1
            uri_idx++;
        }
    }
    
    encoded_uri->pos = p - encoded_uri->buf;
    
    return s - decoded_uri_str;
}

int topo_hiding_match_no_dlg(struct sip_msg *msg) {
	struct sip_uri *r_uri;
	rr_t *route1 = NULL, *route2 = NULL;
	str *route_set = NULL;
	int route_set_len = 0;
	int i = 0;
	unsigned int route_classification;

	if (parse_sip_msg_uri(msg) < 0) {
		LM_ERR("Failed to parse request URI\n");
		return -1;
	}

	if (parse_headers(msg, HDR_ROUTE_F, 0) == -1) {
		LM_ERR("failed to parse route headers\n");
	}

	r_uri = &msg->parsed_uri;

	if ((th_no_dlg_check_self_socket_tag(msg->rcv.bind_address) ||
		 check_self(&r_uri->host, r_uri->port_no ? r_uri->port_no : SIP_PORT, 0)) && msg->route == NULL) {
		/* topology_hiding_match with thinfo and request domain is us
		 * needs to have a thinfo to continue otherwise we cannot match */
		for (i = 0; i < r_uri->u_params_no; i++) {
			if (r_uri->u_name[i].len == th_contact_encode_param.len &&
				memcmp(th_contact_encode_param.s, r_uri->u_name[i].s, th_contact_encode_param.len) == 0) {
				LM_DBG("We found param in R-URI with value of %.*s\n",
					r_uri->u_val[i].len, r_uri->u_val[i].s);
				/* pass the param value to the matching funcs */
				return th_no_dlg_seq_handling(msg, &r_uri->u_val[i]);
			}
		}
	} else if (rr_enabled && msg->route != NULL) {
		if (th_no_dlg_one_way_hiding(msg->rcv.bind_address)) {
			route_set = rr_api.get_route_set(msg, &route_set_len);

			if (parse_rr_body(route_set->s, route_set->len, &route1) != 0) {
				LM_ERR("failed parsing route set\n");
				goto cleanup;
			}

			route_classification = topo_no_dlg_classify_route(route1);

			if (route_classification & ROUTE_LOOSE) {
				LM_DBG("First Route header is a loose router\n");

				if ((route_classification & ROUTE_DOUBLE_RR) && (route_classification & ROUTE_SELF)) {
					route2 = route1->next;

					if (route2 == NULL && route_set_len > 1) {
						LM_DBG("Second Route header NULL trying second string\n");
						route_set++;
						if (parse_rr_body(route_set->s, route_set->len, &route2) != 0) {
							LM_ERR("failed parsing route set\n");
							goto cleanup;
						}
					} else {
						goto cleanup;
					}

					route_classification = topo_no_dlg_classify_route(route2);

					if (!(route_classification & ROUTE_LOOSE) || !(route_classification & ROUTE_DOUBLE_RR) || !(route_classification & ROUTE_SELF)) {
						LM_ERR("r2=on and second route not loose or r2\n");
						goto cleanup;	
					}
				}
			} else {
				goto cleanup;
			}

			return TOPOH_MATCH_ONE_WAY_HIDING;

cleanup: // TODO cleanup route1/2
			return TOPOH_MATCH_FAILURE;
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

int add_custom_record_route(struct sip_msg* msg) {
    struct lump *l, *l2;
    char *prefix, *suffix, *term;
    int prefix_len, suffix_len;
    
    // Anchor the lump at the beginning of headers
    l = anchor_lump(msg, msg->headers->name.s - msg->buf, HDR_RECORDROUTE_T);
    l2 = anchor_lump(msg, msg->headers->name.s - msg->buf, HDR_RECORDROUTE_T);
    
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
			// if (!(suffix = build_encoded_contact_suffix2(req, NULL, 0, 0, flags, 1))) {
			// 	LM_ERR("Failed to add build Record-Route suffix\n");
            //     return -1;
			// }

            if (add_custom_record_route(req)) {
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

static char* build_encoded_contact_suffix2(struct sip_msg* msg, str *routes, unsigned int rrs_to_ignore, int *suffix_len, uint16_t flags, int socket_only) {
	uint16_t enc_len = 0;
	char *suffix_enc, *s;
    rr_t *next = NULL, *head = NULL;
	str contact = STR_NULL;
	int i, params_len = 0;
	struct sip_uri ctu = { 0 }, rr_uri = { 0 }, rr_uri_r2 = { 0 };
	struct th_ct_params* el;
	param_t *it;
    uint16_t encoded_uris = 1; // Assume at least Contact
    str rr_set = STR_NULL;
    int is_req = (msg->first_line.type == SIP_REQUEST) ? 1 : 0;

	/* parse all headers as we can have multiple
	   RR headers in the same message */
	if (parse_headers(msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("failed to parse all headers\n");
		return NULL;
	}

    reset_encode_buffer();

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
        if (encode_uri(&ctu) == -1) {
            LM_ERR("Error encoding Contact URI\n");
            goto error;
        }
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
				if (encode_uri(&rr_uri) == -1) {
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

				if (!is_2rr(&rr_uri_r2.params)) {
					LM_ERR("Second SIP uri is not r2=on when the first one is\n");
					goto error;
				}

				if (encode_dual_uri(&rr_uri, &rr_uri_r2) == -1) {
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
    if (encode_socket(msg->rcv.bind_address) < 0) {
        LM_ERR("Error encoding socket\n");
        // TODO error handling
    }

    if (head != NULL)
        pkg_free(head);

    enc_len = th_ct_enc_scheme == ENC_BASE64 ?
		calc_word64_encode_len(encoded_uri_buf.len) : calc_word32_encode_len(encoded_uri_buf.len);
    
    finalize_encode_buffer(flags, encoded_uris);

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

/* We encode the RR headers, the actual Contact and the socket str for this leg */
/* Via headers will be restored using the TM module, no need to save anything for them */
static char* build_encoded_contact_suffix(struct sip_msg* msg, str *routes, unsigned int rrs_to_ignore, int *suffix_len, int flags) {
	short rr_len, ct_len, addr_len, flags_len, enc_len;
	char *suffix_enc = NULL, *suffix_enc2 = NULL, *p, *s;
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

    reset_encode_buffer();

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

        if (encode_uri(&ctu) == -1) {
            LM_ERR("Error encoding Contact URI\n");
            goto error;
        }
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

	LM_DBG("Size of encoded length %d\n", local_len);
	if (local_len > th_buffer.input.len && th_no_dlg_realloc_input_buffer(&th_buffer, local_len) != 0) {
		goto error;
	}

	encoding_buffer = th_buffer.input.s;

	p = encoding_buffer;
	memcpy(p, &rr_len, sizeof(short));
	p += sizeof(short);
	if (rr_len) {
		memcpy(p, rr_set.s, rr_set.len);
		p+= rr_set.len;

        struct sip_uri rr_uri;
        rr_t *head = NULL, *next;

        if (parse_rr_body(rr_set.s, rr_set.len, &head) != 0) {
            LM_ERR("failed parsing route set\n");
            goto cleanup_head;
        }

        if (parse_uri(head->nameaddr.uri.s, head->nameaddr.uri.len, &rr_uri) < 0) {
            LM_ERR("Failed to parse first SIP uri\n");
            goto cleanup_head;
        }

        if (encode_uri(&rr_uri) == -1) {
            LM_ERR("Error encoding first Route URI\n");
            goto cleanup_head;
        }

        next = head->next;
        while (next != NULL) {
            memset(&rr_uri, 0, sizeof(rr_uri));

            if (parse_uri(next->nameaddr.uri.s, next->nameaddr.uri.len, &rr_uri) < 0) {
                LM_ERR("Failed to parse SIP uri\n");
                goto cleanup_head;
            }

            if (encode_uri(&rr_uri) == -1) {
                LM_ERR("Error encoding Route URI\n");
                goto cleanup_head;
            }

            next = next->next;
        }
cleanup_head:
        if (head != NULL)
            free_rr(&head);
	}

    uint16_t _sec_encode_len = th_ct_enc_scheme == ENC_BASE64 ?
		calc_word64_encode_len(encoded_uri_buf.len) : calc_word32_encode_len(encoded_uri_buf.len);
    
    memcpy(encoded_uri_buf.buf + 2, &flags, sizeof(uint16_t));
    // finalize_encode_buffer(encoded_uri_buf.len);

    suffix_enc2 = pkg_malloc(_sec_encode_len + 1);
	if (!suffix_enc2) {
		LM_ERR("no more pkg\n");
		goto error;
	}

    if (th_ct_enc_scheme == ENC_BASE64)
		word64encode((unsigned char*)suffix_enc2, encoded_uri_buf.buf, encoded_uri_buf.len);
    else
		word32encode((unsigned char*)suffix_enc2, encoded_uri_buf.buf, encoded_uri_buf.len);

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
    LM_ERR("Old: %.*s - len %d\n", *suffix_len, (char*) suffix_enc, *suffix_len);
    LM_ERR("New: %.*s - len %d\n", _sec_encode_len + 1, (char*) suffix_enc2, _sec_encode_len + 1);
	return suffix_enc;
error:
	if (rr_set.s && !routes)
		pkg_free(rr_set.s);
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

	if (!(suffix = build_encoded_contact_suffix2(msg, routes, rrs_to_ignore, &suffix_len, flags, 0))) {
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

static int th_no_dlg_encode_record_route(struct sip_msg *msg, unsigned int flags, str *routes, unsigned int rrs_to_ignore) {
	struct lump* lump;
	char *prefix = NULL,*suffix = NULL,*ct_username = NULL;
	int prefix_len, suffix_len = 0, ct_username_len = 0;
	struct sip_uri ctu;
	str contact;

	// if (!msg->contact) {
	// 	if(parse_headers(msg, HDR_CONTACT_F, 0)< 0) {
	// 		LM_ERR("Failed to parse headers\n");
	// 		return -1;
	// 	}
	// 	if (!msg->contact)
	// 		return 0;
	// }

	// if (!(lump = delete_existing_contact(msg, 0))) {
	// 	LM_ERR("Failed to delete existing contact \n");
	// 	goto error;
	// }

	// LM_DBG("Flags '%d' passed for encoding Contact\n", flags);

	// prefix_len = 5; /* <sip: */
	// if (flags & TOPOH_KEEP_USER) {
	// 	if (parse_contact(msg->contact) < 0 || HAS_NO_CONTACT_BODY(msg)) {
	// 		LM_ERR("bad Contact HDR\n");
	// 	} else {
	// 		contact = ((contact_body_t *)msg->contact->parsed)->contacts->uri;
	// 		if (parse_uri(contact.s, contact.len, &ctu) < 0) {
	// 			LM_ERR("Bad Contact URI\n");
	// 		} else {
	// 			ct_username = ctu.user.s;
	// 			ct_username_len = ctu.user.len;
	// 			LM_DBG("Trying to propagate username [%.*s]\n", ct_username_len,
	// 								ct_username);
	// 			if (ct_username_len > 0)
	// 				prefix_len += 1 + /* @ */ + ct_username_len;
	// 		}
	// 	}
	// }

	// prefix = pkg_malloc(prefix_len);
	// if (!prefix) {
	// 	LM_ERR("no more pkg\n");
	// 	goto error;
	// }

	// memcpy(prefix,"<sip:",5);
	// if (flags & TOPOH_KEEP_USER && ct_username_len > 0) {
	// 	memcpy(prefix + 5, ct_username, ct_username_len);
	// 	prefix[prefix_len - 1] = '@';
	// }

	// if (!(lump = insert_new_lump_after(lump, prefix, prefix_len,0))) {
	// 	LM_ERR("failed inserting '<sip:'\n");
	// 	goto error;
	// }

	// /* make sure we do not free this string in case of a further error */
	// prefix = NULL;

	if (!(suffix = build_encoded_contact_suffix2(msg, routes, rrs_to_ignore, &suffix_len, flags, 1))) {
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
    decoded_len = decode_uris(&decoded_uri_buf, uri_count, sip_uris);

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
	str rr_buf, ct_buf;
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

static int th_no_dlg_seq_handling2(struct sip_msg *msg, str *info) {
	int max_size;
	char *route = NULL, *msg_buf = NULL;
	str rr_buf = STR_NULL, ct_buf;
	struct hdr_field *it;
	struct lump* lmp = NULL;
	struct socket_info *sock = NULL;
	str *route_s = NULL;
	unsigned long dec_len = 0;
	uint16_t flags;
    int one_way_hiding = 0;
	int route_flags = ROUTE_SUCCESS;
	int decoded_len;
	str sip_uris[MAX_ENCODED_SIP_URIS];
	uint8_t uri_count = 0;
	unsigned short port = 0;
    str host = STR_NULL;
    int proto = 0;

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

	

	lmp = anchor_lump(msg, msg->headers->name.s - msg_buf, 0);
	if (lmp == NULL) {
		LM_ERR("failed anchoring new lump\n");
		goto err_fail_early;
	}

	route_flags = topo_no_dlg_route(msg, &rr_buf, lmp);
	if (route_flags & ROUTE_FAILURE) {
		LM_ERR("Failure to Route\n");
		goto err_fail_early;
	}

    ct_buf.s = ct_buf.s + 1; // remove < but lets do this better in the future
    ct_buf.len = ct_buf.len - 3; // Removing <>,

	if (!(route_flags & ROUTE_FAILURE) && !(route_flags & ROUTE_STRICT)) {
		LM_DBG("Setting new URI to %.*s \n", ct_buf.len, ct_buf.s);

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

	if (host.len > 0 && host.s != NULL) {
        sock = grep_sock_info(&host, port, proto);
        if (!sock) {
            LM_WARN("non-local socket <%.*s>...ignoring\n", host.len, host.s);
        }
        msg->force_send_socket = sock;
    } else {
        sock = msg->force_send_socket;
    }

    one_way_hiding = th_no_dlg_one_way_hiding(sock);

	if (!one_way_hiding) {
		if (topo_delete_vias(msg) < 0) {
			LM_ERR("Failed to remove via headers\n");
		}

        if (th_no_dlg_encode_contact(msg, flags, route_s, NULL) < 0) {
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