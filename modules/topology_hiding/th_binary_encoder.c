#include <stdint.h>

#include "../../parser/msg_parser.h"
#include "../../socket_info.h"

#define SCHEME_MASK    0x0007
#define SCHEME_SIP     0x0000
#define SCHEME_SIPS    0x0001
#define SCHEME_TEL     0x0002
#define SCHEME_TELS    0x0003
#define SCHEME_URN_S   0x0004
#define SCHEME_URN_N   0x0005
#define SCHEME_M1      0x0006  // Magic bit 1 - must be 0 (invalid/garbage detection)
#define SCHEME_M2      0x0007  // Magic bit 2 - must be 0 (invalid/garbage detection)

#define TRANSPORT_MASK 0x0038
#define TRANSPORT_UDP  0x0000
#define TRANSPORT_TCP  0x0008
#define TRANSPORT_TLS  0x0010
#define TRANSPORT_SCTP 0x0018
#define TRANSPORT_WS   0x0020
#define TRANSPORT_WSS  0x0028
#define TRANSPORT_M1   0x0030  // Magic bit 1 - must be 0 (invalid/garbage detection)
#define TRANSPORT_M2   0x0038  // Magic bit 2 - must be 0 (invalid/garbage detection)

#define DOMAIN_MASK    0x00C0
#define DOMAIN_IPV4    0x0000
#define DOMAIN_IPV6    0x0040
#define DOMAIN_FQDN    0x0080
#define DOMAIN_M1      0x00C0  // Magic bit - must be 0 (invalid/garbage detection)

#define HAS_USERNAME   0x0100
#define HAS_PASSWORD   0x0200
#define HAS_PORT       0x0400
#define HAS_PARAMS     0x0800  // Now means "has OTHER params" (not lr/r2)
#define HAS_HEADERS    0x1000
#define HAS_LR         0x2000  // lr or lr=on present
#define IS_DUAL_URI    0x4000  // Dual URI encoding flag
#define RESERVED_BIT   0x8000  // Reserved for future use

#define SOCKET_PROTO_MASK  0x07  // 3 bits for protocol (bits 0-2)
#define SOCKET_IP_MASK     0x18  // 2 bits for IP type (bits 3-4)
#define SOCKET_IPV4        0x00
#define SOCKET_IPV6        0x08
#define SOCKET_HAS_PORT    0x20  // Bit 5: port is present


// URI2 properties byte (1 byte following URI1 data)
#define URI2_SCHEME_MASK    0x07    // Bits 0-2: scheme for URI2
#define URI2_TRANSPORT_MASK 0x38    // Bits 3-5: transport for URI2
#define URI2_TRANSPORT_SHIFT 3
#define URI2_HAS_PORT       0x40    // Bit 6: URI2 has port
#define URI2_HAS_R2         0x80    // Bit 7: r2 flag for both URIs in dual encoding

static str r2_on = str_init("r2=on");
static str lr = str_init("lr");
static str lr_on = str_init("lr=on");

#define MAX_ENCODED_URI_SIZE ( \
    sizeof(uint16_t) +             /* uri properties */ \
    sizeof(uint8_t)  + UINT8_MAX + /* username */ \
    sizeof(uint8_t)  + UINT8_MAX + /* password */ \
    sizeof(uint8_t)  + UINT8_MAX + /* domain */ \
    sizeof(uint16_t) +             /* port */ \
    sizeof(uint8_t)  + UINT8_MAX + /* params */ \
    sizeof(uint8_t)  + UINT8_MAX + /* headers */ \
    sizeof(uint8_t)  +             /* second associated uri flags */ \
    sizeof(uint16_t)               /* second associated uri port */ \
)

#define MAX_THINFO_BUFFER_SIZE 4096

typedef struct {
    uint16_t len;
    unsigned char buf[MAX_THINFO_BUFFER_SIZE];
    int pos;
} encoded_uri_t;

static const uint8_t SCHEMES[] = {
    [ERROR_URI_T]            = 0,
    [SIP_URI_T]              = SCHEME_SIP,
    [SIPS_URI_T]             = SCHEME_SIPS,
    [TEL_URI_T]              = SCHEME_TEL,
    [TELS_URI_T]             = SCHEME_TELS,
    [URN_SERVICE_URI_T]      = SCHEME_URN_N,
    [URN_NENA_SERVICE_URI_T] = SCHEME_URN_S
};

static const enum _uri_type SCHEME_TO_ENUM[] = {
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

static const uint8_t TRANSPORTS[] = {
    [PROTO_NONE]    = 0,
    [PROTO_UDP]     = TRANSPORT_UDP,
    [PROTO_TCP]     = TRANSPORT_TCP,
    [PROTO_TLS]     = TRANSPORT_TLS,
    [PROTO_SCTP]    = TRANSPORT_SCTP,
    [PROTO_WS]      = TRANSPORT_WS,
    [PROTO_WSS]     = TRANSPORT_WSS
};

static const enum sip_protos TRANSPORT_TO_ENUM[] = {
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

static str dual_uri_skip_params[] = {
    str_init("transport"),
    str_init("lr"),
    str_init("r2")
};

static int dual_uri_skip_params_count = sizeof(dual_uri_skip_params) / sizeof(dual_uri_skip_params[0]);

static uint8_t encode_params(unsigned char *p, uint16_t *uri_properties, str *params, int param_count, str params_to_skip[static param_count]) {
    char *src, *end;
    int remaining, param_len_current;
    uint8_t param_len = 0;
    int skip_encode = 0;
    
    if (!params || params->len == 0 || params->len > UINT8_MAX) {
        return 0;
    }
    
    src = params->s;
    remaining = params->len;
    
    if (remaining > 0 && *src == ';') {
        src++;
        remaining--;
    }
    
    while (remaining > 0) {
        if (*src == ';') {
            src++;
            remaining--;
            if (remaining == 0) break;
        }
        
        skip_encode = 0;
        end = memchr(src, ';', remaining);
        param_len_current = end ? (end - src) : remaining;

        for (int i = 0; i < param_count; i++) {
            LM_DBG("Checking param [%.*s]\n", params_to_skip[i].len, params_to_skip[i].s);
            if (param_len_current >= params_to_skip[i].len && strncmp(src, params_to_skip[i].s, params_to_skip[i].len) == 0) {
                /* Setting some flags in case of lr or r2 params which will be encoded into the uri properties */
                if (param_len_current == r2_on.len && memcmp(src, r2_on.s, r2_on.len) == 0) {
                    *uri_properties |= URI2_HAS_R2;
                } else if ((param_len_current == lr.len && memcmp(src, lr.s, lr.len) == 0) ||
                         (param_len_current == lr_on.len && memcmp(src, lr_on.s, lr_on.len) == 0)) {
                    *uri_properties |= HAS_LR;
                }
                
                src += param_len_current;
                remaining -= param_len_current;
                skip_encode = 1;
                break;
            }
        }

        if (skip_encode) {
            continue;
        }

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
    
    return param_len;
}

int encode_dual_uri(encoded_uri_t *encoding_uri, struct sip_uri *uri1, struct sip_uri *uri2) {
    unsigned char *p, *props_ptr, *param_len_ptr, *uri2_props_ptr;
    uint16_t props;
    uint8_t uri2_props;
    char tmp[256];
    uint8_t param_len;
    size_t start_pos;
    
    if (encoding_uri->len + MAX_ENCODED_URI_SIZE * 2 > MAX_THINFO_BUFFER_SIZE) {
        return -1;
    }
    
    if (encoding_uri->len == 0) {
        p = encoding_uri->buf + 3;
        encoding_uri->len = 3;
        encoding_uri->pos = 0;
    } else {
        p = encoding_uri->buf + encoding_uri->len;
    }
    
    start_pos = p - encoding_uri->buf;
    
    // Initialize URI1 properties with IS_DUAL_URI flag
    props = IS_DUAL_URI;
    props_ptr = p;
    p += 2;

    props |= SCHEMES[uri1->type];
    if (uri1->proto >= PROTO_UDP && uri1->proto <= PROTO_WSS) {
        props = (props & ~TRANSPORT_MASK) | TRANSPORTS[uri1->proto];
    } else {
        props = (props & ~TRANSPORT_MASK) | TRANSPORTS[PROTO_UDP];
    }

    if (uri1->user.len > 0 && uri1->user.len <= UINT8_MAX) {
        props |= HAS_USERNAME;
        *p++ = (uint8_t)uri1->user.len;
        memcpy(p, uri1->user.s, uri1->user.len);
        p += uri1->user.len;
    }

    if (uri1->passwd.len > 0 && uri1->passwd.len <= UINT8_MAX) {
        props |= HAS_PASSWORD;
        *p++ = (uint8_t)uri1->passwd.len;
        memcpy(p, uri1->passwd.s, uri1->passwd.len);
        p += uri1->passwd.len;
    }

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

    if (uri1->port_no > 0) {
        props |= HAS_PORT;
        *p++ = (uri1->port_no >> 8) & 0xFF;
        *p++ = uri1->port_no & 0xFF;
    }

    uri2_props = 0;
    uri2_props_ptr = p;
    p += 1;

    uri2_props |= SCHEMES[uri2->type] & URI2_SCHEME_MASK;
    if (uri2->proto >= PROTO_UDP && uri2->proto <= PROTO_WSS) {
        // TRANSPORTS values are already in bits 3-5 format (0x00, 0x08, 0x10, 0x18, 0x20, 0x28)
        // Just mask to fit in URI2 byte
        uri2_props |= TRANSPORTS[uri2->proto] & URI2_TRANSPORT_MASK;
    }

    if (uri2->port_no > 0) {
        uri2_props |= URI2_HAS_PORT;
        *p++ = (uri2->port_no >> 8) & 0xFF;
        *p++ = uri2->port_no & 0xFF;
    }

    if (uri1->params.len > 0 && uri1->params.len <= UINT8_MAX) {
        param_len_ptr = p++;
        param_len = encode_params(p, &props, &uri1->params, dual_uri_skip_params_count, dual_uri_skip_params);

        if (props & URI2_HAS_R2) {
            uri2_props |= URI2_HAS_R2;
            props &= ~URI2_HAS_R2;  // Clear it from props since it belongs in uri2_props
        }

        if (param_len > 0) {
            *param_len_ptr = param_len;
            props |= HAS_PARAMS;
            p += param_len;
        } else {
            p = param_len_ptr;
        }
    }

    if (uri1->headers.len > 0 && uri1->headers.len <= UINT8_MAX) {
        props |= HAS_HEADERS;
        *p++ = (uint8_t)uri1->headers.len;
        memcpy(p, uri1->headers.s, uri1->headers.len);
        p += uri1->headers.len;
    }

    props_ptr[0] = (props >> 8) & 0xFF;
    props_ptr[1] = props & 0xFF;

    *uri2_props_ptr = uri2_props;
    
    encoding_uri->len = p - encoding_uri->buf;
    return p - (encoding_uri->buf + start_pos);
}


int encode_uri(encoded_uri_t *encoding_uri, struct sip_uri *uri, int param_count, str params_to_skip[static param_count]) {
    unsigned char *p, *props_ptr, *param_len_ptr;
    uint16_t props;
    char tmp[256];
    uint8_t param_len;
    size_t start_pos;
    str extra_params[param_count + 2];
    int extra_param_count = param_count;
    
    if (encoding_uri->len + MAX_ENCODED_URI_SIZE > MAX_THINFO_BUFFER_SIZE) {
        return -1;
    }
    
    if (encoding_uri->len == 0) {
        p = encoding_uri->buf + 3;
        encoding_uri->len = 3;
        encoding_uri->pos = 0;
    } else {
        p = encoding_uri->buf + encoding_uri->len;
    }
    
    start_pos = p - encoding_uri->buf;
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

    if (uri->params.len > 0 && uri->params.len <= UINT8_MAX) {
        memcpy(extra_params, params_to_skip, param_count * sizeof(params_to_skip[0]));
        extra_params[extra_param_count++] = str_init("transport");
        extra_params[extra_param_count++] = str_init("lr");

        param_len_ptr = p++;
        param_len = encode_params(p, &props, &uri->params, extra_param_count, extra_params);
        
        if (param_len > 0) {
            *param_len_ptr = param_len;
            props |= HAS_PARAMS;
            p += param_len;
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

	LM_ERR("ENCODE URI: props=0x%04x, buffer_pos=%ld, bytes_written=%ld\n",
    	props, (long)(props_ptr - encoding_uri->buf), (long)(p - props_ptr));
    
    props_ptr[0] = (props >> 8) & 0xFF;
    props_ptr[1] = props & 0xFF;
    
    encoding_uri->len = p - encoding_uri->buf;
    return p - (encoding_uri->buf + start_pos);
}


// Socket encoding/decoding functions
int encode_socket(encoded_uri_t *encoding_uri, struct socket_info *si) {
    unsigned char *p;
    uint8_t flags = 0;
    int has_port = 0;

    if (si == NULL) {
        LM_ERR("Socket is null\n");
        return -1;
    }
    
    if (encoding_uri->len + MAX_ENCODED_URI_SIZE > MAX_THINFO_BUFFER_SIZE) {
        return -1;
    }

    if (encoding_uri->len == 0) {
        encoding_uri->len = 3;
    }

    p = encoding_uri->buf + encoding_uri->len;

    if (si->proto >= PROTO_UDP && si->proto <= PROTO_WSS) {
        flags |= (TRANSPORTS[si->proto] >> 3) & SOCKET_PROTO_MASK;
    } else {
        return -1;
    }

    if (si->address.af == AF_INET) {
        flags |= SOCKET_IPV4;
    } else if (si->address.af == AF_INET6) {
        flags |= SOCKET_IPV6;
    } else {
        return -1;
    }
    
    // Check if port is non-standard (not default for protocol)
    // For now, always encode port - can optimize later
    has_port = (si->port_no > 0) ? 1 : 0;
    if (has_port) {
        flags |= SOCKET_HAS_PORT;
    }

    *p++ = flags;

    if (si->address.af == AF_INET) {
        memcpy(p, si->address.u.addr, 4);
        p += 4;
    } else if (si->address.af == AF_INET6) {
        memcpy(p, si->address.u.addr, 16);
        p += 16;
    }

    if (has_port) {
        *p++ = (si->port_no >> 8) & 0xFF;
        *p++ = si->port_no & 0xFF;
    }
    
    int bytes_written = p - (encoding_uri->buf + encoding_uri->len);
    encoding_uri->len = p - encoding_uri->buf;
    
    return bytes_written;
}

int decode_socket(encoded_uri_t *encoded_uri, int *proto, str *ip, unsigned short *port) {
    static char ip_str[INET6_ADDRSTRLEN];
    unsigned char *p;
    uint8_t flags, proto_bits, ip_type;
    int remaining, has_port;
    
    if (!encoded_uri || encoded_uri->pos >= encoded_uri->len) return -1;

    if (encoded_uri->pos == 0) {
        encoded_uri->pos = 3;
    }
    
    p = encoded_uri->buf + encoded_uri->pos;
    remaining = encoded_uri->len - encoded_uri->pos;
    
    if (remaining < 5) return -1;  // Minimum: 1 byte flags + 4 bytes IPv4
    
    flags = *p++;
    remaining--;
    
    proto_bits = (flags & SOCKET_PROTO_MASK) << 3;
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
    has_port = (flags & SOCKET_HAS_PORT) ? 1 : 0;
    
    // Read IP address
    if (ip_type == SOCKET_IPV4) {
        if (remaining < (4 + (has_port ? 2 : 0))) return -1;  // Need 4 bytes for IP + optional 2 for port
        inet_ntop(AF_INET, p, ip_str, INET_ADDRSTRLEN);
        ip->s = ip_str;
        ip->len = strlen(ip_str);
        p += 4;
    } else if (ip_type == SOCKET_IPV6) {
        if (remaining < (16 + (has_port ? 2 : 0))) return -1;  // Need 16 bytes for IP + optional 2 for port
        inet_ntop(AF_INET6, p, ip_str, INET6_ADDRSTRLEN);
        ip->s = ip_str;
        ip->len = strlen(ip_str);
        p += 16;
    } else {
        return -1;
    }

    if (has_port) {
        *port = (p[0] << 8) | p[1];
        p += 2;
    } else {
        *port = 0;
    }
    
    encoded_uri->pos = p - encoded_uri->buf;
    
    return 1;
}

void reset_encode_buffer(encoded_uri_t *encoded_uri) {
    encoded_uri->len = 0;
}

void finalize_encode_buffer(encoded_uri_t *encoded_uri, uint16_t flags, uint8_t count) {
    encoded_uri->buf[0] = (flags >> 8) & 0xFF;
    encoded_uri->buf[1] = flags & 0xFF;
    encoded_uri->buf[2] = count;
}

uint8_t get_uri_count(encoded_uri_t *encoded_uri) {
    return encoded_uri->buf[2];
}

uint16_t get_flags(encoded_uri_t *encoded_uri) {
    return (encoded_uri->buf[0] << 8) | encoded_uri->buf[1];
}

int decode_uris(encoded_uri_t *encoded_uri, char decoded_uri_str[static MAX_ENCODED_URI_SIZE * 3], uint16_t uri_count, str uris[static uri_count]) {
    unsigned char *p;
    uint16_t props;
    uint8_t domain_type, len, scheme, transport_bits;
    char *s, *uri_start;
    int t_len;
    int uri_idx;
    char host_buf[256];
    int host_len;
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

        LM_ERR("DECODE URI[%d]: props=0x%04x, HAS_LR=%d, IS_DUAL=%d, buffer_pos=%ld\n",
            uri_idx, props, !!(props & HAS_LR), !!(props & IS_DUAL_URI), (long)(p - encoded_uri->buf));
        
        // Validate magic bits - detect garbage data
        // Must check exact values, not just bit patterns
        scheme = props & SCHEME_MASK;
        transport_bits = props & TRANSPORT_MASK;
        domain_type = props & DOMAIN_MASK;
        
        if (scheme > SCHEME_URN_N || transport_bits > TRANSPORT_WSS || domain_type > DOMAIN_FQDN) {
            LM_ERR("Invalid properties detected: props=0x%04x, scheme=0x%02x, transport=0x%02x, domain=0x%02x (garbage data)\n",
                props, scheme, transport_bits, domain_type);
            return -1;
        }
        
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
            transport2 = uri2_props & URI2_TRANSPORT_MASK;  // Extract transport bits (already in correct position for TRANSPORT_STRINGS)
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
            
            // Add transport for URI1 (only if not UDP)
            if (transport1 != TRANSPORT_UDP) {
                if (transport1 < sizeof(TRANSPORT_STRINGS)/sizeof(TRANSPORT_STRINGS[0]) && 
                    TRANSPORT_STRINGS[transport1] != NULL) {
                    *s++ = ';';
                    t_len = strlen(TRANSPORT_STRINGS[transport1]);
                    memcpy(s, TRANSPORT_STRINGS[transport1], t_len);
                    s += t_len;
                }
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
            
            uris[uri_idx].s = uri_start - 1;
            uris[uri_idx].len = s - uris[uri_idx].s;
            
            if (uri_idx < uri_count - 1) {
                *s++ = ',';
            }
            
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
                
                // Add transport for URI2 (only if not UDP)
                if (transport2 != TRANSPORT_UDP) {
                    if (transport2 < sizeof(TRANSPORT_STRINGS)/sizeof(TRANSPORT_STRINGS[0]) && 
                        TRANSPORT_STRINGS[transport2] != NULL) {
                        *s++ = ';';
                        t_len = strlen(TRANSPORT_STRINGS[transport2]);
                        memcpy(s, TRANSPORT_STRINGS[transport2], t_len);
                        s += t_len;
                    }
                }

                // Add r2 flag (from URI2 props, not from IS_DUAL_URI)
                if (has_r2) {
                    memcpy(s, ";r2=on", 6);
                    s += 6;
                }
                
                // Add lr flag (shared)
                if (props & HAS_LR) {
                    memcpy(s, ";lr", 3);
                    s += 3;
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
                
                uris[uri_idx].s = uri_start - 1;
                uris[uri_idx].len = s - uris[uri_idx].s;
                
                if (uri_idx < uri_count - 1) {
                    *s++ = ',';
                    *s++ = ' ';
                }
                
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
            
            // Output transport parameter only if not UDP
            transport_bits = (props & TRANSPORT_MASK);
            if (transport_bits != TRANSPORT_UDP) {
                if (transport_bits < sizeof(TRANSPORT_STRINGS)/sizeof(TRANSPORT_STRINGS[0]) && 
                    TRANSPORT_STRINGS[transport_bits] != NULL) {
                    *s++ = ';';
                    t_len = strlen(TRANSPORT_STRINGS[transport_bits]);
                    memcpy(s, TRANSPORT_STRINGS[transport_bits], t_len);
                    s += t_len;
                }
            }
            
            if (props & HAS_LR) {
                memcpy(s, ";lr", 3);
                s += 3;
            }
            
            // Note: r2 is NOT decoded from IS_DUAL_URI flag for single URIs
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
            
            uris[uri_idx].s = uri_start - 1;
            uris[uri_idx].len = s - uris[uri_idx].s;
            
            if (uri_idx < uri_count - 1) {
                *s++ = ',';
            }
            
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