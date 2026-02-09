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

#ifndef _TH_BINARY_ENCODER_H
#define _TH_BINARY_ENCODER_H

#include <stdint.h>

#include "../../parser/msg_parser.h"
#include "../../socket_info.h"

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

int encode_uri(encoded_uri_t *encoding_uri, struct sip_uri *uri, int param_count, str params_to_skip[static param_count]);
int encode_dual_uri(encoded_uri_t *encoding_uri, struct sip_uri *uri1, struct sip_uri *uri2);
int encode_socket(encoded_uri_t *encoding_uri, struct socket_info *si);

int decode_uris(encoded_uri_t *encoded_uri, char decoded_uri_str[static MAX_ENCODED_URI_SIZE * 3], uint16_t uri_count, str uris[static uri_count]);
int decode_socket(encoded_uri_t *encoded_uri, int *proto, str *ip, unsigned short *port);

uint8_t get_uri_count(encoded_uri_t *encoded_uri);
uint16_t get_flags(encoded_uri_t *encoded_uri);

void finalize_encode_buffer(encoded_uri_t *encoded_uri, uint16_t flags, uint8_t count);
void reset_encode_buffer(encoded_uri_t *encoded_uri);

#endif