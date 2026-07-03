/*
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

#ifndef redact_pii_h
#define redact_pii_h

#include "str.h"

enum {
    REDACT_REPLACE = 0,
    REDACT_APPEND,
    REDACT_PREPEND,
    REDACT_FORMAT
};

typedef struct {
    str left;
    str right;
} redact_log_format_t;

extern int redact_pii_;
extern char *redact_template;
extern int redact_mode;
extern redact_log_format_t redact_fmt;

const char* redact_pii(const char* input);
int redact_pii_len(const char* input, int orig_len);
#define REDACT_PII(len, s) redact_pii_len((s), (len)), redact_pii((s))

#endif
