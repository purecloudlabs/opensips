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

#ifndef _TH_NO_DLG_LOGIC_H
#define _TH_NO_DLG_LOGIC_H

#include "../../str.h"
#include "../tm/t_hooks.h"
#include "th_common_logic.h"

enum encode_scheme {ENC_BASE64, ENC_BASE32};

int topo_hiding_no_dlg(struct sip_msg *req, struct cell* t, unsigned int extra_flags);
int topo_hiding_match_no_dlg(struct sip_msg *msg);
int topo_hiding_init_no_dlg(int use_compression_api);
int topo_hiding_destroy_no_dlg(void);

#endif