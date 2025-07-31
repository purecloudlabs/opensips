/*
 * Copyright (C) 2025 OpenSIPS Solutions
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

#ifndef _REST_SOCKET_H_
#define _REST_SOCKET_H_

#include <curl/curl.h>
#include <curl/multi.h>

#include <sys/resource.h>

int init_process_limits(rlim_t rlim_cur);
int get_max_fd(int no_max_default);
int start_multi_socket(CURLM *multi_handle);
int run_multi_socket(CURLM *multi_handle);
int setsocket_callback(CURLM *multi_handle);

#endif /* _REST_SOCKET_H_ */ 