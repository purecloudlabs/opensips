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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "rest_sockets.h"

#if defined(__CPU_aarch64) || defined(__CPU_x86_64) || defined(__CPU_mips64)
#define WORD_SIZE_BITS 64
#define WORD_SIZE_BYTES 8
#define COUNT_LEADING_ZEROS(s) __builtin_clzll(s)
#define COUNT_TRAILING_ZEROS(s) __builtin_ctzll(s)
typedef uint64_t cpuword_t;
#else
#define WORD_SIZE_BITS 32
#define WORD_SIZE_BYTES 4
#define COUNT_LEADING_ZEROS(s) __builtin_clz(s)
#define COUNT_TRAILING_ZEROS(s) __builtin_ctz(s)
typedef uint32_t cpuword_t;
#endif

#define BYTE_LEN 8

typedef struct _file_descriptors {
	unsigned char *tracked_socks;
	int max_fd_index;
} file_descriptors;

static file_descriptors fds;
size_t aligned_bitset_len;

int init_process_limits(rlim_t rlim_cur) {
	aligned_bitset_len = (((rlim_cur + BYTE_LEN - 1) / BYTE_LEN) * BYTE_LEN) / BYTE_LEN;

	fds.tracked_socks = (unsigned char*) pkg_malloc(aligned_bitset_len);
	fds.max_fd_index = 0;

	if (fds.tracked_socks == NULL) {
		return -1;
	}

	return 0;
}

int get_max_fd(int no_max_default) {
	cpuword_t sockets;

	if (fds.max_fd_index < 0) {
		return -2;
	}

    memcpy(&sockets, fds.tracked_socks + fds.max_fd_index, sizeof(cpuword_t));

	if (!sockets) {
		fds.max_fd_index -= WORD_SIZE_BYTES;
		return no_max_default;
	}
	
    return ((fds.max_fd_index << 3) + WORD_SIZE_BITS - 1) - COUNT_LEADING_ZEROS(sockets);
}

int running_sockets(void) {
	cpuword_t sockets;
    int running, curl_fd;

	for (int i = 0; i <= fds.max_fd_index; i += WORD_SIZE_BYTES) {
		memcpy(&sockets, fds.tracked_socks + i, sizeof(cpuword_t));

		if (sockets) {
			return 1;
		}
	}

	return 0;
}

static void add_sock(int s) {
    int sock_index = s >> 3;

	if (sock_index > fds.max_fd_index) {
		fds.max_fd_index = sock_index;
	}

    fds.tracked_socks[s / BYTE_LEN] |= (1 << (s % BYTE_LEN));
}

static void remove_sock(int s) {
	cpuword_t sockets;

	fds.tracked_socks[s / BYTE_LEN] &= ~(1 << (s % BYTE_LEN));

	if (fds.max_fd_index >= 0) {
		memcpy(&sockets, fds.tracked_socks + fds.max_fd_index, sizeof(cpuword_t));

		if (!sockets) {
			fds.max_fd_index -= WORD_SIZE_BYTES;
		}
	}
}

static int socket_action_connect(CURL *e, curl_socket_t s, int event, void *cbp, void *sockp) {
	LM_DBG("called for socket %d status %d\n", s, event);

	CURLEasyHandles *easy_handles = (CURLEasyHandles*) cbp;
	if (event != CURL_POLL_REMOVE) {
		add_sock(s);
	} else if (event == CURL_POLL_REMOVE) {
		remove_sock(s);

		LM_DBG("Adding handle for socket %d current size %d\n", s, easy_handles->size);
		easy_handles->handles[easy_handles->size] = e;
		easy_handles->size += 1;
	}

  	return 0;
}

static int socket_action_http(CURL *e, curl_socket_t s, int event, void *cbp, void *sockp) {
	LM_DBG("called for socket %d status %d\n", s, event);

	if (event != CURL_POLL_REMOVE) {
		add_sock(s);
	} else if (event == CURL_POLL_REMOVE) {
		remove_sock(s);
	}

  	return 0;
}

int setsocket_callback_connect(CURLM *multi_handle, CURLEasyHandles *easy_handles) {
    CURLMcode mrc;

    mrc = curl_multi_setopt(multi_handle, CURLMOPT_SOCKETFUNCTION, socket_action_connect);
    if (mrc != CURLM_OK) {
        LM_ERR("curl_multi_setopt(%d): (%s)\n", CURLMOPT_SOCKETFUNCTION, curl_multi_strerror(mrc));
        return -1;
    }

    mrc = curl_multi_setopt(multi_handle, CURLMOPT_SOCKETDATA, easy_handles);
    if (mrc != CURLM_OK) {
        LM_ERR("curl_multi_setopt(%d): (%s)\n", CURLMOPT_SOCKETFUNCTION, curl_multi_strerror(mrc));
        return -1;
    }

    return 0;
}

int setsocket_callback_request(CURLM *multi_handle) {
    CURLMcode mrc;
    
    mrc = curl_multi_setopt(multi_handle, CURLMOPT_SOCKETFUNCTION, socket_action_http);
    if (mrc != CURLM_OK) {
        LM_ERR("curl_multi_setopt(%d): (%s)\n", CURLMOPT_SOCKETFUNCTION, curl_multi_strerror(mrc));
        return -1;
    }

    return 0;
}

static int run_all_multi_socket(CURLM *multi_handle, int ev_bitmask) {
	CURLMcode mrc;
	int running;

	memset(fds.tracked_socks, 0, aligned_bitset_len);
	fds.max_fd_index = 0;
	mrc = curl_multi_socket_action(multi_handle, CURL_SOCKET_TIMEOUT, 0, &running);

	if (mrc != CURLM_OK) {
		LM_ERR("curl_multi_socket_action: %s\n", curl_multi_strerror(mrc));
		return -1;
	}

	return running;
}

int start_multi_socket(CURLM *multi_handle) {
	return run_all_multi_socket(multi_handle, CURL_SOCKET_TIMEOUT);
}

int end_multi_socket(CURLM *multi_handle) {
	return run_all_multi_socket(multi_handle, CURL_POLL_REMOVE);
}

int run_multi_socket(CURLM *multi_handle) {
	CURLMcode mrc;
	cpuword_t sockets;
    int running, curl_fd;

	for (int i = 0; i <= fds.max_fd_index; i += WORD_SIZE_BYTES) {
		memcpy(&sockets, fds.tracked_socks + i, sizeof(cpuword_t));
		
		while (sockets) {
			curl_fd = (i * BYTE_LEN) + COUNT_TRAILING_ZEROS(sockets);
			LM_DBG("Action on socket %d\n", curl_fd);
		
			mrc = curl_multi_socket_action(multi_handle, curl_fd, 0, &running);
			if (mrc != CURLM_OK) {
				LM_ERR("curl_multi_socket_action: %s\n", curl_multi_strerror(mrc));
				return -1;
			}

			sockets &= sockets - 1;
		}
	}

	return running;
}
