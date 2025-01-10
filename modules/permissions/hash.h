/*
 * Hash table functions header file
 *
 * Copyright (C) 2009 Irina Stanescu
 * Copyright (C) 2009 Voice System
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

#ifndef PERM_HASH_H
#define PERM_HASH_H


#include <sys/types.h>
#include "../../ip_addr.h"
#include "../../str.h"
#include "../../mi/mi.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_from.h"
#include "../../usr_avp.h"
#include "partitions.h"

#define PERM_HASH_SIZE 4096

#define GROUP_ANY 0
#define MASK_ANY 32
#define PORT_ANY 0

/*
 * Structure stored in address hash table
 */
struct address_list {
	struct net *subnet;
	unsigned int grp;			/* Group for the specified IP */
    unsigned int port;			/* Port */
	int proto;                  /* Protocol -- UDP, TCP, TLS, or SCTP */
	char *pattern;              /* Pattern matching From header field */
	char *info;       		    /* Extra information */
	struct address_list *next;  /* Next element in the list */
};


/*
 * Create and initialize a hash table
 */
struct address_list** pm_hash_create(void);


/*
 * Destroy a hash table and release memory
 */
void pm_hash_destroy(struct address_list** table);


/*
 * Add <ip, group, port, proto, pattern> into hash table
 */
int pm_hash_insert(struct address_list** table, struct net *subnet,
		unsigned int grp, unsigned int port, int proto,
		str* pattern, str* info);


/*
 * Check if an entry exists in hash table that has given group, ip,
 * port, protocol value and pattern that matches to From URI.
 */
int pm_hash_match(struct sip_msg *msg, struct address_list** table,
		unsigned int grp, struct ip_addr *ip, unsigned int port, int proto,
		char *pattern, pv_spec_t* info, int is_subnet);


/*
 * Print entries stored in hash table
 */
//void hash_print(struct address_list** hash_table, FILE* reply_file);
int pm_hash_mi_print(struct address_list **table, mi_item_t *part_item,
		struct pm_part_struct *pm, int is_subnet);

int pm_count_hash(struct address_list **table);

/*
 * Empty hash table
 */
void pm_empty_hash(struct address_list** table);

int find_group_in_hash_table(struct address_list** table,
		struct ip_addr *ip, unsigned int port, int is_subnet);

#endif /* PERM_HASH_H */
