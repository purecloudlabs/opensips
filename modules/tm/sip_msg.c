/*
 * $Id$
 * 
 * Copyright (C) 2001-2003 FhG Fokus
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2003-01-23 - msg_cloner clones msg->from->parsed too (janakj)
 *  2003-01-29 - scratchpad removed (jiri)
 *  2003-02-25 - auth_body cloner added (janakj)
 *  2003-02-28  scratchpad compatibility abandoned (jiri)
 *  2003-03-31  removed msg->repl_add_rm (andrei)
 *  2003-04-04  parsed uris are recalculated on cloning (jiri)
 *  2003-05-07  received, rport & i via shortcuts are also translated (andrei)
 *  2003-11-11  updated cloning of lump_rpl (bogdan)
 *  2004-03-31  alias shortcuts are also translated (andrei)
 *
 *
 * cloning a message into shared memory (TM keeps a snapshot
 * of messages in memory); note that many operations, which
 * allocate pkg memory (such as parsing) cannot be used with
 * a cloned message -- it would result in linking pkg structures
 * to shmem msg and eventually in a memory error 
 *
 * the cloned message is stored in a single memory fragment to
 * save too many shm_mallocs -- these are expensive as they
 * not only take lookup in fragment table but also a shmem lock
 * operation (the same for shm_free)
 *
 */

#include <stdio.h>
#include "sip_msg.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../data_lump.h"
#include "../../data_lump_rpl.h"
#include "../../ut.h"
#include "../../parser/digest/digest.h"


/* rounds to the first 4 byte multiple on 32 bit archs 
 * and to the first 8 byte multiple on 64 bit archs */
#define ROUND4(s) \
	(((s)+(sizeof(char*)-1))&(~(sizeof(char*)-1)))

#define lump_len( _lump) \
	(ROUND4(sizeof(struct lump)) +\
	ROUND4(((_lump)->op==LUMP_ADD)?(_lump)->len:0))
#define lump_clone( _new,_old,_ptr) \
	{\
		(_new) = (struct lump*)(_ptr);\
		memcpy( (_new), (_old), sizeof(struct lump) );\
		(_new)->flags|=LUMPFLAG_SHMEM; \
		(_ptr)+=ROUND4(sizeof(struct lump));\
		if ( (_old)->op==LUMP_ADD) {\
			(_new)->u.value = (char*)(_ptr);\
			memcpy( (_new)->u.value , (_old)->u.value , (_old)->len);\
			(_ptr)+=ROUND4((_old)->len);}\
	}




inline static struct via_body* via_body_cloner( char* new_buf,
					char *org_buf, struct via_body *param_org_via, char **p)
{
	struct via_body *new_via;
	struct via_body *first_via, *last_via;
	struct via_body *org_via;

	first_via = last_via = 0;
	org_via = param_org_via;

	do
	{
		/* clones the via_body structure */
		new_via = (struct via_body*)(*p);
		memcpy( new_via , org_via , sizeof( struct via_body) );
		(*p) += ROUND4(sizeof( struct via_body ));

		/* hdr (str type) */
		new_via->hdr.s=translate_pointer(new_buf,org_buf,org_via->hdr.s);
		/* name (str type) */
		new_via->name.s=translate_pointer(new_buf,org_buf,org_via->name.s);
		/* version (str type) */
		new_via->version.s=
			translate_pointer(new_buf,org_buf,org_via->version.s);
		/* transport (str type) */
		new_via->transport.s=
			translate_pointer(new_buf,org_buf,org_via->transport.s);
		/* host (str type) */
		new_via->host.s=translate_pointer(new_buf,org_buf,org_via->host.s);
		/* port_str (str type) */
		new_via->port_str.s=
			translate_pointer(new_buf,org_buf,org_via->port_str.s);
		/* params (str type) */
		new_via->params.s=translate_pointer(new_buf,org_buf,org_via->params.s);
		/* transaction id */
		new_via->tid.s=
			translate_pointer(new_buf, org_buf, org_via->tid.s);
		/* comment (str type) */
		new_via->comment.s=
			translate_pointer(new_buf,org_buf,org_via->comment.s);

		if ( org_via->param_lst )
		{
			struct via_param *vp, *new_vp, *last_new_vp;
			for( vp=org_via->param_lst, last_new_vp=0 ; vp ; vp=vp->next )
			{
				new_vp = (struct via_param*)(*p);
				memcpy( new_vp , vp , sizeof(struct via_param));
				(*p) += ROUND4(sizeof(struct via_param));
				new_vp->name.s=translate_pointer(new_buf,org_buf,vp->name.s);
				new_vp->value.s=translate_pointer(new_buf,org_buf,vp->value.s);
				new_vp->start=translate_pointer(new_buf,org_buf,vp->start);
				
				/* "translate" the shortcuts */
				switch(new_vp->type){
					case PARAM_BRANCH:
							new_via->branch = new_vp;
							break;
					case PARAM_RECEIVED:
							new_via->received = new_vp;
							break;
					case PARAM_RPORT:
							new_via->rport = new_vp;
							break;
					case PARAM_I:
							new_via->i = new_vp;
							break;
					case PARAM_ALIAS:
							new_via->alias = new_vp;
							break;
					case PARAM_MADDR:
							new_via->maddr = new_vp;
							break;
				}

				if (last_new_vp)
					last_new_vp->next = new_vp;
				else
					new_via->param_lst = new_vp;

				last_new_vp = new_vp;
				last_new_vp->next = NULL;
			}
			new_via->last_param = new_vp;
		}/*end if via has params */

		if (last_via)
			last_via->next = new_via;
		else
			first_via = new_via;
		last_via = new_via;
		org_via = org_via->next;
	}while(org_via);

	return first_via;
}


static void uri_trans(char *new_buf, char *org_buf, struct sip_uri *uri)
{
	uri->user.s=translate_pointer(new_buf,org_buf,uri->user.s);
	uri->passwd.s=translate_pointer(new_buf,org_buf,uri->passwd.s);
	uri->host.s=translate_pointer(new_buf,org_buf,uri->host.s);
	uri->port.s=translate_pointer(new_buf,org_buf,uri->port.s);
	uri->params.s=translate_pointer(new_buf,org_buf,uri->params.s);
	uri->headers.s=translate_pointer(new_buf,org_buf,uri->headers.s);
	/* parameters */
	uri->transport.s=translate_pointer(new_buf,org_buf,uri->transport.s);
	uri->ttl.s=translate_pointer(new_buf,org_buf,uri->ttl.s);
	uri->user_param.s=translate_pointer(new_buf,org_buf,uri->user_param.s);
	uri->maddr.s=translate_pointer(new_buf,org_buf,uri->maddr.s);
	uri->method.s=translate_pointer(new_buf,org_buf,uri->method.s);
	uri->lr.s=translate_pointer(new_buf,org_buf,uri->lr.s);
	uri->r2.s=translate_pointer(new_buf,org_buf,uri->r2.s);
		/* ser specific rr parameter */
	/* values */
	uri->transport_val.s
		=translate_pointer(new_buf,org_buf,uri->transport_val.s);
	uri->ttl_val.s=translate_pointer(new_buf,org_buf,uri->ttl_val.s);
	uri->user_param_val.s
		=translate_pointer(new_buf,org_buf,uri->user_param_val.s);
	uri->maddr_val.s=translate_pointer(new_buf,org_buf,uri->maddr_val.s);
	uri->method_val.s=translate_pointer(new_buf,org_buf,uri->method_val.s);
	uri->lr_val.s=translate_pointer(new_buf,org_buf,uri->lr_val.s);
		/* lr value placeholder for lr=on a.s.o*/
	uri->r2_val.s=translate_pointer(new_buf,org_buf,uri->r2_val.s);
}


static inline struct auth_body* auth_body_cloner(char* new_buf, char *org_buf, struct auth_body *auth, char **p)
{
	struct auth_body* new_auth;

	new_auth = (struct auth_body*)(*p);
	memcpy(new_auth , auth , sizeof(struct auth_body));
	(*p) += ROUND4(sizeof(struct auth_body));
	
	/* authorized field must be cloned elsewhere */
	new_auth->digest.username.whole.s =
		translate_pointer(new_buf, org_buf, auth->digest.username.whole.s);
	new_auth->digest.username.user.s =
		translate_pointer(new_buf, org_buf, auth->digest.username.user.s);
	new_auth->digest.username.domain.s =
		translate_pointer(new_buf, org_buf, auth->digest.username.domain.s);
	new_auth->digest.realm.s =
		translate_pointer(new_buf, org_buf, auth->digest.realm.s);
	new_auth->digest.nonce.s =
		translate_pointer(new_buf, org_buf, auth->digest.nonce.s);
	new_auth->digest.uri.s =
		translate_pointer(new_buf, org_buf, auth->digest.uri.s);
	new_auth->digest.response.s =
		translate_pointer(new_buf, org_buf, auth->digest.response.s);
	new_auth->digest.alg.alg_str.s =
		translate_pointer(new_buf, org_buf, auth->digest.alg.alg_str.s);
	new_auth->digest.cnonce.s =
		translate_pointer(new_buf, org_buf, auth->digest.cnonce.s);
	new_auth->digest.opaque.s =
		translate_pointer(new_buf, org_buf, auth->digest.opaque.s);
	new_auth->digest.qop.qop_str.s =
		translate_pointer(new_buf, org_buf, auth->digest.qop.qop_str.s);
	new_auth->digest.nc.s =
		translate_pointer(new_buf, org_buf, auth->digest.nc.s);
	return new_auth;
}


static inline int clone_authorized_hooks(struct sip_msg* new,
					 struct sip_msg* old)
{
	struct hdr_field* ptr, *new_ptr, *hook1, *hook2;
	char stop = 0;

	get_authorized_cred(old->authorization, &hook1);
	if (!hook1) stop = 1;
	
	get_authorized_cred(old->proxy_auth, &hook2);
	if (!hook2) stop |= 2;

	ptr = old->headers;
	new_ptr = new->headers;

	while(ptr) {
		if (ptr == hook1) {
			if (!new->authorization || !new->authorization->parsed) {
				LM_CRIT("message cloner (authorization) failed\n");
				return -1;
			}
			((struct auth_body*)new->authorization->parsed)->authorized =
				new_ptr;
			stop |= 1;
		}
		
		if (ptr == hook2) {
			if (!new->proxy_auth || !new->proxy_auth->parsed) {
				LM_CRIT("message cloner (proxy_auth) failed\n");
				return -1;
			}
			((struct auth_body*)new->proxy_auth->parsed)->authorized =
				new_ptr;
			stop |= 2;
		}

		if (stop == 3) break;

		ptr = ptr->next;
		new_ptr = new_ptr->next;
	}
	return 0;
}


#define AUTH_BODY_SIZE sizeof(struct auth_body)

#define HOOK_NOT_SET(hook) (new_msg->hook == org_msg->hook)

/* next macro should only be called if hook is already set */
#define LINK_SIBLING_HEADER(_hook, _hdr) \
	do { \
		struct hdr_field *_itr; \
		for (_itr=new_msg->_hook; _itr->sibling; _itr=_itr->sibling); \
		_itr->sibling = _hdr; \
	} while(0)


struct sip_msg*  sip_msg_cloner( struct sip_msg *org_msg, int *sip_msg_len )
{
	unsigned int      len;
	struct hdr_field  *hdr,*new_hdr,*last_hdr;
	struct via_body   *via;
	struct via_param  *prm;
	struct to_param   *to_prm,*new_to_prm;
	struct sip_msg    *new_msg;
	struct lump_rpl   *rpl_lump, **rpl_lump_anchor;
	char              *p;


	/*computing the length of entire sip_msg structure*/
	len = ROUND4(sizeof( struct sip_msg ));
	/*we will keep only the original msg +ZT */
	len += ROUND4(org_msg->len + 1);
	/*the new uri (if any)*/
	if (org_msg->new_uri.s && org_msg->new_uri.len)
		len+= ROUND4(org_msg->new_uri.len);
	/*all the headers*/
	for( hdr=org_msg->headers ; hdr ; hdr=hdr->next )
	{
		/*size of header struct*/
		len += ROUND4(sizeof( struct hdr_field));
		switch (hdr->type)
		{
			case HDR_VIA_T:
				for (via=(struct via_body*)hdr->parsed;via;via=via->next)
				{
					len+=ROUND4(sizeof(struct via_body));
					/*via param*/
					for(prm=via->param_lst;prm;prm=prm->next)
						len+=ROUND4(sizeof(struct via_param ));
				}
				break;

			case HDR_TO_T:
			case HDR_FROM_T:
				/* From header might be unparsed */
				if (hdr->parsed) {
					len+=ROUND4(sizeof(struct to_body));
					     /*to param*/
					to_prm = ((struct to_body*)(hdr->parsed))->param_lst;
					for(;to_prm;to_prm=to_prm->next)
						len+=ROUND4(sizeof(struct to_param ));
				}
				break;

			case HDR_CSEQ_T:
				len+=ROUND4(sizeof(struct cseq_body));
				break;

			case HDR_AUTHORIZATION_T:
			case HDR_PROXYAUTH_T:
				if (hdr->parsed) {
					len += ROUND4(AUTH_BODY_SIZE);
				}
				break;

			case HDR_CALLID_T:
			case HDR_CONTACT_T:
			case HDR_MAXFORWARDS_T:
			case HDR_ROUTE_T:
			case HDR_RECORDROUTE_T:
			case HDR_PATH_T:
			case HDR_CONTENTTYPE_T:
			case HDR_CONTENTLENGTH_T:
			case HDR_EXPIRES_T:
			case HDR_SUPPORTED_T:
			case HDR_PROXYREQUIRE_T:
			case HDR_UNSUPPORTED_T:
			case HDR_ALLOW_T:
			case HDR_EVENT_T:
			case HDR_ACCEPT_T:
			case HDR_ACCEPTLANGUAGE_T:
			case HDR_ORGANIZATION_T:
			case HDR_PRIORITY_T:
			case HDR_SUBJECT_T:
			case HDR_USERAGENT_T:
			case HDR_ACCEPTDISPOSITION_T:
			case HDR_CONTENTDISPOSITION_T:
			case HDR_DIVERSION_T:
			case HDR_RPID_T:
			case HDR_REFER_TO_T:
			case HDR_SESSION_EXPIRES_T:
			case HDR_MIN_SE_T:
			case HDR_PPI_T:
			case HDR_PAI_T:
			case HDR_PRIVACY_T:
			case HDR_RETRY_AFTER_T:
				/* we ignore them for now even if they have something parsed*/
				break;

			default:
				if (hdr->parsed) {
					LM_WARN("header body ignored: %d\n", hdr->type );
				}
				break;
		}/*switch*/
	}/*for all headers*/

	/* length of the data lump structures */
#define LUMP_LIST_LEN(len, list) \
do { \
        struct lump* tmp, *chain; \
	chain = (list); \
	while (chain) \
	{ \
		(len) += lump_len(chain); \
		tmp = chain->before; \
		while ( tmp ) \
		{ \
			(len) += lump_len( tmp ); \
			tmp = tmp->before; \
		} \
		tmp = chain->after; \
		while ( tmp ) \
		{ \
			(len) += lump_len( tmp ); \
			tmp = tmp->after; \
		} \
		chain = chain->next; \
	} \
} while(0);

	LUMP_LIST_LEN(len, org_msg->add_rm);
	LUMP_LIST_LEN(len, org_msg->body_lumps);
	
	/*length of reply lump structures*/
	for(rpl_lump=org_msg->reply_lump;rpl_lump;rpl_lump=rpl_lump->next)
			len+=ROUND4(sizeof(struct lump_rpl))+ROUND4(rpl_lump->text.len);

	p=(char *)shm_malloc(len);
	if (!p)
	{
		LM_ERR("no more share memory\n" );
		return 0;
	}
	if (sip_msg_len)
		*sip_msg_len = len;

	/* filling up the new structure */
	new_msg = (struct sip_msg*)p;
	/* sip msg structure */
	memcpy( new_msg , org_msg , sizeof(struct sip_msg) );

	/* avoid copying pointer to un-clonned structures */
	new_msg->sdp = 0;

	new_msg->msg_flags |= FL_SHM_CLONE;
	p += ROUND4(sizeof(struct sip_msg));
	new_msg->add_rm = 0;
	new_msg->body_lumps = 0;
	/* new_uri */
	if (org_msg->new_uri.s && org_msg->new_uri.len)
	{
		new_msg->new_uri.s = p;
		memcpy( p , org_msg->new_uri.s , org_msg->new_uri.len);
		p += ROUND4(org_msg->new_uri.len);
	}
	/* dst_uri to zero */
	new_msg->dst_uri.s = 0;
	new_msg->dst_uri.len = 0;
	/* path_vec to zero */
	new_msg->path_vec.s = 0;
	new_msg->path_vec.len = 0;
	/* message buffers(org and scratch pad) */
	memcpy( p , org_msg->buf, org_msg->len);
	/* ZT to be safer */
	*(p+org_msg->len)=0;
	new_msg->buf = p;
	p += ROUND4(new_msg->len+1);
	/* unparsed and eoh pointer */
	new_msg->unparsed = translate_pointer(new_msg->buf ,org_msg->buf,
		org_msg->unparsed );
	new_msg->eoh = translate_pointer(new_msg->buf,org_msg->buf,org_msg->eoh);
	/* first line, updating the pointers*/
	if ( org_msg->first_line.type==SIP_REQUEST )
	{
		new_msg->first_line.u.request.method.s =
			translate_pointer( new_msg->buf , org_msg->buf ,
			org_msg->first_line.u.request.method.s );
		new_msg->first_line.u.request.uri.s =
			translate_pointer( new_msg->buf , org_msg->buf ,
			org_msg->first_line.u.request.uri.s );
		new_msg->first_line.u.request.version.s =
			translate_pointer( new_msg->buf , org_msg->buf ,
			org_msg->first_line.u.request.version.s );
		if(new_msg->parsed_orig_ruri_ok)
			uri_trans(new_msg->buf, org_msg->buf, &new_msg->parsed_orig_ruri);
		if(new_msg->parsed_uri_ok) {
			if (new_msg->new_uri.s) {
				/* uri string in a separate buffer */
				uri_trans(new_msg->new_uri.s, org_msg->new_uri.s,
					&new_msg->parsed_uri);
			} else {
				/* uri string still in buf */
				uri_trans(new_msg->buf, org_msg->buf, &new_msg->parsed_uri);
			}
		}
	}
	else if ( org_msg->first_line.type==SIP_REPLY )
	{
		new_msg->first_line.u.reply.version.s =
			translate_pointer( new_msg->buf , org_msg->buf ,
			org_msg->first_line.u.reply.version.s );
		new_msg->first_line.u.reply.status.s =
			translate_pointer( new_msg->buf , org_msg->buf ,
			org_msg->first_line.u.reply.status.s );
		new_msg->first_line.u.reply.reason.s =
			translate_pointer( new_msg->buf , org_msg->buf ,
			org_msg->first_line.u.reply.reason.s );
	}

	/*headers list*/
	new_msg->via1=0;
	new_msg->via2=0;
	for( hdr=org_msg->headers,last_hdr=0 ; hdr ; hdr=hdr->next )
	{
		new_hdr = (struct hdr_field*)p;
		memcpy(new_hdr, hdr, sizeof(struct hdr_field) );
		p += ROUND4(sizeof( struct hdr_field));
		new_hdr->name.s = translate_pointer(new_msg->buf, org_msg->buf,
			hdr->name.s);
		new_hdr->body.s = translate_pointer(new_msg->buf, org_msg->buf,
			hdr->body.s);
		/* by default, we assume we don't understand this header in TM
		   and better set it to zero; if we do, we will set a specific
		   value in the following switch statement
		*/
		new_hdr->parsed=0;

		new_hdr->sibling=0;

		switch (hdr->type)
		{
			case HDR_VIA_T:
				/*fprintf(stderr,"prepare to clone via |%.*s|\n",
					via_len((struct via_body*)hdr->parsed),
					via_s((struct via_body*)hdr->parsed,org_msg));*/
				if ( !new_msg->via1 )
				{
					new_msg->h_via1 = new_hdr;
					new_msg->via1 = via_body_cloner(new_msg->buf,
						org_msg->buf, (struct via_body*)hdr->parsed, &p);
					new_hdr->parsed  = (void*)new_msg->via1;
					/*fprintf(stderr,"setting via1 |%.*s|\n",
						via_len(new_msg->via1),
						via_s(new_msg->via1,new_msg));*/
					if ( new_msg->via1->next )
						new_msg->via2 = new_msg->via1->next;
				}
				else if ( !new_msg->via2 )
				{
					LINK_SIBLING_HEADER(h_via1, new_hdr);
					new_msg->h_via2 = new_hdr;
					new_msg->via2 = via_body_cloner( new_msg->buf,
						org_msg->buf, (struct via_body*)hdr->parsed, &p);
					new_hdr->parsed  = (void*)new_msg->via2;
				}
				else
				{
					LINK_SIBLING_HEADER(h_via1, new_hdr);
					new_hdr->parsed =  
						via_body_cloner( new_msg->buf , org_msg->buf ,
						(struct via_body*)hdr->parsed , &p);
				}
				break;
			case HDR_CSEQ_T:
				new_hdr->parsed = p;
				p +=ROUND4(sizeof(struct cseq_body));
				memcpy(new_hdr->parsed, hdr->parsed, sizeof(struct cseq_body));
				((struct cseq_body*)new_hdr->parsed)->number.s =
					translate_pointer(new_msg->buf ,org_msg->buf,
					((struct cseq_body*)hdr->parsed)->number.s );
				((struct cseq_body*)new_hdr->parsed)->method.s =
					translate_pointer(new_msg->buf ,org_msg->buf,
					((struct cseq_body*)hdr->parsed)->method.s );
				if (HOOK_NOT_SET(cseq)) new_msg->cseq = new_hdr;
				break;
			case HDR_TO_T:
			case HDR_FROM_T:
				if (hdr->type == HDR_TO_T) {
					if (HOOK_NOT_SET(to)) new_msg->to = new_hdr;
				} else {
					if (HOOK_NOT_SET(from)) new_msg->from = new_hdr;
				}
				/* From header might be unparsed */
				if (!hdr->parsed) break;
				new_hdr->parsed = p;
				p +=ROUND4(sizeof(struct to_body));
				memcpy(new_hdr->parsed, hdr->parsed, sizeof(struct to_body));
				((struct to_body*)new_hdr->parsed)->body.s =
					translate_pointer( new_msg->buf , org_msg->buf ,
					((struct to_body*)hdr->parsed)->body.s );
				((struct to_body*)new_hdr->parsed)->uri.s =
					translate_pointer( new_msg->buf , org_msg->buf ,
					((struct to_body*)hdr->parsed)->uri.s );
				if ( ((struct to_body*)hdr->parsed)->display.s )
					((struct to_body*)new_hdr->parsed)->display.s =
						translate_pointer( new_msg->buf , org_msg->buf ,
						((struct to_body*)hdr->parsed)->display.s );
				if ( ((struct to_body*)hdr->parsed)->tag_value.s )
					((struct to_body*)new_hdr->parsed)->tag_value.s =
						translate_pointer( new_msg->buf , org_msg->buf ,
						((struct to_body*)hdr->parsed)->tag_value.s );
				if ( (((struct to_body*)new_hdr->parsed)->parsed_uri.user.s)
				|| (((struct to_body*)new_hdr->parsed)->parsed_uri.host.s) )
					uri_trans(new_msg->buf, org_msg->buf,
							&((struct to_body*)new_hdr->parsed)->parsed_uri);

				/*to params*/
				to_prm = ((struct to_body*)(hdr->parsed))->param_lst;
				for(;to_prm;to_prm=to_prm->next)
				{
					/*alloc*/
					new_to_prm = (struct to_param*)p;
					p +=ROUND4(sizeof(struct to_param ));
					/*coping*/
					memcpy( new_to_prm, to_prm, sizeof(struct to_param ));
					((struct to_body*)new_hdr->parsed)->param_lst = 0;
					new_to_prm->name.s = translate_pointer( new_msg->buf,
						org_msg->buf , to_prm->name.s );
					new_to_prm->value.s = translate_pointer( new_msg->buf,
						org_msg->buf , to_prm->value.s );
					/*linking*/
					if ( !((struct to_body*)new_hdr->parsed)->param_lst )
						((struct to_body*)new_hdr->parsed)->param_lst
							= new_to_prm;
					else
						((struct to_body*)new_hdr->parsed)->last_param->next
							= new_to_prm;
					((struct to_body*)new_hdr->parsed)->last_param
						= new_to_prm;
				}
				break;
			case HDR_CALLID_T:
				if (HOOK_NOT_SET(callid)) {
					new_msg->callid = new_hdr;
				}
				break;
			case HDR_CONTACT_T:
				if (HOOK_NOT_SET(contact)) {
					new_msg->contact = new_hdr;
				} else {
					LINK_SIBLING_HEADER(contact, new_hdr);
				}
				break;
			case HDR_MAXFORWARDS_T :
				if (HOOK_NOT_SET(maxforwards)) {
					new_msg->maxforwards = new_hdr;
				}
				break;
			case HDR_ROUTE_T :
				if (HOOK_NOT_SET(route)) {
					new_msg->route = new_hdr;
				} else {
					LINK_SIBLING_HEADER(route, new_hdr);
				}
				break;
			case HDR_RECORDROUTE_T :
				if (HOOK_NOT_SET(record_route)) {
					new_msg->record_route = new_hdr;
				} else {
					LINK_SIBLING_HEADER(record_route, new_hdr);
				}
				break;
			case HDR_PATH_T :
				if (HOOK_NOT_SET(path)) {
					new_msg->path = new_hdr;
				} else {
					LINK_SIBLING_HEADER(path, new_hdr);
				}
				break;
			case HDR_CONTENTLENGTH_T :
				if (HOOK_NOT_SET(content_length)) {
					new_msg->content_length = new_hdr;
					new_msg->content_length->parsed = hdr->parsed;
				}
				break;
			case HDR_AUTHORIZATION_T :
				if (HOOK_NOT_SET(authorization)) {
					new_msg->authorization = new_hdr;
				} else {
					LINK_SIBLING_HEADER(authorization, new_hdr);
				}
				if (hdr->parsed) {
					new_hdr->parsed = auth_body_cloner(new_msg->buf ,
						org_msg->buf , (struct auth_body*)hdr->parsed , &p);
				}
				break;
			case HDR_EXPIRES_T :
				if (HOOK_NOT_SET(expires)) {
					new_msg->expires = new_hdr;
				}
				break;
			case HDR_PROXYAUTH_T :
				if (HOOK_NOT_SET(proxy_auth)) {
					new_msg->proxy_auth = new_hdr;
				} else {
					LINK_SIBLING_HEADER(proxy_auth, new_hdr);
				}
				if (hdr->parsed) {
					new_hdr->parsed = auth_body_cloner(new_msg->buf ,
						org_msg->buf , (struct auth_body*)hdr->parsed , &p);
				}
				break;
			case HDR_SUPPORTED_T :
				if (HOOK_NOT_SET(supported)) {
					new_msg->supported = new_hdr;
				} else {
					LINK_SIBLING_HEADER(supported, new_hdr);
				}
				break;
			case HDR_PROXYREQUIRE_T :
				if (HOOK_NOT_SET(proxy_require)) {
					new_msg->proxy_require = new_hdr;
				} else {
					LINK_SIBLING_HEADER(proxy_require, new_hdr);
				}
				break;
			case HDR_UNSUPPORTED_T :
				if (HOOK_NOT_SET(unsupported)) {
					new_msg->unsupported = new_hdr;
				} else {
					LINK_SIBLING_HEADER(unsupported, new_hdr);
				}
				break;
			case HDR_ALLOW_T :
				if (HOOK_NOT_SET(allow)) {
					new_msg->allow = new_hdr;
				} else {
					LINK_SIBLING_HEADER(allow, new_hdr);
				}
				break;
			case HDR_EVENT_T:
				if (HOOK_NOT_SET(event)) {
					new_msg->event = new_hdr;
				} else {
					LINK_SIBLING_HEADER(event, new_hdr);
				}
				break;

			case HDR_CONTENTTYPE_T:
				if (HOOK_NOT_SET(content_type)) {
					new_msg->content_type = new_hdr;
				} else {
					LINK_SIBLING_HEADER(content_type, new_hdr);
				}
				break;
				
			case HDR_ACCEPT_T:
				if (HOOK_NOT_SET(accept)) {
					new_msg->accept = new_hdr;
				} else {
					LINK_SIBLING_HEADER(accept, new_hdr);
				}
				break;
			case HDR_ACCEPTLANGUAGE_T:
				if (HOOK_NOT_SET(accept_language)) {
					new_msg->accept_language = new_hdr;
				} else {
					LINK_SIBLING_HEADER(accept_language, new_hdr);
				}
				break;
			case HDR_ORGANIZATION_T:
				if (HOOK_NOT_SET(organization)) {
					new_msg->organization = new_hdr;
				}
				break;
			case HDR_PRIORITY_T:
				if (HOOK_NOT_SET(priority)) {
					new_msg->priority = new_hdr;
				}
				break;
			case HDR_SUBJECT_T:
				if (HOOK_NOT_SET(subject)) {
					new_msg->subject = new_hdr;
				}
				break;
			case HDR_USERAGENT_T:
				if (HOOK_NOT_SET(user_agent)) {
					new_msg->user_agent = new_hdr;
				}
				break;
			case HDR_ACCEPTDISPOSITION_T:
				if (HOOK_NOT_SET(accept_disposition)) {
					new_msg->accept_disposition = new_hdr;
				} else {
					LINK_SIBLING_HEADER(accept_disposition, new_hdr);
				}
				break;
			case HDR_CONTENTDISPOSITION_T:
				if (HOOK_NOT_SET(content_disposition)) {
					new_msg->content_disposition = new_hdr;
				}
				break;
			case HDR_DIVERSION_T:
				if (HOOK_NOT_SET(diversion)) {
					new_msg->diversion = new_hdr;
				} else {
					LINK_SIBLING_HEADER(diversion, new_hdr);
				}
				break;
			case HDR_RPID_T:
				if (HOOK_NOT_SET(rpid)) {
					new_msg->rpid = new_hdr;
				}
				break;
			case HDR_REFER_TO_T:
				if (HOOK_NOT_SET(refer_to)) {
					new_msg->refer_to = new_hdr;
				}
				break;
			case HDR_SESSION_EXPIRES_T:
				if (HOOK_NOT_SET(session_expires)) {
					new_msg->session_expires = new_hdr;
				}
				break;
			case HDR_MIN_SE_T:
				if (HOOK_NOT_SET(min_se)) {
					new_msg->min_se = new_hdr;
				}
				break;
			case HDR_PPI_T:
				if (HOOK_NOT_SET(ppi)) {
					new_msg->ppi = new_hdr;
				}
				break;
			case HDR_PAI_T:
				if (HOOK_NOT_SET(pai)) {
					new_msg->pai = new_hdr;
				}
				break;
			case HDR_PRIVACY_T:
				if (HOOK_NOT_SET(privacy)) {
					new_msg->privacy = new_hdr;
				}
				break;
			default:
				/* ignore the rest*/
				;
		}/*switch*/

		if ( last_hdr )
		{
			last_hdr->next = new_hdr;
			last_hdr=last_hdr->next;
		}
		else
		{
			last_hdr=new_hdr;
			new_msg->headers =new_hdr;
		}
		last_hdr->next = 0;
		new_msg->last_header = last_hdr;
	}

	/* cloning data lump */
#define CLONE_LUMP_LIST(anchor, list) \
do { \
	struct lump* lump_tmp, *l; \
	struct lump** lump_anchor2, **a; \
	a = (anchor); \
	l = (list); \
	while (l) \
	{ \
		lump_clone( (*a) , l , p ); \
		/*before list*/ \
		lump_tmp = l->before; \
		lump_anchor2 = &((*a)->before); \
		while ( lump_tmp ) \
		{ \
			lump_clone( (*lump_anchor2) , lump_tmp , p ); \
			lump_anchor2 = &((*lump_anchor2)->before); \
			lump_tmp = lump_tmp->before; \
		} \
		/*after list*/ \
		lump_tmp = l->after; \
		lump_anchor2 = &((*a)->after); \
		while ( lump_tmp ) \
		{ \
			lump_clone( (*lump_anchor2) , lump_tmp , p ); \
			lump_anchor2 = &((*lump_anchor2)->after); \
			lump_tmp = lump_tmp->after; \
		} \
		a = &((*a)->next); \
		l = l->next; \
	} \
} while(0)

	CLONE_LUMP_LIST(&(new_msg->add_rm), org_msg->add_rm);
	CLONE_LUMP_LIST(&(new_msg->body_lumps), org_msg->body_lumps);

	/*cloning reply lump structures*/
	rpl_lump_anchor = &(new_msg->reply_lump);
	for(rpl_lump=org_msg->reply_lump;rpl_lump;rpl_lump=rpl_lump->next)
	{
		*(rpl_lump_anchor)=(struct lump_rpl*)p;
		p+=ROUND4(sizeof( struct lump_rpl ));
		(*rpl_lump_anchor)->flags = LUMP_RPL_SHMEM |
			(rpl_lump->flags&(~(LUMP_RPL_NODUP|LUMP_RPL_NOFREE)));
		(*rpl_lump_anchor)->text.len = rpl_lump->text.len;
		(*rpl_lump_anchor)->text.s=p;
		p+=ROUND4(rpl_lump->text.len);
		memcpy((*rpl_lump_anchor)->text.s,rpl_lump->text.s,rpl_lump->text.len);
		(*rpl_lump_anchor)->next=0;
		rpl_lump_anchor = &((*rpl_lump_anchor)->next);
	}

	if (clone_authorized_hooks(new_msg, org_msg) < 0) {
		shm_free(new_msg);
		return 0;
	}

	return new_msg;
}





