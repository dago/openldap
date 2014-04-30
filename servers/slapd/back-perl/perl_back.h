/* $OpenLDAP: pkg/ldap/servers/slapd/back-perl/perl_back.h,v 1.13.2.3 2007/01/02 21:44:06 kurt Exp $ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2007 The OpenLDAP Foundation.
 * Portions Copyright 1999 John C. Quillan.
 * Portions Copyright 2002 myinternet Limited.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

/*
 * Data Structures
 * ---------------
 *
 * Perl Backend:
 * +- PerlBackend
 *    +-PerlContext
 *      +- SV *pc_sv		connection object
 *      +- SV *pc_base_sv	backend object cloned into this interpreter
 *      +- PerlInterpreter *pc... the Perl interpreter for the context
 *	+- ...mutex		use mutex when Perl interpreter is active
 *
 *
 * PerlContextPool:
 *   PerlContext *pcp_base_context		new contexts are cloned from this one
 *   PerlContextList *pcp_unused_contexts	this linked list stores idle contexts
 *   PerlContextList *pcp_used_contexts		this linked list stores active contexts
 *   pcp_mutex					lock this mutex when changing the context pool
 *
 * There is one Perl interpreter per backend database.
 * Each connection is identified by a unique index named c_conn_idx. For each
 * connection there is a connection context held in the global variable
 * connection_context[conn->c_conn_idx]. A connection context consists of
 * a perl interpreter.
 */

#ifndef PERL_BACK_H
#define PERL_BACK_H 1

#define PERL_NO_GET_CONTEXT     /* we want efficiency */
#include <EXTERN.h>
#include <perl.h>
#undef _	/* #defined by both Perl and ac/localize.h */
#include "asperl_undefs.h"

#include "portable.h"

#include "slap.h"

#include <ac/string.h>

LDAP_BEGIN_DECL

/*
 * From Apache mod_perl: test for Perl version.
 */

#if defined(pTHX_) || (PERL_REVISION > 5 || (PERL_REVISION == 5 && PERL_VERSION >= 6))
#define PERL_IS_5_6
#endif

#define EVAL_BUF_SIZE 500

#ifdef PERL_IS_5_6
/* We should be using the PL_errgv, I think */
/* All the old style variables are prefixed with PL_ now */
#define errgv	PL_errgv
#define na	PL_na
#endif

#if defined( HAVE_WIN32_ASPERL ) || defined( USE_ITHREADS )
#define PERL_BACK_XS_INIT_PARAMS		pTHX
#define PERL_BACK_BOOT_DYNALOADER_PARAMS	pTHX, CV *cv
#else
#define PERL_BACK_XS_INIT_PARAMS		void
#define PERL_BACK_BOOT_DYNALOADER_PARAMS	CV *cv
#endif

typedef struct perl_interpreter_context {
	SV			*pic_base_sv;		/* backend object cloned into this interpreter */
	SV			*pic_conn_sv;		/* connection object */
	int			pic_usage_count;	/* how often this context has been reused */
	PerlInterpreter		*pic_perl_interpreter;
	ldap_pvt_thread_mutex_t	pic_perl_interpreter_mutex;
} PerlInterpreterContext;

typedef struct perl_interpreter_pool {
	char			*pip_pool_name;
	char			*pip_module_path;
	char			*pip_module_name;
	PerlInterpreterContext	*pip_base_context;
	PerlInterpreterContext	**pip_idle_interpreters;
	PerlInterpreterContext	**pip_conn_interpreters;
	int			pip_idle_interpreter_count;
	int			pip_max_idle_interpreters;
	int			pip_max_interpreter_usage_count;
	int			pip_lazy_connection_init;
	int			pip_single_threaded;
	ldap_pvt_thread_mutex_t	pip_mutex;

	LDAP_SLIST_ENTRY( perl_interpreter_pool )	pip_next;
} PerlInterpreterPool;

typedef struct perl_backend_database {
	int			pbdb_filter_search_results;
	PerlInterpreterPool	*pbdb_perl_interpreter_pool;
} PerlBackendDatabase;

typedef struct perl_backend {
	LDAP_SLIST_HEAD( PerlInterpreterPoolList, perl_interpreter_pool ) pb_interpreter_pools; 	/* current pool first */
} PerlBackend;

/* pool modification functions */
extern PerlInterpreterPool *pb_pool_create( char *name );
extern void pb_pool_initialize( PerlInterpreterPool *pool );
extern PerlInterpreterContext *pb_pool_getcontext( PerlInterpreterPool *pool );
extern void pb_pool_putcontext( PerlInterpreterPool *pool, PerlInterpreterContext *pic );
extern PerlInterpreterContext *pb_get_connection_context( PerlInterpreterPool *pool, Connection *c );

#define aSP sp
#define aSP_ aSP,
#define pSP register SV **sp
#define pSP_ pSP,

/* stack modifications from operations */
extern void pb_stack_prepare_bind( pTHX_ pSP_ Operation *op, SlapReply *rs );
extern void pb_stack_prepare_add( pTHX_ pSP_ Operation *op, SlapReply *rs );
extern void pb_stack_prepare_delete( pTHX_ pSP_ Operation *op, SlapReply *rs );
extern void pb_stack_prepare_modrdn( pTHX_ pSP_ Operation *op, SlapReply *rs );
extern void pb_stack_prepare_modify( pTHX_ pSP_ Operation *op, SlapReply *rs );
extern void pb_stack_prepare_compare( pTHX_ pSP_ Operation *op, SlapReply *rs );
extern void pb_stack_prepare_search( pTHX_ pSP_ Operation *op, SlapReply *rs );
extern void pb_stack_process_search( pTHX_ pSP_ Operation *op, SlapReply *rs, I32 count );
extern void pb_stack_prepare_extended( pTHX_ pSP_ Operation *op, SlapReply *rs );

/* utility functions */
extern void convert_retval( pTHX_ SV *retval, SlapReply *rs );
extern Entry *sv2entry( pTHX_ SV *sv );
#define svpv2berval(sv,bv) (bv).bv_val=SvPV(sv,(bv).bv_len)

/* This macro takes a BerValue referece and returns the matching Perl scalar */
#define newSVberval(bv) newSVpvn( (bv)->bv_val, (bv)->bv_len )

extern void dump_entry( Entry *e );

/*
 * The push_connection  macro takes a pointer to a connection and pushes some interesting
 * fields in a hash reference on the stack.
 */

#define push_connection(c) STMT_START {						\
	HV *conn_hash = newHV();						\
	XPUSHs( sv_2mortal( newSVpv( "connection", 0 ) ) );			\
	hv_store( conn_hash, "conn_idx", STRLENOF( "conn_idx" ),		\
		newSViv( c->c_conn_idx ), 0 );					\
	hv_store( conn_hash, "peer_domain", STRLENOF( "peer_domain" ),		\
		newSVberval( &c->c_peer_domain ), 0 );				\
	hv_store( conn_hash, "peer_name", STRLENOF( "peer_name" ),		\
		 newSVberval( &c->c_peer_name ), 0 );				\
	XPUSHs( sv_2mortal( newRV( (SV*) conn_hash ) ) );			\
	} STMT_END

/*
 * The push_opheader macro takes a pointer to an operation header and pushes
 * some interesting fields in a hash.
 */

#define push_opheader(o_hdr) STMT_START {						\
	HV *hv_opheader = newHV();						\
	XPUSHs( sv_2mortal( newSVpv( "operation", 0 ) ) );			\
	hv_store( hv_opheader, "opid", STRLENOF( "opid" ),			\
		newSViv( o_hdr->oh_opid ), 0 );					\
	hv_store( hv_opheader, "connid", STRLENOF( "connid" ),			\
		 newSViv( o_hdr->oh_connid ), 0 );				\
	XPUSHs( sv_2mortal( newRV( (SV *) hv_opheader ) ) );			\
	} STMT_END

LDAP_END_DECL

#include "proto-perl.h"

#endif /* PERL_BACK_H */
