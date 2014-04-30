/* $OpenLDAP: pkg/ldap/servers/slapd/back-perl/modrdn.c,v 1.20.2.4 2007/01/02 21:44:06 kurt Exp $ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2007 The OpenLDAP Foundation.
 * Portions Copyright 1999 John C. Quillan.
 * Portions Copyright 2002 myinternet Limited.
 * Portions Copyright 2007 Dagobert Michelsen, Baltic Online Computer GmbH.
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

#include "perl_back.h"

typedef struct pb_op {
	char *pbo_perl_method_name;
	char *pbo_no_perl_method_error;
	void (*pbo_stack_prepare)( pTHX_ pSP_ Operation *op, SlapReply *rs );
	void (*pbo_stack_process)( pTHX_ pSP_ Operation *op, SlapReply *rs, I32 count );
} PerlBackendOperation;

/*
 * NOTE: keep in sync with slap_op_t in slapd.h
 */
static PerlBackendOperation pb_op_table[] = {
	{ "bind", "No Perl bind method", &pb_stack_prepare_bind, NULL },
	{ "unbind", "No Perl unbind method", NULL, NULL },
	{ "add", "No Perl add method", &pb_stack_prepare_add, NULL },
	{ "delete", "No Perl delete method", &pb_stack_prepare_delete, NULL },
	{ "modrdn", "No Perl modrdn method", &pb_stack_prepare_modrdn, NULL },
	{ "modify", "No Perl modify method", &pb_stack_prepare_modify, NULL },
	{ "compare", "No Perl compare method", &pb_stack_prepare_compare, NULL },
	{ "search", "No Perl search method", &pb_stack_prepare_search, &pb_stack_process_search },
	{ NULL, NULL, NULL, NULL },				/* SLAP_OP_ABANDON */
	{ "extended", "No Perl extended method", &pb_stack_prepare_extended, NULL },
	{ NULL, NULL, NULL, NULL }				/* SLAP_OP_LAST */
};

int
perl_back_operation(
	Operation *op,
	SlapReply *rs )
{
	PerlBackendDatabase *pbdb = (PerlBackendDatabase *) op->o_bd->be_private;
	PerlInterpreterPool *pool = pbdb->pbdb_perl_interpreter_pool;
	PerlInterpreterContext *pic = pb_get_connection_context( pool, op->o_conn );
	PerlBackendOperation *pbo = &pb_op_table[ slap_req2op( op->o_tag ) ];
	dTHXa( pic->pic_perl_interpreter );

	/*
	 * perl_back_operation must only be set in bi_op_* if perl method name  is defined
	 */
	assert( pbo->pbo_perl_method_name != NULL );
	assert( pbo->pbo_no_perl_method_error != NULL );
 
	PERL_SET_CONTEXT( pic->pic_perl_interpreter );
 
	ldap_pvt_thread_mutex_lock( &pic->pic_perl_interpreter_mutex );

	if( pic->pic_conn_sv && gv_fetchmethod( SvSTASH( SvRV( pic->pic_conn_sv ) ), pbo->pbo_perl_method_name ) == NULL ||
	    !pic->pic_conn_sv && gv_fetchmethod( gv_stashpv( pool->pip_module_name, 0 ), pbo->pbo_perl_method_name ) == NULL ) {
		rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		rs->sr_text = pbo->pbo_no_perl_method_error;
	} else {
		dSP; ENTER; SAVETMPS;
		ber_int_t rc;
		I32 count;

		PUSHMARK( sp ) ;

		if( pic->pic_conn_sv != NULL ) {
			XPUSHs( pic->pic_conn_sv );
		}

		if( pbo->pbo_stack_prepare != NULL ) {
			(*pbo->pbo_stack_prepare)( aTHX_ aSP_ op, rs );
		}
 
		push_opheader( op->o_hdr );
		push_connection( op->o_hdr->oh_conn );

		PUTBACK;

                if( pic->pic_conn_sv != NULL ) {
			/* use connection object to call method */
#ifdef PERL_IS_5_6
			count = call_method( pbo->pbo_perl_method_name, G_EVAL | G_ARRAY );
#else
			count = perl_call_method( pbo->pbo_perl_method_name, G_EVAL | G_ARRAY );
#endif
		} else {
			/* no connection object, use functional interface */
			char func[ SLAP_TEXT_BUFLEN ];
			snprintf( func, SLAP_TEXT_BUFLEN, "%s::%s", pool->pip_module_name, pbo->pbo_perl_method_name );
#ifdef PERL_IS_5_6
			count = call_pv( func, G_EVAL | G_ARRAY );
#else
			count = perl_call_pv( func, G_EVAL | G_ARRAY );
#endif
		}

		SPAGAIN;

		if( SvTRUE( ERRSV ) ) {
			rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
			rs->sr_text = SvPV_nolen( ERRSV );
			POPs;
		} else if( count < 1 ) {
			rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
			rs->sr_text = "The called Perl function did not return a value";
		} else {
			if( pbo->pbo_stack_process != NULL ) {
				(*pbo->pbo_stack_process)( aTHX_ aSP_ op, rs, count );
			}
			convert_retval( aTHX_ POPs, rs );
		}

		PUTBACK; FREETMPS; LEAVE;
	}

	ldap_pvt_thread_mutex_unlock( &pic->pic_perl_interpreter_mutex );

	send_ldap_result( op, rs );

	return 0;
}

