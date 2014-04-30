/* $OpenLDAP: pkg/ldap/servers/slapd/back-perl/bind.c,v 1.17.2.5 2004/04/28 23:23:16 kurt Exp $ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2004 The OpenLDAP Foundation.
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


PerlInterpreterContext *
pb_get_connection_context(
	PerlInterpreterPool *pool,
	Connection *c )
{
	if( pool->pip_conn_interpreters[ c->c_conn_idx ] == NULL ) {
		PerlInterpreterContext *pic = pb_pool_getcontext( pool );
		dTHXa( pic->pic_perl_interpreter );

		pool->pip_conn_interpreters[ c->c_conn_idx ] = pic;

		PERL_SET_CONTEXT( pic->pic_perl_interpreter );

		ldap_pvt_thread_mutex_lock( &pic->pic_perl_interpreter_mutex );
fprintf( stderr, "M: %s ID: %d pool: %lx\n", pool->pip_module_name, c->c_conn_idx, pool );

		if( pic->pic_conn_sv && gv_fetchmethod( SvSTASH( SvRV( pic->pic_conn_sv ) ), "connection_init" ) == NULL ||
		    !pic->pic_conn_sv && gv_fetchmethod( gv_stashpv( pool->pip_module_name, 0 ), "connection_init" ) == NULL ) {
			/* It is okay to not have a connection init method */
		} else {
			int count;
			dSP; ENTER; SAVETMPS;

	 		PUSHMARK(SP);
			XPUSHs( pic->pic_base_sv );
			push_connection( c );

			PUTBACK;

			if( pic->pic_conn_sv ) {
#ifdef PERL_IS_5_6
				count = call_method( "connection_init", G_SCALAR );
#else
				count = perl_call_method( "connection_init", G_SCALAR );
#endif
			} else {
				char func[ 256 ];
				snprintf( func, 256, "%s::connection_init", pool->pip_module_name );
#ifdef PERL_IS_5_6
				count = call_pv( func, G_SCALAR );
#else
				count = perl_call_pv( func, G_SCALAR );
#endif
			}

			SPAGAIN;

			if (count != 1) {
				croak("Big trouble in back_bind\n");
			}

			pic->pic_conn_sv = SvREFCNT_inc( POPs );
			if( !sv_isobject( pic->pic_conn_sv ) ) {
				croak("Method 'connection_init' did not return an object reference\n");
			}

			PUTBACK; FREETMPS; LEAVE;
		}
		ldap_pvt_thread_mutex_unlock( &pic->pic_perl_interpreter_mutex );
	}

	return pool->pip_conn_interpreters[ c->c_conn_idx ];
}

int
perl_back_connection_init(
	BackendDB *be,
	Connection *c )

{
	PerlInterpreterPool *pool = ((PerlBackendDatabase *) be->be_private)->pbdb_perl_interpreter_pool;
	if( !pool->pip_lazy_connection_init ) {
		pb_get_connection_context( pool, c );
	}
	return 0;
}


/**********************************************************
 *
 * Connection Destroy
 *
 **********************************************************/
int
perl_back_connection_destroy(
	BackendDB *be,
	Connection *c )
{
	PerlInterpreterPool *pool = ((PerlBackendDatabase *) be->be_private)->pbdb_perl_interpreter_pool;
	PerlInterpreterContext *pic = pool->pip_conn_interpreters[ c->c_conn_idx ];

	/*
	 * If this pool has lazy connections enabled and the operation went to another
	 * pool there may be no interpreter context.
	 */
	if( pic == NULL ) {
		return 0;
	}

	dTHXa( pic->pic_perl_interpreter );

	PERL_SET_CONTEXT( pic->pic_perl_interpreter );

	ldap_pvt_thread_mutex_lock( &pic->pic_perl_interpreter_mutex );

	if( pic->pic_conn_sv && gv_fetchmethod( SvSTASH( SvRV( pic->pic_conn_sv ) ), "connection_destroy" ) == NULL ||
	    !pic->pic_conn_sv && gv_fetchmethod( gv_stashpv( pool->pip_module_name, 0 ), "connection_destroy" ) == NULL ) {
		/* It is okay not to have a connection_destroy method */
		fprintf( stderr, "No Perl connection_destroy method\n" );
	} else {
		int count;
		dSP; ENTER; SAVETMPS;

		PUSHMARK(SP);
		XPUSHs( pic->pic_conn_sv );
		push_connection( c );

		PUTBACK;

		if( pic->pic_conn_sv ) {
#ifdef PERL_IS_5_6
			count = call_method( "connection_destroy", G_SCALAR );
#else
			count = perl_call_method( "connection_destroy", G_SCALAR );
#endif
		} else {
			char func[ 256 ];
			snprintf( func, 256, "%s::connection_destroy", pool->pip_module_name );
#ifdef PERL_IS_5_6
			count = call_pv( func, G_SCALAR );
#else
			count = perl_call_pv( func, G_SCALAR );
#endif
		}

		SPAGAIN;

		SvREFCNT_dec( pic->pic_conn_sv );
		pic->pic_conn_sv = NULL;

		pb_pool_putcontext( pool, pic );

		PUTBACK; FREETMPS; LEAVE;
	}
	pool->pip_conn_interpreters[ c->c_conn_idx ] = NULL;

	ldap_pvt_thread_mutex_unlock( &pic->pic_perl_interpreter_mutex );
	fprintf( stderr, "Perl connection destroy done\n" );

	return 0;
}

