/* $Id$ */
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

static void perl_back_xs_init LDAP_P((PERL_BACK_XS_INIT_PARAMS));
EXT void boot_DynaLoader LDAP_P((PERL_BACK_BOOT_DYNALOADER_PARAMS));

/*
 * PerlInterpreterContext
 */

static PerlInterpreterContext *
pb_pic_clone(
	PerlInterpreterContext *pic )
{
	PerlInterpreterContext	*cloned_pic;
	SV			*cloned_sv;
	CLONE_PARAMS 	  	 clone_params;
	dTHXa( pic->pic_perl_interpreter );

	cloned_pic = (PerlInterpreterContext *) ch_malloc( sizeof(PerlInterpreterContext) );
	ldap_pvt_thread_mutex_init( &cloned_pic->pic_perl_interpreter_mutex );

	ldap_pvt_thread_mutex_lock( &pic->pic_perl_interpreter_mutex );
	PERL_SET_CONTEXT( pic->pic_perl_interpreter );
	PerlIO_flush( (PerlIO *) NULL );

	/* the pointertable is needed for sv_dup */
	cloned_pic->pic_perl_interpreter = perl_clone( pic->pic_perl_interpreter, CLONEf_KEEP_PTR_TABLE );
	aTHX = cloned_pic->pic_perl_interpreter;

	/*
	 * Duplicate the object into the new interpreter and make sure the refcount is 1.
         * (otherwise the object will not be freed and on interpreter destruction ugly
         * warning will be printed)
	 */
	clone_params.flags = 0;
	cloned_pic->pic_base_sv = SvREFCNT_inc( sv_dup( pic->pic_conn_sv, &clone_params ) );
	cloned_pic->pic_conn_sv = NULL;

	/* Clean up from CLONEf_KEEP_PTR_TABLE */
	ptr_table_free( PL_ptr_table );
	PL_ptr_table = NULL;

	ldap_pvt_thread_mutex_unlock( &pic->pic_perl_interpreter_mutex );

	return cloned_pic;
}


/*
 * pb_pic_destroy
 *
 * This function frees a PerlInterpreterContext and all associated data structures
 */

void
pb_pic_destroy(
	PerlInterpreterContext *pic )
{
	dTHXa( pic->pic_perl_interpreter );

	if( pic->pic_base_sv != NULL ) SvREFCNT_dec( pic->pic_base_sv );
	if( pic->pic_conn_sv != NULL ) SvREFCNT_dec( pic->pic_conn_sv );
	PERL_SET_CONTEXT( pic->pic_perl_interpreter );
	perl_destruct( pic->pic_perl_interpreter );
	perl_free( pic->pic_perl_interpreter );
	ldap_pvt_thread_mutex_destroy( &pic->pic_perl_interpreter_mutex );
	ch_free( pic );
}


/*
 * PerlInterpreterPool
 *
 * Invariants to each pool:
 * - pool->pip_idle_interpreters[ 0 .. pool->pip_max_idle_interpreters ] is allocated
 * - pool->pip_idle_interpreters[ 0 ] .. pool->pip_idle_interpreters[ pool->pip_idle_interpreter_count - 1 ]
 *     point to valid interpreter contexts
 */

/*
 * pb_pool_create
 *
 * This function creates a new interpreter pool. No interpreter contexts are
 * allocated.
 */

PerlInterpreterPool *
pb_pool_create( char *name )
{
	PerlInterpreterPool *pool = (PerlInterpreterPool *)
		ch_calloc( 1, sizeof(PerlInterpreterPool) );

	if( pool == NULL ) {
		Debug( LDAP_DEBUG_ANY, "<= pb_pool_create NULL "
			"(PerlInterpreterPool allocation failed)\n", 0, 0, 0 );
		return NULL;
	}
	pool->pip_pool_name = strdup( name );
	pool->pip_conn_interpreters = (PerlInterpreterContext **)
		ch_calloc( dtblsize, sizeof(PerlInterpreterContext *) );
	if( pool->pip_conn_interpreters == NULL ) {
		Debug( LDAP_DEBUG_ANY, "<= pb_pool_create NULL "
			"(pip_conn_interpreters allocation failed)\n", 0, 0, 0 );
		return NULL;
	}
	pool->pip_max_idle_interpreters = -1;
	pool->pip_max_interpreter_usage_count = -1;
	pool->pip_lazy_connection_init = -1;

	/* XXX: Force single threaded if Perl has not been compiled with ithreads */
	/* XXX: Disallow changing this parameter if ithreads are not available */
#ifndef USE_ITHREADS
	pool->pip_single_threaded = 2;	/* 2 means not changeable */
#else
	pool->pip_single_threaded = 1;
#endif

	return pool;
}


/*
 * pb_pool_initialize:
 * This function takes an existing pool and initializes a base interpreter
 */
void
pb_pool_initialize(
        PerlInterpreterPool *pool
)
{
	PerlInterpreter *pi;
	PerlInterpreterContext *pic;
	/* XXX: Get env PERL_DEBUG and concat with '-e' for second arg */
	char *perl_argv[] = { "", "-e", "0" };
	char eval_str[ EVAL_BUF_SIZE ];

	assert( pool->pip_base_context == NULL );
	assert( pool->pip_module_path );
	assert( pool->pip_module_name );

	pi = perl_alloc();
	perl_construct( pi );
	perl_parse( pi, perl_back_xs_init, 3, perl_argv, (char **) NULL );
	perl_run( pi );		/* XXX: is this necessary? */

	pic = (PerlInterpreterContext *) ch_calloc( 1, sizeof(PerlInterpreterContext) );
	pic->pic_perl_interpreter = pi;
	ldap_pvt_thread_mutex_init( &pic->pic_perl_interpreter_mutex );

	pool->pip_base_context = pic;

	dTHXa( pi );
/*
	PERL_SET_CONTEXT( pc->pc_perl_interpreter );
*/
	snprintf( eval_str, EVAL_BUF_SIZE, "push @INC, '%s';", pool->pip_module_path );
#ifdef PERL_IS_5_6
	eval_pv( eval_str, 0 );
	if( SvTRUE( ERRSV ) ) {
		fprintf( stderr , "Error %s\n", SvPV_nolen(ERRSV)) ;
	}
#else
	perl_eval_pv( eval_str, 0 );
	if( SvTRUE( GvSV( errgv ) ) ) {
		fprintf( stderr , "Error %s\n", SvPV_nolen(GvSV(errgv))) ;
	}
#endif

#ifdef PERL_IS_5_6
	snprintf( eval_str, EVAL_BUF_SIZE, "use %s;", pool->pip_module_name );
	eval_pv( eval_str, 0 );

	if (SvTRUE(ERRSV)) {
		fprintf(stderr , "Error %s\n", SvPV_nolen(ERRSV)) ;
	}
#else
	snprintf( eval_str, EVAL_BUF_SIZE, "%s.pm", pool->pip_module_name );
	perl_require_pv( eval_str );

	/* XXX: Check for init function */

	if (SvTRUE(GvSV(errgv))) {
		fprintf(stderr , "Error %s\n", SvPV(GvSV(errgv))) ;
	}
#endif /* PERL_IS_5_6 */
	else {
		int count;
		dSP;
		ENTER;
		SAVETMPS;

		PUSHMARK( sp );
		XPUSHs( sv_2mortal( newSVpv( pool->pip_module_name, 0 ) ) );

		XPUSHs( sv_2mortal( newSVpv( "dtblsize", 0 ) ) );
		XPUSHs( sv_2mortal( newSViv( dtblsize ) ) );

		PUTBACK;

#ifdef PERL_IS_5_6
		count = call_method("init", G_SCALAR);
#else
		count = perl_call_method("init", G_SCALAR);
#endif

		SPAGAIN;

#if 0
		if (count != 1) {
			croak("Big trouble in config\n") ;
		}

		pic->pic_base_sv = newSVsv( POPs );

		if( !sv_isobject( pic->pic_base_sv ) ) {
			croak("Method 'init' did not return an object reference\n");
		}
#endif
		PUTBACK; FREETMPS; LEAVE ;
	}
}


/*
 * pb_pool_set_max_idle_interpreters
 *
 * This function sets the maximum number of idle interpreters and adjusts the
 * array holding the idle interpreters accordingly.
 */

static void
pb_pool_set_max_idle_interpreters(
	PerlInterpreterPool *pool,
	int max_idle_interpreters )
{
	if( max_idle_interpreters > pool->pip_idle_interpreter_count ) {
		/* get rid of superfluous interpreters */
		while( max_idle_interpreters > pool->pip_idle_interpreter_count ) {
			pb_pic_destroy(
				 pool->pip_idle_interpreters[ --pool->pip_idle_interpreter_count ]
			);
		}
	}
	pool->pip_max_idle_interpreters = max_idle_interpreters;

	pool->pip_idle_interpreters = (PerlInterpreterContext **)
		ch_realloc(
			pool->pip_idle_interpreters,
			pool->pip_max_idle_interpreters * sizeof(PerlInterpreterContext *)
		);
	if( pool->pip_idle_interpreters == NULL ) {
		Debug( LDAP_DEBUG_ANY, "<= pb_pool_set_max_idle_interpreters NULL "
			"(pip_idle_interpreters array reallocation failed)\n", 0, 0, 0 );
		return;
	}
}

/*
 * pb_pool_destroy
 *
 * This function frees a PerlInterpreterPool and all associated Perl interpreters and
 * data structures.
 */

void
pb_pool_destroy(
	PerlInterpreterPool *pool )
{
	int i;

	if( pool->pip_pool_name ) ch_free( pool->pip_pool_name );
	if( pool->pip_module_path ) ch_free( pool->pip_module_path );
	if( pool->pip_module_name ) ch_free( pool->pip_module_name );
	
	if( pool->pip_base_context ) pb_pic_destroy( pool->pip_base_context );
	while( pool->pip_idle_interpreter_count > 0 ) {
		pb_pic_destroy( pool->pip_idle_interpreters[ pool->pip_idle_interpreter_count-- ] );
	}
	ch_free( pool->pip_idle_interpreters );
	for( i = 0; i < dtblsize; i++ ) {
		assert( pool->pip_conn_interpreters == NULL );
	}
	ch_free( pool->pip_conn_interpreters );
	ldap_pvt_thread_mutex_destroy( &pool->pip_mutex );
	ch_free( pool );

	/* XXX: remove this pool from the interpreter pool list */
}

/*
 * pb_pool_getcontext
 *
 * This function fetches an idle context from the pool or creates
 * a new context if no idle context is available.
 */

PerlInterpreterContext *
pb_pool_getcontext(
	PerlInterpreterPool *pool )
{
	PerlInterpreterContext *pic;

	ldap_pvt_thread_mutex_lock( &pool->pip_mutex );
	if( pool->pip_single_threaded ) {
		/*
		 * In a single-threaded Perl interpreter environment the interpreter is
		 * stored in pip_base_context and stays there. No allocation/deallocation.
		 */
		pic = pool->pip_base_context;
	} else if( pool->pip_idle_interpreter_count > 0 ) {
		pic = pool->pip_idle_interpreters[ --pool->pip_idle_interpreter_count ];
	} else {
		pic = pb_pic_clone( pool->pip_base_context );
	}
	pic->pic_usage_count++;
	ldap_pvt_thread_mutex_unlock( &pool->pip_mutex );

	return pic;
}

/*
 * pb_pool_putcontext
 *
 * This function takes a context and puts it back to the idle context pool
 */

void
pb_pool_putcontext(
	PerlInterpreterPool *pool,
	PerlInterpreterContext *pic )
{
	/* backend object must be freed beforehand */
	assert( pic->pic_conn_sv == NULL );

	if( pool->pip_single_threaded ) {
		/*
		 * In a single-threaded Perl interpreter environment the interpreter is
		 * stored in pip_base_context and stays there. No allocation/deallocation.
		 */
		return;
	}

	ldap_pvt_thread_mutex_lock( &pool->pip_mutex );
	if( pool->pip_idle_interpreter_count < pool->pip_max_idle_interpreters &&
	    (pool->pip_max_interpreter_usage_count < 0 ||
             pic->pic_usage_count < pool->pip_max_interpreter_usage_count) ) {
		pool->pip_idle_interpreters[ pool->pip_idle_interpreter_count++ ] = pic;
	} else {
		pb_pic_destroy( pic );
	}
	ldap_pvt_thread_mutex_unlock( &pool->pip_mutex );
}


static void
perl_back_xs_init(PERL_BACK_XS_INIT_PARAMS)
{
	char *file = __FILE__;
	dXSUB_SYS;
	newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
}
