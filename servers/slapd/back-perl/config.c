/* $OpenLDAP: pkg/ldap/servers/slapd/back-perl/config.c,v 1.20.2.3 2007/01/02 21:44:06 kurt Exp $ */
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

#include "config.h"

enum {
	PB_ARG_POOL_NAME = 1,
	PB_ARG_PERL_MODULE_PATH,
	PB_ARG_PERL_MODULE_NAME,
	PB_ARG_MAX_IDLE_INTERPRETERS,
	PB_ARG_MAX_INTERPRETER_USAGE_COUNT,
	PB_ARG_LAZY_CONNECTION_INIT,
	PB_ARG_SINGLE_THREADED,
	PB_ARG_FILTER_SEARCH_RESULTS,
	PB_ARG_FORCE_PENDING_CHANGES
};

static ConfigDriver pb_config;

static ConfigTable pb_cfats[] = {
	{ "pool-name", "pool",
		2, 2, 0, ARG_STRING | ARG_MAGIC | PB_ARG_POOL_NAME, (void *) pb_config,
		"( OLcfgDbAt:11.1 NAME 'olcPBPoolName' "
		"DESC 'Name of Perl interpreter pool' "
		"EQUALITY caseExactMatch "
		"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "perl-module-path", "directory",
		2, 2, 0, ARG_STRING | ARG_MAGIC | PB_ARG_PERL_MODULE_PATH, (void *) pb_config,
		"( OLcfgDbAt:11.2 NAME 'olcPBPerlModulePath' "
		"DESC 'Path to Perl module' "
		"EQUALITY caseExactIA5Match "
		"SYNTAX OMsyn:26 SINGLE-VALUE )", NULL, NULL },
	{ "perl-module-name", "name",
		2, 2, 0, ARG_STRING | ARG_MAGIC | PB_ARG_PERL_MODULE_NAME, (void *) pb_config,
		"( OLcfgDbAt:11.3 NAME 'olcPBPerlModuleName' "
		"DESC 'Name of Perl module' "
		"EQUALITY caseExactIA5Match "
		"SYNTAX OMsyn:26 SINGLE-VALUE )", NULL, NULL },
	{ "max-idle-interpreters", "count",
		2, 2, 0, ARG_INT | ARG_MAGIC | PB_ARG_MAX_IDLE_INTERPRETERS, (void *) pb_config,
		"( OLcfgDbAt:11.4 NAME 'olcPBMaxIdleInterpreters' "
		"DESC 'Maximum count of idle Perl interpreters' "
		"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "max-interpreter-usage-count", "count",
		2, 2, 0, ARG_INT | ARG_MAGIC | PB_ARG_MAX_INTERPRETER_USAGE_COUNT, (void *) pb_config,
		"( OLcfgDbAt:11.5 NAME 'olcPBMaxInterpreterUsageCount' "
		"DESC 'Maximum number of times a Perl interpreter can be reused before recycling' "
		"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "lazy-connection-init", "mode",
		2, 2, 0, ARG_ON_OFF | ARG_MAGIC | PB_ARG_LAZY_CONNECTION_INIT, (void *) pb_config,
		"( OLcfgDbAt:11.6 NAME 'olcPBLazyConnectionInit' "
		"DESC 'Enable lazy connection initialization' "
		"SYNTAX OMsBoolean SINGLE-VALUE )", NULL, NULL },
	{ "single-threaded", "mode",
		2, 2, 0, ARG_ON_OFF | ARG_MAGIC | PB_ARG_SINGLE_THREADED, (void *) pb_config,
		"( OLcfgDbAt:11.7 NAME 'olcPBSingleThreaded' "
		"DESC 'Use only a single Perl interpreter in a single thread' "
		"SYNTAX OMsBoolean SINGLE-VALUE )", NULL, NULL },
	{ "filter-search-results", "mode",
		2, 2, 0, ARG_ON_OFF | ARG_MAGIC | PB_ARG_FILTER_SEARCH_RESULTS, (void *) pb_config,
		"( OLcfgDbAt:11.8 NAME 'olcPBFilterSearchResults' "
		"DESC 'Filter search results' "
		"SYNTAX OMsBoolean SINGLE-VALUE )", NULL, NULL },
	{ "", "",
		2, 2, 0, ARG_ON_OFF | ARG_MAGIC | PB_ARG_FORCE_PENDING_CHANGES, (void *) pb_config,
		"( OLcfgDbAt:11.9 NAME 'olcPBForcePendingChanges' "
		"DESC 'Force pending changes to the Perl interpreter pool' "
		"SYNTAX OMsBoolean SINGLE-VALUE )", NULL, NULL },
	{ NULL, NULL, 0, 0, 0, ARG_IGNORED }
};

static ConfigLDAPadd pb_config_ldap_add_backend;
static ConfigCfAdd pb_config_cf_add_backend;

static ConfigLDAPadd pb_config_ldap_add_database;
static ConfigCfAdd pb_config_cf_add_database;

static ConfigLDAPadd pb_config_ldap_add_pool;
static ConfigCfAdd pb_config_cf_add_pool;

static ConfigOCs pb_cfocs[] = {
	{ "( OLcfgBkOc:11 "
		"NAME 'olcPBBackendConfig' "
		"DESC 'Perl backend configuration' "
		"SUP olcBackendConfig )",
		Cft_Backend, pb_cfats, pb_config_ldap_add_backend, pb_config_cf_add_backend },
	{ "( OLcfgDbOc:11 "
		"NAME 'olcPBDbConfig' "
		"DESC 'Perl backend database configuration' "
		"SUP olcDatabaseConfig "
		"MAY ( olcPBPoolName $ olcPBFilterSearchResults ) )",
		Cft_Database, pb_cfats, pb_config_ldap_add_database, pb_config_cf_add_database },
	{ "( OLcfgBkOc:11.1 "
		"NAME 'olcPBPoolConfig' "
		"DESC 'Perl backend interpreter pool configuration' "
		"MUST ( olcPBPoolName $ "
			"olcPBPerlModulePath $ "
			"olcPBPerlModuleName ) "
		"MAY ( olcPBMaxIdleInterpreters $ "
			"olcPBLazyConnectionInit $ "
			"olcPBSingleThreaded ) )",
		Cft_Misc, pb_cfats, pb_config_ldap_add_pool, pb_config_cf_add_pool },
	{ NULL, 0, NULL }
};

int
perl_back_init_cf( BackendInfo *bi )
{
	int rc;

	bi->bi_cf_ocs = &pb_cfocs[ 0 ];

	rc = config_register_schema( pb_cfats, pb_cfocs );

	return rc;
}

int
perl_back_db_init_cf( BackendDB *be )
{
	/* be->be_cf_ocs = be->bd_info->bi_cf_ocs;	/* == pb_cfocs */
	be->be_cf_ocs = &pb_cfocs[ 1 ];

	return 0;
}

static int
pb_config( ConfigArgs *c )
{
	int rc = 0;

	fprintf( stderr, "XXX type: %d be: %d bi: %d argc: %d op: %d entry: %d\n", c->type, c->be, c->bi, c->argc, c->op, c->ca_entry );

	if( c->op == SLAP_CONFIG_EMIT ) {
		fprintf( stderr, "emit 1\n" );
//		return 0;
		PerlBackendDatabase *pbdb = (PerlBackendDatabase *) c->be->be_private;
		PerlInterpreterPool *pool = pbdb->pbdb_perl_interpreter_pool;

		switch( c->type ) {
			char buf[ 64 ];
			struct berval bv;

			case PB_ARG_POOL_NAME:
				if( !pool->pip_pool_name ) { return 1; }
				c->value_string = strdup( pool->pip_pool_name );
				rc = 0;
				break;
		}
		return rc;
	} else if( c->op == LDAP_MOD_DELETE ) {
		return rc;
	} 

	/* Parameter set in config file */
	if( c->type == PB_ARG_POOL_NAME ) {
		if( c->bi ) {
			/* create new pool and put prepend it to the list of interpreter pools */
			/* XXX: check if MULTIPLICITY is set if more than one pool is allocated */
#ifndef MULTIPLICITY
			if( pb->pb_interpreter_pools != NULL ) {
				Debug( LDAP_DEBUG_ANY, "<= pb_config "
					"ERROR: Perl has not been compiled with multiplicity "
					"and more than pool was allocated. Either compile Perl "
					"with multiplicity or use only one pool. Please "
					"note that 'single-threaded' is hardwired to 'on' "
					"also if multiplicy is not set.", 0, 0, 0 );
				return 1;
#endif
			PerlBackend *pb = (PerlBackend *) c->bi->bi_private;
			fprintf( stderr, "Making new pool %s\n", c->value_string );
			PerlInterpreterPool *pool = pb_pool_create( c->value_string );
// assert( 0 );
#if 0
			{
/*
   5141 config_build_entry( Operation *op, SlapReply *rs, CfEntryInfo *parent,
   5142 	ConfigArgs *c, struct berval *rdn, ConfigOCs *main, ConfigOCs *extra )
 */
			OperationBuffer opbuf;
			Operation *op = &opbuf.ob_op;
			struct berval rdn;

			op->o_tag = LDAP_REQ_ADD;
			op->o_callback = &cb;
			op->o_bd = configdb
			op->o_dn = olcBackend=perl,cn=config
			op->o_ndn = 
			rdn.bv_len = snprintf( c->cr_msg, SLAP_TEXT_BUFLEN, "olcPBPoolName=%s", pool->pip_pool_name );
			rdn.bv_val = c->cr_msg;
			e = config_build_entry( op, &rs, ceparent, &c, &rdn, &CFOC_BACKEND,
				&pb_cfocs[1] );
			}
#endif

			LDAP_SLIST_INSERT_HEAD( &pb->pb_interpreter_pools, pool, pip_next );

			return 0;
		} else if( c->be ) {
			/* find pool with the given name and remember it */
			PerlBackendDatabase *pbdb = (PerlBackendDatabase *) c->be->be_private;
			PerlBackend *pb = (PerlBackend *) c->be->bd_info->bi_private;
			PerlInterpreterPool *pool;

			if( pbdb->pbdb_perl_interpreter_pool ) {
				Debug( LDAP_DEBUG_ANY, "<= pb_config "
					"ERROR: Trying to assign another pool to "
					"a database where the pool '%s' has already been assigned\n",
					pbdb->pbdb_perl_interpreter_pool->pip_pool_name, 0, 0 );
				return 1;
			}
			LDAP_SLIST_FOREACH( pool, &pb->pb_interpreter_pools, pip_next ) {
				if( strcmp( c->value_string, pool->pip_pool_name ) == 0 ) {
					Debug( LDAP_DEBUG_ANY, "Assigning pool '%s'\n", c->value_string, 0, 0 );
					if( pool->pip_base_context == NULL ) {
						pb_pool_initialize( pool );
					}
					pbdb->pbdb_perl_interpreter_pool = pool;

					PerlInterpreterContext *pic = pool->pip_base_context;
					dTHXa( pic->pic_perl_interpreter );
					PERL_SET_CONTEXT( pic->pic_perl_interpreter );

					ldap_pvt_thread_mutex_lock( &pic->pic_perl_interpreter_mutex );

					if( gv_fetchmethod( gv_stashpv( pool->pip_module_name, 0 ), "open" ) == NULL ) {
						fprintf( stderr, "No Perl open function\n" );
						return 0;        /* It's ok to have no open method */
					} else {
					AV *av_suffix;
					BerValue *bv;
					int count;

					dSP; ENTER; SAVETMPS;
					PUSHMARK( sp );
					XPUSHs( sv_2mortal( newSVpv( pool->pip_module_name, 0 ) ) );

					XPUSHs( sv_2mortal( newSVpv( "suffix", 0 ) ) );
					av_suffix = newAV();
					for( bv = c->be->be_suffix; bv->bv_val != NULL; bv++ ) {
						av_push( av_suffix, newSVberval( bv ) );
					}
					XPUSHs( sv_2mortal( newRV_noinc( (SV *) av_suffix ) ) );

					PUTBACK;

#ifdef PERL_IS_5_6
					count = call_method( "open", G_SCALAR );
#else
					count = perl_call_method( "open", G_SCALAR );
#endif

					SPAGAIN;

					if (count != 1) {
						croak("Big trouble in config\n") ;
					}

					pic->pic_base_sv = newSVsv( POPs );

					if( !sv_isobject( pic->pic_base_sv ) ) {
						Debug( LDAP_DEBUG_ANY, "Method 'open' did not return "
							"an object reference\n", 0, 0, 0 );
					}

					PUTBACK; FREETMPS; LEAVE ;
					}

					ldap_pvt_thread_mutex_unlock( &pic->pic_perl_interpreter_mutex );



					break;
				}
			}
			if( pbdb->pbdb_perl_interpreter_pool == NULL ) {
				Debug( LDAP_DEBUG_ANY, "<= pb_config "
					"ERROR: Unable to associate the undefined pool '%s' "
					"to the database\n", c->value_string, 0, 0 );
				return 1;
			}
			return 0;
		}
	}

	/* All other parameters are specific to a pool. Make sure that one is defined */

fprintf(stderr, "1\n");
	PerlInterpreterPool *pool;
	if( c->bi ) {
		/* If c->bi is set we are in the 'backend' section */
		PerlBackend *pb = (PerlBackend *) c->bi->bi_private;
		pool = LDAP_SLIST_FIRST( &pb->pb_interpreter_pools );
	} else {
		PerlBackendDatabase *pbdb = (PerlBackendDatabase *) c->be->be_private;
		PerlBackend *pb = (PerlBackend *) c->be->bd_info->bi_private;
		/* The implicit pool name is derived from the first dn suffix of the database */
		pool = pbdb->pbdb_perl_interpreter_pool;
		if( pool == NULL ) {
			/* No explicit pool defined, use the implicit always
		 	 * present from the database */
			pool = pb_pool_create( c->be->be_suffix->bv_val );
			pbdb->pbdb_perl_interpreter_pool = pool;
			LDAP_SLIST_INSERT_HEAD( &pb->pb_interpreter_pools, pool, pip_next );

		}
	}
fprintf(stderr, "2\n");
fprintf(stderr, "3\n");
	if( pool == NULL ) {
		Debug( LDAP_DEBUG_ANY, "<= pb_config "
			"ERROR: A pool must be created before setting "
			"the Perl module path\n", 0, 0, 0 );
		return 1;
	}

	switch( c->type ) {
		case PB_ARG_PERL_MODULE_PATH:
			if( pool->pip_module_path ) {	
				/* XXX: Use c->msg[0] for error??? */
				Debug( LDAP_DEBUG_ANY, "<= pb_config "
					"ERROR: The Perl module path is already set and can "
					"only set once during initial configuration\n", 0, 0, 0 );
				return 1;
			}
			pool->pip_module_path = strdup( c->value_string );
			break;
		case PB_ARG_PERL_MODULE_NAME:
			if( pool->pip_module_path == NULL ) {
				Debug( LDAP_DEBUG_ANY, "<= pb_config "
					"ERROR: The Perl module path must be set before "
					"setting the Perl module name\n", 0, 0, 0 );
				return 1;
			}
			if( pool->pip_module_name ) {	
				/* XXX: Use c->msg[0] for error??? */
				Debug( LDAP_DEBUG_ANY, "<= pb_config "
					"ERROR: The Perl module name is already set and can "
					"only set once during initial configuration\n", 0, 0, 0 );
				return 1;
			}
			pool->pip_module_name = strdup( c->value_string );
			/* XXX: Instantiate Perl interpreter here? */
			break;
		case PB_ARG_MAX_IDLE_INTERPRETERS:
			pool->pip_max_idle_interpreters = c->value_int;
			break;
		case PB_ARG_LAZY_CONNECTION_INIT:
			pool->pip_lazy_connection_init = c->value_int;
			break;
		case PB_ARG_SINGLE_THREADED:
			/* XXX: Must be set and not changeable if ITHREADS is not set */
			pool->pip_single_threaded = c->value_int;
			break;
		case PB_ARG_FORCE_PENDING_CHANGES:
			/*
			 * activate changes like single-threaded immediately.
			 * Used interpreters are discarded immediately and connected
			 * clients receive UNWILLING TO PERFORM on all further requests.
			 */
			break;
	}


	return 0;
}

static int
perl_back_config_database( ConfigArgs *c )
{
	int rc = 0;
	PerlBackendDatabase *pdb = (PerlBackendDatabase *) c->be->be_private;

	fprintf( stderr, "type: %d\n", c->type );

	if( c->op == SLAP_CONFIG_EMIT ) {
		return rc;
	} else if( c->op == LDAP_MOD_DELETE ) {
		return rc;
	} 

	/* Parameter set in config file */
	switch( c->type ) {
		case PB_ARG_POOL_NAME: {
			/* database: reference pool defined in backend
			 */
		}
	}
	return rc;
}

/* Check if the child is allowed to be LDAPAdd'd to the parent */
static int
pb_config_ldap_add_backend(
	CfEntryInfo *parent,
	Entry *child,
	struct config_args_s *ca
) {
	fprintf( stderr, "-> pb_config_ldap_add_backend\n" );
	assert( 0 );
}

/* Let the object create children out of slapd.conf */
static int
pb_config_cf_add_backend(
	Operation *op,
	SlapReply *rs,
	Entry *parent,
	struct config_args_s *ca
) {
	/* This is never called as it is used only for overlays */
	fprintf( stderr, "-> pb_config_cf_add_backend\n" );
	assert( 0 );
}

/* Check if the child is allowed to be LDAPAdd'd to the parent */
static int
pb_config_ldap_add_pool(
	CfEntryInfo *parent,
	Entry *child,
	struct config_args_s *ca
) {
	fprintf( stderr, "-> pb_config_ldap_add_pool\n" );
	assert( 0 );
}

/* Let the object create children out of slapd.conf */
static int
pb_config_cf_add_pool(
	Operation *op,
	SlapReply *rs,
	Entry *parent,
	struct config_args_s *ca
) {
	fprintf( stderr, "-> pb_config_cf_add_pool\n" );
	assert( 0 );
}

/* Check if the child is allowed to be LDAPAdd'd to the parent */
static int
pb_config_ldap_add_database(
	CfEntryInfo *parent,
	Entry *child,
	struct config_args_s *ca
) {
	fprintf( stderr, "-> pb_config_ldap_add_database\n" );
	assert( 0 );
}

/* Let the object create children out of slapd.conf */
static int
pb_config_cf_add_database(
	Operation *op,
	SlapReply *rs,
	Entry *parent,
	struct config_args_s *ca
) {
	fprintf( stderr, "-> pb_config_cf_add_database\n" );

	/* find backend node */
	/* olcBackend=perl,cn=config */

	/* insert node for this pool if not already done */
	/* 
		"NAME 'olcPBPoolConfig' "
		"DESC 'Perl backend interpreter pool configuration' "
		"MUST ( olcPBPoolName $ "
			"olcPBPerlModulePath $ "
			"olcPBPerlModuleName ) "
		"MAY ( olcPBMaxIdleInterpreters $ "
			"olcPBLazyConnectionInit $ "
			"olcPBSingleThreaded ) )",
	*/

	/* olcPBPoolName=abc,olcBackend=perl,cn=config */
}


/**********************************************************
 *
 * Config
 *
 **********************************************************/
int
perl_back_db_config(
	 BackendDB *be,
	 const char *fname,
	 int lineno,
	 int argc,
	 char **argv
)
{
	SV* loc_sv;
	PerlBackendDatabase *pbdb = (PerlBackendDatabase *) be->be_private;
	PerlInterpreterPool *pool = pbdb->pbdb_perl_interpreter_pool;
	PerlInterpreterContext *pic = pool->pip_base_context;

fprintf( stderr, "perl_back_db_config called\n");

	if( pic == NULL ) {
		Debug( LDAP_DEBUG_ANY, "perl_back_db_config: no interpreter pool "
			"has been allocated yet\n", 0, 0, 0 );

		/* The pool is not initialized because we did not have an explicit backend
		 * definition
		 */



			/* XXX: Unify pool initialization */
					pb_pool_initialize( pool );

					pic = pool->pip_base_context;
					dTHXa( pic->pic_perl_interpreter );
					PERL_SET_CONTEXT( pic->pic_perl_interpreter );

					ldap_pvt_thread_mutex_lock( &pic->pic_perl_interpreter_mutex );

					if( gv_fetchmethod( gv_stashpv( pool->pip_module_name, 0 ), "open" ) == NULL ) {
						fprintf( stderr, "No Perl open function\n" );
						return 0;        /* It's ok to have no open method */
					} else {
					AV *av_suffix;
					BerValue *bv;
					int count;

					dSP; ENTER; SAVETMPS;
					PUSHMARK( sp );
					XPUSHs( sv_2mortal( newSVpv( pool->pip_module_name, 0 ) ) );

					XPUSHs( sv_2mortal( newSVpv( "suffix", 0 ) ) );
					av_suffix = newAV();
					for( bv = be->be_suffix; bv->bv_val != NULL; bv++ ) {
						av_push( av_suffix, newSVberval( bv ) );
					}
					XPUSHs( sv_2mortal( newRV_noinc( (SV *) av_suffix ) ) );

					PUTBACK;

#ifdef PERL_IS_5_6
					count = call_method( "open", G_SCALAR );
#else
					count = perl_call_method( "open", G_SCALAR );
#endif

					SPAGAIN;

					if (count != 1) {
						croak("Big trouble in config\n") ;
					}

					pic->pic_base_sv = newSVsv( POPs );

					if( !sv_isobject( pic->pic_base_sv ) ) {
						Debug( LDAP_DEBUG_ANY, "Method 'open' did not return "
							"an object reference\n", 0, 0, 0 );
					}

					PUTBACK; FREETMPS; LEAVE ;
					}

					ldap_pvt_thread_mutex_unlock( &pic->pic_perl_interpreter_mutex );

	pic = pool->pip_base_context;

//		return 1;
	}

	char eval_str[EVAL_BUF_SIZE];
	int count ;
	int args;
	int return_code;
	
	dTHXa( pic->pic_perl_interpreter );
        PERL_SET_CONTEXT( pic->pic_perl_interpreter );

	ldap_pvt_thread_mutex_lock( &pic->pic_perl_interpreter_mutex );

		return_code = SLAP_CONF_UNKNOWN;
		/*
		 * Pass it to Perl module if defined
		 */
		if( pic->pic_base_sv && gv_fetchmethod( SvSTASH(SvRV(pic->pic_base_sv)), "config" ) == NULL ||
		    pic->pic_base_sv == NULL && gv_fetchmethod( gv_stashpv( pool->pip_module_name, 0 ), "config" ) == NULL ) {
			fprintf( stderr, "No Perl config method\n" );
			return_code = SLAP_CONF_UNKNOWN;
		} else {
			AV *av_args;
			dSP ;  ENTER ; SAVETMPS;

			av_args = newAV();

			PUSHMARK(sp) ;
			if( pic->pic_base_sv ) {
				XPUSHs( pic->pic_base_sv );
			}

			XPUSHs( sv_2mortal( newSVpv( "file", 0 ) ) );
			XPUSHs( sv_2mortal( newSVpv( fname, 0 ) ) );

			XPUSHs( sv_2mortal( newSVpv( "line", 0 ) ) );
			XPUSHs( sv_2mortal( newSViv( lineno ) ) );

			XPUSHs( sv_2mortal( newSVpv( "args", 0 ) ) );
			for( args = 0; args < argc; args++ ) {
                        	av_push(av_args, newSVpv(argv[args], 0));
			}
			XPUSHs(sv_2mortal(newRV_noinc( (SV *) av_args)));

			PUTBACK ;

#ifdef PERL_IS_5_6
			if( pic->pic_base_sv ) {
				count = call_method( "config", G_SCALAR );
			} else {
				count = call_pv( "config", G_SCALAR );
			}
#else
			if( pic->pic_base_sv ) {
				count = perl_call_method("config", G_SCALAR);
			} else {
				count = perl_call_pv( "config", G_SCALAR );
			}
#endif

			SPAGAIN ;

			if (count != 1) {
				croak("Big trouble in config\n") ;
			}

			return_code = POPi;

			PUTBACK ; FREETMPS ;  LEAVE ;

		}

	ldap_pvt_thread_mutex_unlock( &pic->pic_perl_interpreter_mutex );


	return return_code;
}

