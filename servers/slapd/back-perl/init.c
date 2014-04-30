/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2013 The OpenLDAP Foundation.
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
#include "../config.h"

ldap_pvt_thread_mutex_t	perl_interpreter_mutex;

/*
 * How initialization works
 *
 * 1. perl_back_initialize is called where the hooks are defined
 *    and dynamic config objectclasses are registered.
 *    The Perl backend data structure is allocated and
 *    accessible through be->be_private
 * 2. During dynamic config of the Perl backend pb_config is
 *    called and the interpreter pools are allocated
 * 3. The Perl backend databases are initialized
 * 4. The databases are associated to the interpreter pools.
 *    Perl interpreters are allocated when the pool is first
 *    referenced by a database. The 'init' method is called
 *    after the interpreter is allocated.
 * 5. perl_back_db_config is called for directives not
 *    statically configured in dynamic config.
 *    
 */

/**********************************************************
 *
 * Init
 *
 **********************************************************/

int
perl_back_initialize(
	BackendInfo	*bi
)
{
	PerlBackend *pb;
	int rc;

	bi->bi_open = 0;
	bi->bi_config = 0;
	bi->bi_close = 0;
	bi->bi_destroy = 0;

	bi->bi_db_init = perl_back_db_init;
	bi->bi_db_config = perl_back_db_config;
	bi->bi_db_open = perl_back_db_open;
	bi->bi_db_close = perl_back_db_close;;
	bi->bi_db_destroy = perl_back_db_destroy;

	bi->bi_op_bind = perl_back_operation;
	bi->bi_op_unbind = perl_back_operation;
	bi->bi_op_search = perl_back_operation;
	bi->bi_op_compare = perl_back_operation;
	bi->bi_op_modify = perl_back_operation;
	bi->bi_op_modrdn = perl_back_operation;
	bi->bi_op_add = perl_back_operation;
	bi->bi_op_delete = perl_back_operation;
	bi->bi_op_abandon = 0;
	bi->bi_op_cancel = 0;
	bi->bi_extended = perl_back_operation;

	bi->bi_connection_init = perl_back_connection_init;
	bi->bi_connection_destroy = perl_back_connection_destroy;

	rc = perl_back_init_cf( bi );
	if( rc ) {
		return rc;
	}

	Debug( LDAP_DEBUG_TRACE, "perl backend open\n", 0, 0, 0 );

	if( bi->bi_private != NULL ) {
		Debug( LDAP_DEBUG_ANY, "<= perl backend open: already opened\n",
			0, 0, 0 );
		return 1;
	}

	pb = (PerlBackend *) ch_calloc( 1, sizeof(PerlBackend) );
	if( pb == NULL ) {
		Debug( LDAP_DEBUG_ANY, "<= perl_back_initialize NULL "
			"(PerlBackend allocation failed)\n", 0, 0, 0 );
		return 1;
	}
	LDAP_SLIST_INIT( &pb->pb_interpreter_pools );
	bi->bi_private = pb;

fprintf( stderr, "bi: %lx bi_private: %lx\n", bi, bi->bi_private );

	return 0;
}

int
perl_back_db_init(
	BackendDB		*be,
	struct config_reply_s	*cr
)
{
	int rc;
	PerlBackendDatabase	*pbdb = (PerlBackendDatabase *) ch_calloc( 1, sizeof(PerlBackendDatabase) );

	Debug( LDAP_DEBUG_TRACE, "perl backend db init\n", 0, 0, 0 );

        be->be_private = pbdb;
	rc = perl_back_db_init_cf( be );
	cr->err = rc;

	return rc;
}

int
perl_back_db_open(
	BackendDB		*be,
	struct config_reply_s	*cr
)
{
	PerlBackendDatabase *pbdb = (PerlBackendDatabase *) be->be_private;
	PerlInterpreterPool *pool = pbdb->pbdb_perl_interpreter_pool;

	Debug( LDAP_DEBUG_TRACE, "perl_back_db_open called\n", 0, 0, 0 );

	if( pool == NULL ) {
		strlcpy( &cr->msg, "The Perl backend database was opened and there "
			"is no associated interpreter pool", SLAP_TEXT_BUFLEN );
		cr->err = 1;
		return 1;
	}

	return 0;
}

#if SLAPD_PERL == SLAPD_MOD_DYNAMIC

/* conditionally define the init_module() function */
SLAP_BACKEND_INIT_MODULE( perl )

#endif /* SLAPD_PERL == SLAPD_MOD_DYNAMIC */


