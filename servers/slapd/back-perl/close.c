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

int
perl_back_db_close(
	BackendDB		*be,
	struct config_reply_s	*cr
)
{
	fprintf( stderr, "perl_back_db_close called\n" );
	return 0;
}

int
perl_back_db_destroy(
	BackendDB		*be,
	struct config_reply_s	*cr
)
{
#if 0
        PerlBackendDatabase *perl_back_db = (PerlBackendDatabase *) be->be_private;
	PerlContext *context = &perl_back_db->pbdb_perl_context;
	dTHXa( context->pc_perl_interpreter );

	fprintf( stderr, "perl_back_db_destroy\n" );
	perl_context_pool_destroy( perl_back_db->pbdb_perl_context_pool );

        if( context->pc_base_sv != NULL ) SvREFCNT_dec( context->pc_base_sv );
        if( context->pc_sv != NULL ) SvREFCNT_dec( context->pc_sv );
        PERL_SET_CONTEXT( context->pc_perl_interpreter );
        perl_destruct( context->pc_perl_interpreter );
        perl_free( context->pc_perl_interpreter );
        ldap_pvt_thread_mutex_destroy( &context->pc_perl_interpreter_mutex );

	free( perl_back_db->pbdb_connection_contexts );

	fprintf( stderr, "perl_back_db_destroy post-pool\n" );

	free( be->be_private );
	be->be_private = NULL;
#endif
	return 0;
}
