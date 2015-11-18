/* unbind.c - sock backend unbind function */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2007-2010 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Brian Candler for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-sock.h"

int
sock_back_unbind(
    Operation		*op,
    SlapReply		*rs
)
{
	struct sockinfo	*si = (struct sockinfo *) op->o_bd->be_private;
	FILE		*fp;
	json_t		*params;
	json_t		*json_request;
	int		err;
	json_error_t	error;

	if ( (fp = opensock( si->si_sockpath )) == NULL ) {
		send_ldap_error( op, rs, LDAP_OTHER,
		    "could not open socket" );
		return( -1 );
	}

	params = json_object();
	if( si->si_cookie ) {
		json_object_set( params, "cookie", si->si_cookie );
	}

	/* write out the request to the unbind process */
	json_request = json_pack( "{s:s,s:s,s:o,s:I}",
		"jsonrpc", "2.0",
		"method", "ldap.unbind",
		"params", params,
                "id", (json_int_t) op->o_msgid
	);


	err = json_dumpf( json_request, fp, 0 );
	json_decref( json_request );
	fprintf( fp, "\n" );

	/* no response to unbind, read the mandatory result from JSON-RPC and ignore it */
	(void) json_loadf( fp, 0, &error );

	fclose( fp );

	return 0;
}
