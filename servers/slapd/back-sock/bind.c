/* bind.c - sock backend bind function */
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
sock_back_bind(
    Operation		*op,
    SlapReply		*rs )
{
	struct sockinfo	*si = (struct sockinfo *) op->o_bd->be_private;
	AttributeDescription *entry = slap_schema.si_ad_entry;
	Entry		e;
	FILE		*fp;
	int		rc;
	json_t		*json_request;
	json_t		*json_params;
	json_t		*suffixes;
	int		err;
	char		*method;
	int		i;
	Backend		*be;
	json_t          *result;
	json_error_t    error;

	e.e_id = NOID;
	e.e_name = op->o_req_dn;
	e.e_nname = op->o_req_ndn;
	e.e_attrs = NULL;
	e.e_ocflags = 0;
	e.e_bv.bv_len = 0;
	e.e_bv.bv_val = NULL;
	e.e_private = NULL;

	if ( ! access_allowed( op, &e,
		entry, NULL, ACL_AUTH, NULL ) )
	{
		send_ldap_error( op, rs, LDAP_INSUFFICIENT_ACCESS, NULL );
		return -1;
	}

	if ( (fp = opensock( si->si_sockpath )) == NULL ) {
		send_ldap_error( op, rs, LDAP_OTHER,
		    "could not open socket" );
		return( -1 );
	}

	/* write out the request to the bind process */
	method = "UNDEFINED";
	switch( op->oq_bind.rb_method ) {
		case LDAP_AUTH_NONE:
			method = "NONE";
			break;
		case LDAP_AUTH_SIMPLE:
			method = "SIMPLE";
			break;
		case LDAP_AUTH_SASL:
			method = "SASL";
			break;
		case LDAP_AUTH_KRBV4:
		case LDAP_AUTH_KRBV41:
		case LDAP_AUTH_KRBV42:
			method = "KERBEROS";
			break;
	}

	be = op->o_bd;
	suffixes = json_array();
	for( i = 0; be->be_suffix[i].bv_val != NULL; i++ ) {
		json_array_append_new( suffixes, json_stringbv( &be->be_suffix[i] ) );
	}

	json_params = json_pack( "{s:s#,s:s,s:s#,s:o}",
			"DN", op->o_req_dn.bv_val, op->o_req_dn.bv_len,
			"method", method,
			"cred", op->oq_bind.rb_cred.bv_val, op->oq_bind.rb_cred.bv_len,
			"suffixes", suffixes
	);
	if( si->si_cookie ) {
		json_object_set( json_params, "cookie", si->si_cookie );
	}

	json_request = json_pack( "{s:s,s:s,s:o,s:I}",
		"jsonrpc", "2.0",
		"method", "ldap.bind",
		"params", json_params,
		"id", (json_int_t) op->o_msgid
	);

	err = json_dumpf( json_request, fp, 0 );
	json_decref( json_request );
	fprintf( fp, "\n" );
	fflush( fp );

	result = json_loadf( fp, 0, &error );
	if( !result ) {
		fprintf( stderr, "Error: %s\n", error.text );
	}

	/* read in the results and send them along */
	rc = sock_read_and_send_results( op, rs, result );
	fclose( fp );

	return( rc );
}
