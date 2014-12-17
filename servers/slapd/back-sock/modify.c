/* modify.c - sock backend modify function */
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

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-sock.h"

int
sock_back_modify(
    Operation	*op,
    SlapReply	*rs )
{
	Modification *mod;
	struct sockinfo	*si = (struct sockinfo *) op->o_bd->be_private;
	AttributeDescription *entry = slap_schema.si_ad_entry;
	Modifications *ml  = op->orm_modlist;
	Entry e;
	FILE			*fp;
	int			i;
	json_t          *result;
	json_t          *params;
	json_t          *mods;
	json_t          *json_request;
	int             err;
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
		entry, NULL, ACL_WRITE, NULL ) )
	{
		send_ldap_error( op, rs, LDAP_INSUFFICIENT_ACCESS, NULL );
		return -1;
	}

	if ( (fp = opensock( si->si_sockpath )) == NULL ) {
		send_ldap_error( op, rs, LDAP_OTHER,
		    "could not open socket" );
		return( -1 );
	}

	/* write out the request to the modify process */
	params = json_object();
	err = json_object_set_new( params, "DN", json_stringbv( &op->o_req_dn ) );
	/* XXX: value may be binary */
	mods = json_array();
	for ( ; ml != NULL; ml = ml->sml_next ) {
		json_t  *jm;

		jm = json_object();

		mod = &ml->sml_mod;
		json_object_set_new( jm, "attribute", json_stringbv( &mod->sm_desc->ad_cname ) );
		switch ( mod->sm_op ) {
			case LDAP_MOD_ADD:
				json_object_set_new( jm, "type", json_string( "ADD" ) );
				break;
			case LDAP_MOD_DELETE:
				json_object_set_new( jm, "type", json_string( "DELETE" ) );
				break;
			case LDAP_MOD_REPLACE:
				json_object_set_new( jm, "type", json_string( "REPLACE" ) );
				break;
			case LDAP_MOD_INCREMENT:
				json_object_set_new( jm, "type", json_string( "INCREMENT" ) );
				break;
			default:
				json_object_set_new( jm, "type", json_integer( mod->sm_op ) );
				break;
		}

		if( mod->sm_values != NULL ) {
			json_t  *jv;

			jv = json_array();
			for ( i = 0; mod->sm_values[i].bv_val != NULL; i++ ) {
				err = json_array_append_new( jv, json_stringbv( &mod->sm_values[i] ) );
			}
			json_object_set_new( jm, "values", jv );
		}
		json_array_append_new( mods, jm );
	}
	err = json_object_set_new( params, "mods", mods );

	if( si->si_cookie ) {
		json_object_set( params, "cookie", si->si_cookie );
	}

	err = json_object_add_suffixes( params, op->o_bd );
	err = json_object_add_conn( params, op->o_conn, si );

	json_request = json_pack( "{s:s,s:s,s:o,s:I}",
		"jsonrpc", "2.0",
		"method", "ldap.modify",
		"params", params,
		"id", (json_int_t) op->o_msgid
	);
	if( !json_request ) {
		fprintf( stderr, "ERR: %s\n", error.text );
	}

	err = json_dumpf( json_request, fp, 0 );
	json_decref( json_request );

	fprintf( fp, "\n" );
	fflush( fp );

	result = json_loadf( fp, 0, &error );
	if( !result ) {
		fprintf( stderr, "Error: %s\n", error.text );
	}

	/* read in the result and send it along */
	sock_read_and_send_results( op, rs, result );

	fclose( fp );
	return( 0 );
}
