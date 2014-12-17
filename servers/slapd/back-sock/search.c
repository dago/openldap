/* search.c - sock backend search function */
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

/*
 * FIXME: add a filterSearchResults option like back-perl has
 */

int
sock_back_search(
    Operation	*op,
    SlapReply	*rs )
{
	struct sockinfo	*si = (struct sockinfo *) op->o_bd->be_private;
	LDAPControl **c;
	FILE			*fp;
	AttributeName	*an;
	json_t			*json_request;
	int		    	err;
	char            *scope;
	char            *deref;
	json_t          *params;
	json_t          *attrs, *battrs;
	json_t          *result;
	json_t          *matches;
	json_t          *controls;
	json_error_t    error;

	if ( (fp = opensock( si->si_sockpath )) == NULL ) {
		send_ldap_error( op, rs, LDAP_OTHER,
		    "could not open socket" );
		return( -1 );
	}

	/* write out the request to the search process */

	scope = NULL;
	if( op->ors_scope != LDAP_SCOPE_DEFAULT ) {
		switch( op->ors_scope ) {
			case LDAP_SCOPE_BASE:
				scope = "BASE";
				break;
			case LDAP_SCOPE_ONE:
				scope = "ONE";
				break;
			case LDAP_SCOPE_SUB:
				scope = "SUB";
				break;
			case LDAP_SCOPE_SUBORDINATE:
				scope = "SUBORDINATES";
				break;
		}
	}

	deref = NULL;
	switch( op->ors_deref ) {
		case LDAP_DEREF_NEVER:
			deref = "NEVER";
			break;
		case LDAP_DEREF_SEARCHING:
			deref = "SEARCHING";
			break;
		case LDAP_DEREF_FINDING:
			deref = "FINDING";
			break;
		case LDAP_DEREF_ALWAYS:
			deref = "ALWAYS";
			break;
	}

	params = json_pack( "{s:s#,s:s#,s:b}",
		"baseDN", op->o_req_dn.bv_val, op->o_req_dn.bv_len,
		"filter", op->oq_search.rs_filterstr.bv_val, op->oq_search.rs_filterstr.bv_len,
		"typesOnly", op->ors_attrsonly
	);

	if( scope ) {
		err = json_object_set_new( params, "scope", json_string( scope ) );
	}
	if( deref ) {
		err = json_object_set_new( params, "derefPolicy", json_string( deref ) );
	}
	if( op->ors_slimit ) {
		err = json_object_set_new( params, "sizeLimit", json_integer( op->ors_slimit ) );
	}
	if( op->ors_tlimit ) {
		err = json_object_set_new( params, "timeLimit", json_integer( op->ors_tlimit ) );
	}

	attrs = json_array();
	battrs = json_array();
	for( an = op->oq_search.rs_attrs; an && an->an_name.bv_val; an++ ) {
		if ( an->an_desc && an->an_desc->ad_type &&
			(slap_syntax_is_binary( an->an_desc->ad_type->sat_syntax ) ||
			slap_syntax_is_blob( an->an_desc->ad_type->sat_syntax) ) ) {
			err = json_array_append_new( battrs, json_string( an->an_name.bv_val ) );
		} else {
			err = json_array_append_new( attrs, json_string( an->an_name.bv_val ) );
		}
	}
	err = json_object_set_new( params, "attributes", attrs );
	err = json_object_set_new( params, "binaryAttributes", battrs );

	json_request = json_pack( "{s:s,s:s,s:o,s:I}",
		"jsonrpc", "2.0",
		"method", "ldap.search",
		"params", params,
		"id", (json_int_t) op->o_msgid
	);

	if( si->si_cookie ) {
		json_object_set( json_request, "cookie", si->si_cookie );
	}

	err = json_object_add_suffixes( json_request, op->o_bd );
	err = json_object_add_conn( json_request, op->o_conn, si );

	err = json_dumpf( json_request, fp, 0 );
	json_decref( json_request );
	fprintf( fp, "\n" );
	
	fflush( fp );

	/* read in the results and send them along */
	rs->sr_attrs = op->oq_search.rs_attrs;

	result = json_loadf( fp, 0, &error );
	if( !result ) {
		fprintf( stderr, "Error: %s\n", error.text );
	}

	matches = json_object_get( result, "matches" );
	if( json_is_array( matches ) ) {
		/* Array of results */
		size_t  index;
		json_t  *value;

		json_array_foreach( matches, index, value ) {
			if( (rs->sr_entry = json2entry( value )) == NULL ) {
				Debug( LDAP_DEBUG_ANY, "str2entry failed\n",
					0, 0, 0 );
			} else {
				rs->sr_attrs = op->oq_search.rs_attrs;
				rs->sr_flags = REP_ENTRY_MODIFIABLE;
				Debug( LDAP_DEBUG_ANY, "str2entry send 1\n", 0, 0, 0 );
				send_search_entry( op, rs );
				Debug( LDAP_DEBUG_ANY, "str2entry send 2\n", 0, 0, 0 );
				entry_free( rs->sr_entry );
				rs->sr_attrs = NULL;
			}
		}
	} else if( json_is_string( matches ) || json_is_object( matches ) ) {
		/* One result in object format */
		if( (rs->sr_entry = json2entry( matches )) == NULL ) {
			Debug( LDAP_DEBUG_ANY, "str2entry failed\n",
				0, 0, 0 );
		} else {
			rs->sr_attrs = op->oq_search.rs_attrs;
			rs->sr_flags = REP_ENTRY_MODIFIABLE;
			Debug( LDAP_DEBUG_ANY, "str2entry send 1\n", 0, 0, 0 );
			send_search_entry( op, rs );
			Debug( LDAP_DEBUG_ANY, "str2entry send 2\n", 0, 0, 0 );
			entry_free( rs->sr_entry );
			rs->sr_attrs = NULL;
		}
	} else {
		Debug( LDAP_DEBUG_ANY, "str2entry Wrong JSON type (%d)\n", json_typeof( matches ), 0, 0 );
		rs->sr_text = "Wrong JSON type";
		rs->sr_err = LDAP_OPERATIONS_ERROR;
	}

	Debug( LDAP_DEBUG_ANY, "str2entry send 3\n", 0, 0, 0 );
	sock_read_and_send_results( op, rs, result );
	Debug( LDAP_DEBUG_ANY, "str2entry send 4\n", 0, 0, 0 );

	fclose( fp );
	return( 0 );
}
