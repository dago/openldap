/* add.c - sock backend add function */
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
#include "lutil.h"
#include "back-sock.h"

int
sock_back_add(
    Operation	*op,
    SlapReply	*rs )
{
	struct sockinfo	*si = (struct sockinfo *) op->o_bd->be_private;
	AttributeDescription *entry = slap_schema.si_ad_entry;
	Attribute   *a;
	FILE			*fp;
	int			len;
	json_t      *json_request;
	json_t      *params;
	json_t      *attributes, *binary_attributes;
	json_t          *result;
	json_error_t    error;
	int         err;
	
	if ( ! access_allowed( op, op->oq_add.rs_e,
		entry, NULL, ACL_WADD, NULL ) )
	{
		send_ldap_error( op, rs, LDAP_INSUFFICIENT_ACCESS, NULL );
		return -1;
	}

	if ( (fp = opensock( si->si_sockpath )) == NULL ) {
		send_ldap_error( op, rs, LDAP_OTHER,
		    "could not open socket" );
		return( -1 );
	}

	/* write out the request to the add process */
	params = json_object();
	err = json_object_set_new( params, "DN", json_stringbv( &op->ora_e->e_name ) );

	attributes = json_object();
	binary_attributes = json_object();

	for( a = op->ora_e->e_attrs; a != NULL; a = a->a_next ) {
		json_t *values;
		int i;

		if ( slap_syntax_is_binary( a->a_desc->ad_type->sat_syntax ) ||
		     slap_syntax_is_blob( a->a_desc->ad_type->sat_syntax ) )
			continue;

		values = json_array();
		for( i = 0; a->a_vals[i].bv_val != NULL; i++ ) {
			json_array_append_new( values, json_stringbv( &a->a_vals[i] ) );
		}
		json_object_set_new( attributes, a->a_desc->ad_cname.bv_val, values );
	}

	/* binary attributes are in base64 */
	for( a = op->ora_e->e_attrs; a != NULL; a = a->a_next ) {
		json_t *values;
		int i;

		if ( !slap_syntax_is_binary( a->a_desc->ad_type->sat_syntax ) &&
		     !slap_syntax_is_blob( a->a_desc->ad_type->sat_syntax ) )
			continue;

		values = json_array();
		for( i = 0; a->a_vals[i].bv_val != NULL; i++ ) {
			char    *b64val;
			size_t  b64len;
			int     rc;

			b64len = LUTIL_BASE64_ENCODE_LEN( a->a_vals[i].bv_len ) + 1;
			b64val = ber_memalloc( b64len );
			if( b64val == NULL ) {
			}

			rc = lutil_b64_ntop(
				(unsigned char *) a->a_vals[i].bv_val, a->a_vals[i].bv_len,
				b64val, b64len );
			if( rc < 0 ) {
			}
			json_array_append_new( values, json_stringn( b64val, b64len ) );
			ber_memfree( b64val );
		}

		json_object_set_new( binary_attributes, a->a_desc->ad_cname.bv_val, values );
	}

	err = json_object_set_new( params, "attributes", attributes );
	err = json_object_set_new( params, "binaryAttributes", binary_attributes );
	if( si->si_cookie ) {
		json_object_set( params, "cookie", si->si_cookie );
	}

	err = json_object_add_suffixes( params, op->o_bd );
	err = json_object_add_conn( params, op->o_conn, si );

	json_request = json_pack( "{s:s,s:s,s:o,s:I}",
		"jsonrpc", "2.0",
		"method", "ldap.add",
		"params", params,
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

	/* read in the result and send it along */
	sock_read_and_send_results( op, rs, result );

	fclose( fp );
	return( 0 );
}
