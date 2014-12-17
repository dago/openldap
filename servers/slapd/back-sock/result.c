/* result.c - sock backend result reading function */
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

#include <ac/errno.h>
#include <ac/string.h>
#include <ac/socket.h>
#include <ac/unistd.h>

#include "slap.h"
#include "lutil.h"
#include "back-sock.h"

/*
 * FIXME: make a RESULT section compulsory from the socket response.
 * Otherwise, a partial/aborted response is treated as 'success'.
 * This is a divergence from the back-shell protocol, but makes things
 * more robust.
 */

int
sock_read_and_send_results(
    Operation	*op,
    SlapReply	*rs,
    json_t      *result )
{
	json_error_t	error;

	if( json_is_object( result ) ) {
	// {"info":"okay","code":0}
        //  "error" : { "code" : 1103, "message" : "LDAP server down or invalid host\/port" }
	json_t *result_message, *result_code, *result_cookie;
	json_t *error;
	json_t *referrals;

	referrals = json_object_get( result, "referrals" );
	if( referrals != NULL ) {
		if( json_is_string( referrals ) ||
			(json_is_array( referrals ) && json_array_size( referrals ) > 0)) {
			/* There are actually referrals to send, preset ldap result with referral
			 * but leave it ready to be overridden. */
			rs->sr_err = LDAP_REFERRAL;
		}
	}

        error = json_object_get( result, "error" );
        if( error ) {
		    result_message = json_object_get( error, "message" );
		    if( result_message == NULL ) {
			    rs->sr_text = NULL;
		    } else if( !json_is_string( result_message ) ) {
			    rs->sr_text = NULL;
		    } else {
			    rs->sr_text = json_string_value( result_message );
		    }

		    result_code = json_object_get( error, "code" );
		    if( result_code == NULL ) {
			    rs->sr_err = 0;
		    } else if( !json_is_integer( result_code ) ) {
		        Debug( LDAP_DEBUG_ANY,
			        "   sock_read_and_send_results error code (wrong JSON type, valid are INTEGER found %d)\n",
                    json_typeof( result_code ), 0, 0 );
			    rs->sr_err = 0;
            /* XXX: Map LDAP returncode strings like LDAP_OPERATIONS_ERROR to integer values */
		    } else {
			    rs->sr_err = json_integer_value( result_code );
		    }
        }

		result_cookie = json_object_get( result, "cookie" );
        if( result_cookie ) {
            struct sockinfo *si = (struct sockinfo *) op->o_bd->be_private;

            if( si->si_cookie ) {
                json_decref( si->si_cookie );
            }
            si->si_cookie = json_incref( result_cookie );
        }
	}
	send_ldap_result( op, rs );
	json_decref( result );
}

void
sock_print_suffixes(
    FILE	*fp,
    Backend	*be
)
{
	int	i;

	for ( i = 0; be->be_suffix[i].bv_val != NULL; i++ ) {
		fprintf( fp, "suffix: %s\n", be->be_suffix[i].bv_val );
	}
}

int
json_object_add_suffixes(
    json_t  *j,
    Backend *be
)
{
    json_t  *suffixes;
    int     i;
    int     err;

    suffixes = json_array();
    if( !suffixes ) {
        return -1;
    }
    for( i = 0; be->be_suffix[i].bv_val != NULL; i++ ) {
        err = json_array_append_new( suffixes, json_string( be->be_suffix[i].bv_val ) );
        if( err ) {
            json_decref( suffixes );
            return err;
        }
    }

    return json_object_set_new( j, "suffixes", suffixes );
}

void
sock_print_conn(
    FILE	*fp,
    Connection	*conn,
    struct sockinfo *si
)
{
	if ( conn == NULL ) return;

	if( si->si_extensions & SOCK_EXT_BINDDN ) {
		fprintf( fp, "binddn: %s\n",
			conn->c_dn.bv_len ? conn->c_dn.bv_val : "" );
	}
	if( si->si_extensions & SOCK_EXT_PEERNAME ) {
		fprintf( fp, "peername: %s\n",
			conn->c_peer_name.bv_len ? conn->c_peer_name.bv_val : "" );
	}
	if( si->si_extensions & SOCK_EXT_SSF ) {
		fprintf( fp, "ssf: %d\n", conn->c_ssf );
	}
}

int
json_object_add_conn(
    json_t  *j,
    Connection *conn,
    struct sockinfo *si
)
{
    json_t  *jc;
    int     err;

	if( conn == NULL ) return 0;

    jc = json_object();
    if( conn->c_dn.bv_len )
        err = json_object_set_new( jc, "binddn", json_stringn( conn->c_dn.bv_val, conn->c_dn.bv_len ) );
    if( conn->c_peer_name.bv_len )
        err = json_object_set_new( jc, "peername", json_stringn( conn->c_peer_name.bv_val, conn->c_peer_name.bv_len ) );
    err = json_object_set_new( jc, "peername", json_integer( conn->c_ssf ) );

    return json_object_set_new( j, "connection", jc );
}

/*
 * jsonstring2berval
 *
 * This function converts a JSON string to a berval. The string can
 * hold arbitrary characters (include '\0'). If 'dup' is given a non-zero value the
 * string in the berval is copied.
 */

struct berval *
jsonstring2berval(
    json_t  *j )
{
    struct berval *bv;
    const char *s;
    size_t len;
    
    assert( json_typeof( j ) == JSON_STRING );

    s = json_string_value( j );
    len = json_string_length( j );
    bv = ber_str2bv( s, len, 1, NULL );

    if( bv == NULL ) {
        Debug( LDAP_DEBUG_ANY,
            "<= jsonstring2berval NULL (ber allocation failed)\n",
            0, 0, 0 );
    }

    return bv;
}


/*
 * json2entry
 *
 * This function converts a json_t datastructure into an LDAP Entry.
 * The structure of this function is similar to str2entry2.
 */

Entry *
json2entry( json_t *je )
{
	int rc;
	Entry		*e;

	const char *text;
	int		i, j;

    const char  *key;
    json_t      *value;
    struct berval bv_dn;

	Debug( LDAP_DEBUG_TRACE, "=> json2entry\n",
		0, 0, 0 );

    if( json_is_string( je ) ) {
        e = str2entry( (char *) json_string_value( je ) );
        return e;
    }

    if( !json_is_object( je ) ) {
		Debug( LDAP_DEBUG_ANY,
			"<= json2entry NULL (Wrong JSON type, valid are STRING and OBJECT, found %d)\n",
            json_typeof( je ), 0, 0 );
		return( NULL );
    }

	/* Attribute https://buildfarm.opencsw.org/source/xref/openldap/servers/slapd/slap.h#1154 */
	e = entry_alloc();

	if( e == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"<= json2entry NULL (entry allocation failed)\n",
			0, 0, 0 );
		return( NULL );
	}

	/* initialize entry */
	e->e_id = NOID;
    e->e_attrs = NULL;

    value = json_object_get( je, "dn" );

    json_object_foreach( je, key, value ) {
fprintf( stderr, "K: %s V: %s\n", key, "x" );
        if( strcasecmp( key, "dn" ) == 0 ) {
            struct berval *dn;

            if( !json_is_string( value ) ) {
			    Debug( LDAP_DEBUG_TRACE,
			    	"<= json2entry value for DN must be a string\n", 0, 0, 0 );
			    goto fail;
            }

			if ( e->e_dn != NULL ) {
				Debug( LDAP_DEBUG_ANY, "json2entry: "
					"entry %ld has multiple DNs \"%s\" and \"%s\"\n",
					(long) e->e_id, e->e_dn, json_string_value( value ) );
				goto fail;
            }

            // dn = jsonstring2berval( value );
            // rc = dnPrettyNormal( NULL, dn, &e->e_name, &e->e_nname, NULL );
		bv_dn.bv_val = (char *) json_string_value( value );
		bv_dn.bv_len = json_string_length( value );
            rc = dnPrettyNormal( NULL, &bv_dn, &e->e_name, &e->e_nname, NULL );
			if( rc != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_ANY, "json2entry: "
					"entry %ld has invalid DN \"%s\"\n",
					(long) e->e_id, dn->bv_val, 0 );
				goto fail;
			}
        } else {
            /* From any other attribute the JSON value may either be a scalar type like Number or String
             * or an array of scalars for multi-value attributes.
             */
            AttributeDescription    *ad;
            Attribute               *attr;
            const char              *errtext;
            int                     rc;

            attr = attr_alloc( NULL );
            /* XXX: Reversing order here, is this allowed as str2entry2 does it differently? */
            attr->a_flags = 0;
            attr->a_next = e->e_attrs;
            e->e_attrs = attr;
            if( attr == NULL ) {
                Debug( LDAP_DEBUG_ANY,
                    "<= json2entry NULL (attribute allocation failed)\n",
                    0, 0, 0 );
                goto fail;
            }

            /* Attribute description */
            Debug( LDAP_DEBUG_ANY, "   json2entry str2ad (%s)\n", key, 0, 0 );
            ad = NULL;
            rc = slap_str2ad( key, &ad, &errtext );
            attr->a_desc = ad;
            if( rc != LDAP_SUCCESS ) {
                Debug( LDAP_DEBUG_ANY, "   json2entry slap_str2ad != LDAP_SUCCESS (%d)\n", rc, 0, 0 );
                rc = slap_str2undef_ad( key, &ad, &errtext, 0 );
                if( rc != LDAP_SUCCESS ) {
                    Debug( LDAP_DEBUG_ANY,
                        "<= str2entry: slap_str2undef_ad(%s): %s\n",
                        key, text, 0 );
                    goto fail;
                }
            }
            Debug( LDAP_DEBUG_ANY, "   json2entry bincheck (%s)\n", key, 0, 0 );

            /* require ';binary' when appropriate (ITS#5071) */
            if ( slap_syntax_is_binary( ad->ad_type->sat_syntax ) && !slap_ad_is_binary( ad ) ) {
                Debug( LDAP_DEBUG_ANY,
                    "str2entry: attributeType %s #%d: "
                    "needs ';binary' transfer as per syntax %s\n",
                    ad->ad_cname.bv_val, 0,
                    ad->ad_type->sat_syntax->ssyn_oid );
                goto fail;
            }

            if( json_is_string( value ) ) {
                /* Single value attribute */
                attr->a_numvals = 1;
                attr->a_vals = ch_malloc( (attr->a_numvals + 1) * sizeof(struct berval) );
                if( attr->a_vals == NULL ) {
                    Debug( LDAP_DEBUG_ANY,
                        "<= json2entry NULL (attribute value allocation for one element failed)\n",
                        0, 0, 0 );
                    goto fail;
                }
                Debug( LDAP_DEBUG_ANY, "   json2entry values for %s (%s)\n", key, json_string_value( value ), 0 );
                // Debug( LDAP_DEBUG_ANY, "   json2entry values for %s -> %s\n", key, attr->a_vals[0].bv_val, 0 );
                if ( ad && ad->ad_type &&
                    (slap_syntax_is_binary( ad->ad_type->sat_syntax ) ||
                    slap_syntax_is_blob( ad->ad_type->sat_syntax) ) ) {
                    attr->a_vals[0].bv_len = LUTIL_BASE64_DECODE_LEN( json_string_length( value ) );
                    attr->a_vals[0].bv_val = ber_memalloc( attr->a_vals[0].bv_len + 1 );
                    if( attr->a_vals[0].bv_val == NULL ) {
                    }

                    rc = lutil_b64_pton( json_string_value( value ), (unsigned char *) attr->a_vals[0].bv_val, attr->a_vals[0].bv_len );
                    // attr->a_vals[0].bv_val = NULL;
                    /* The initial string may contain newlines which are used in length calculation but do not carry any data.
                     * This can lead to the actual number of decoded characters to be less than the expected number.
                     */
                    assert( rc < attr->a_vals[0].bv_len );
                } else {

                    ber_str2bv( json_string_value( value ), json_string_length( value ), 1, &attr->a_vals[0] );
                }

                attr->a_vals[1].bv_val = NULL;
                attr->a_vals[1].bv_len = 0;
            } else if( json_is_array( value ) ) {
                /* Multi value attribute */
                size_t i;

                attr->a_numvals = json_array_size( value );
                attr->a_vals = ch_malloc( (attr->a_numvals + 1) * sizeof(struct berval) );
                if( attr->a_vals == NULL ) {
                    Debug( LDAP_DEBUG_ANY,
                        "<= json2entry NULL (attribute value allocation for %d elements failed)\n",
                        attr->a_numvals, 0, 0 );
                    goto fail;
                }
                for( i = 0; i < attr->a_numvals; i++ ) {
                    json_t  *e = json_array_get( value, i );
                    if( json_is_string( e ) ) {
                        Debug( LDAP_DEBUG_ANY, "   json2entry values for %s (%s)\n", key, json_string_value( e ), 0 );
                        ber_str2bv( json_string_value( e ), json_string_length( e ), 1, &attr->a_vals[i] );
                        Debug( LDAP_DEBUG_ANY, "   json2entry values for %s -> %s\n", key, attr->a_vals[i].bv_val, 0 );
                    } else {
                        Debug( LDAP_DEBUG_ANY,
                            "<= str2entry: Wrong type of JSON element for key %s (%d)\n",
                            key, json_typeof( e ), 0 );
                        goto fail;
                    }
                }
                attr->a_vals[i].bv_val = NULL;
                attr->a_vals[i].bv_len = 0;
            
            } else {
				Debug( LDAP_DEBUG_ANY, "json2entry: "
					"entry %ld has invalid type for value \"%d\"\n",
					(long) e->e_id, json_typeof( value ), 0 );
				goto fail;
                
            }

            /* Sort */
/*
            if ( ad->ad_type->sat_flags & SLAP_AT_SORTED_VAL ) {
                rc = slap_sort_vals( (Modifications *)attr, &text, &j, NULL );
                if ( rc == LDAP_SUCCESS ) {
                    attr->a_flags |= SLAP_ATTR_SORTED_VALS;
                } else if ( rc == LDAP_TYPE_OR_VALUE_EXISTS ) {
                    Debug( LDAP_DEBUG_ANY,
                        "str2entry: attributeType %s value #%d provided more than once\n",
                        attr->a_desc->ad_cname.bv_val, j, 0 );
                    goto fail;
                }
            }
*/
            /* Normalize */

            Debug( LDAP_DEBUG_ANY, "   json2entry normalize (%s)\n", key, 0, 0 );

			if ( ad->ad_type->sat_equality &&
				ad->ad_type->sat_equality->smr_normalize )
			{
                int i;

                attr->a_nvals = ch_malloc( (attr->a_numvals + 1) * sizeof(struct berval) );
                if( attr->a_nvals == NULL ) {
                    Debug( LDAP_DEBUG_ANY,
                        "<= json2entry NULL (attribute normalized value allocation for %d elements failed)\n",
                        attr->a_numvals, 0, 0 );
                    goto fail;
                }
                for( i = 0; i < attr->a_numvals; i++ ) {
                    Debug( LDAP_DEBUG_ANY, "   json2entry normalize value (%s): %s\n", key, attr->a_vals[i].bv_val, 0 );
				    rc = ordered_value_normalize(
    					SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
    					ad,
    					ad->ad_type->sat_equality,
    					&attr->a_vals[i], &attr->a_nvals[i], NULL );
    	
    				if ( rc ) {
    					Debug( LDAP_DEBUG_ANY,
    				   		"<= json2entry NULL (smr_normalize %s %d)\n", ad->ad_cname.bv_val, rc, 0 );
    					goto fail;
    				}
                }
                attr->a_nvals[i].bv_val = NULL;
                attr->a_nvals[i].bv_len = 0;
            } else {
                // attr->a_nvals = NULL;
                attr->a_nvals = attr->a_vals;
            }

        }
    }

	/* check to make sure there was a dn: line */
	if ( BER_BVISNULL( &e->e_name )) {
		Debug( LDAP_DEBUG_ANY, "json2entry: entry %ld has no dn\n",
			(long) e->e_id, 0, 0 );
		goto fail;
	}

	Debug(LDAP_DEBUG_TRACE, "<= json2entry(%s) -> 0x%lx\n",
		e->e_dn, (unsigned long) e, 0 );
	return( e );

fail:
	entry_free( e );
	return NULL;
}

