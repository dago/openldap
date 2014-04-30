/* $OpenLDAP: pkg/ldap/servers/slapd/back-perl/search.c,v 1.25.2.5 2007/01/02 21:44:06 kurt Exp $ */
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
#include <ac/string.h>

/*
 * convert_retval
 *
 * This function takes a pointer to an SV and converts the fields
 * into an SlapReply, which is passed as pointer, too.
 *
 * Input format for the SV:
 *   <n>	integer
 *   { err => <n>, text => "<string>" }
 *		reference to hash with values for error-code and error-text
 */

void
convert_retval(
	pTHX_
	SV *retval,
	SlapReply *rs )
{
	rs->sr_text = NULL;
	rs->sr_err = 0;

	if(SvROK(retval)) {
		/* The retval is a reference, pull out the values */
		if( SvTYPE(SvRV(retval)) == SVt_PVHV ) {
			HV *hash = (HV *) SvRV(retval);
			SV **sv_err = hv_fetch(hash, "err", STRLENOF( "err" ), 0);
			SV **sv_text = hv_fetch(hash, "text", STRLENOF( "text" ), 0);
			if( sv_err != NULL ) rs->sr_err = SvIV( *sv_err );
			if( sv_text != NULL ) rs->sr_text = SvPV_nolen( *sv_text );
		} else {
			Debug( LDAP_DEBUG_ANY, "<= convert_retval wrong return type, reference to %s "
				"instead of reference to HASH",
				sv_reftype( SvRV( retval ), 0), 0, 0 );
		}
	} else if(SvIOK(retval)) {
		/* A simple integer was returned. Use it as error code */
		rs->sr_err = SvIV( retval );
	} else {
		Debug( LDAP_DEBUG_ANY, "<= convert_retval wrong return type, %s "
			"instead of integer or reference to HASH",
			sv_reftype( retval, 0 ), 0, 0 );
	}
}

/*
 * svpv2berval
 *
 * This function converts a scalar containing a string to a berval. The string can
 * hold arbitrary characters (include '\0'). If 'dup' is given a non-zero value the
 * string in the berval is copied.
 */

/*
struct berval *
svpv2berval(
	pTHX_
	SV *sv,
	int dup )
{
	struct berval *bv;
	char *s;
	STRLEN len;
	
	s = SvPV( sv, len );
	bv = ber_str2bv( s, len, dup, NULL );

	if( bv == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"<= svpv2berval NULL (ber allocation failed)\n",
			0, 0, 0 );
	}

	return bv;
}
*/

/*
 * sv2entry
 *
 * This function converts a Perl data structure into an LDAP Entry. The passed
 * scalar must be a
 *   [ attr1 => [ value1 ], attr2 => [ value2, value3 ] ]
 * The structure of the function is similar to str2entry2.
 */

Entry *
sv2entry(
	pTHX_
	SV *sv )
{
	Entry	*e;

	struct berval bv_type;
	struct berval bv_value;
	SV *sv_val;
	HV *hv;
	Attribute ahead, *atail;
	int rc;

	if( SvROK( sv ) ) {
		if( SvTYPE( SvRV( sv ) ) != SVt_PVHV ) {
			Debug( LDAP_DEBUG_ANY,
				"<= sv2entry NULL (wrong type reference to %s instead of reference to HASH)\n",
				sv_reftype( SvRV( sv ), 0 ), 0, 0 );
			return NULL;
		}
	} else if( SvPOK( sv ) ) {
		return str2entry( SvPV_nolen( sv ) );
	} else {
		Debug( LDAP_DEBUG_ANY,
			"<= sv2entry NULL (wrong type %s instead of STRING or reference to HASH)\n",
			sv_reftype( sv, 0 ), 0, 0 );
		return NULL;
	}

	/* We really have a reference to a hash */
	e = (Entry *) ch_calloc( 1, sizeof( Entry ) );
	if( e == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"<= sv2entry NULL (entry allocation failed)\n",
			0, 0, 0 );
		return NULL;
	}
	e->e_id = NOID;

	/* assumptions:
	 * - I32(=int) (keylen) == ber_len_t (=unsigned LBER_LEN_T=unsigned long)
	 */

	atail = &ahead;

	hv = (HV *) SvRV( sv );
	(void) hv_iterinit( hv );
	while( sv_val = hv_iternextsv( hv, &bv_type.bv_val, (I32 *) &bv_type.bv_len ) ) {
fprintf( stderr, "Key: %s\n", bv_type.bv_val );
		/* sv_val may be scalar or reference to an array with one element */
		if( strcasecmp( bv_type.bv_val, "dn" ) == 0 ) {
			/* set 'dn' */
			STRLEN len;
			if( SvROK( sv_val ) ) {
				Debug( LDAP_DEBUG_ANY, "<= sv2entry: wrong type, "
					"reference to %s instead of reference to SCALAR)\n",
					sv_reftype( SvRV( sv_val ), 0 ), 0, 0 );
				goto fail;
			}
			bv_value.bv_val = SvPV( sv_val, len );
			bv_value.bv_len = len;	/* cast unsigned int to long */
fprintf( stderr, "value: %s\n", bv_value.bv_val );
			rc = dnPrettyNormal( NULL, &bv_value, &e->e_name, &e->e_nname, NULL );
fprintf( stderr, "value p: %s %s\n", e->e_name.bv_val, e->e_nname.bv_val );
			if( rc != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_ANY, "sv2entry: "
					"entry %ld has invalid DN \"%s\"\n",
					(long) e->e_id, bv_value.bv_val, 0 );
			}
			
		} else {
			/* set attributes != 'dn' */

			const char *text;
			int attr_cnt;
			I32 i;

			atail->a_next = (Attribute *) ch_malloc( sizeof(Attribute) );
			atail = atail->a_next;
			atail->a_desc = NULL;
			atail->a_flags = 0;

			/* setup attribute description */
			rc = slap_bv2ad( &bv_type, &atail->a_desc, &text );
			if( rc != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_TRACE,
					"<= sv2entry: slap_bv2ad(%s): %s\n", bv_type.bv_val, text, 0 );
				rc = slap_bv2undef_ad( &bv_type, &atail->a_desc, &text, 0 );
				if( rc != LDAP_SUCCESS ) {
					Debug( LDAP_DEBUG_ANY,
						"<= sv2entry: slap_bv2undef_ad(%s): %s\n",
							bv_type.bv_val, text, 0 );
					goto fail;
				}
			}

			/* check for correct value type and get attribute count */
			if( SvROK( sv_val ) ) {
				if( SvTYPE( SvRV( sv_val ) ) != SVt_PVAV ) {
					Debug( LDAP_DEBUG_ANY,
						"<= sv2entry: wrong value for attribute, "
						"reference to %s instead of reference to ARRAY)\n",
						sv_reftype( SvRV( sv_val ), 0 ), 0, 0 );
					goto fail;
				}
				attr_cnt = av_len( (AV *) SvRV( sv_val ) ) + 1;
			} else {
				attr_cnt = 1;
			}

			/* allocate memory for the attribute count */
			atail->a_vals = ch_malloc( (attr_cnt + 1) * sizeof(struct berval) );
			if( atail->a_vals == NULL ) {
				Debug( LDAP_DEBUG_ANY,
					"<= sv2entry: allocation failed for values of attribute %s\n",
					bv_type.bv_val, 0, 0 );
				goto fail;
			}

			/* set values */
			if( SvROK( sv_val ) ) {
				AV *av = (AV *) SvRV( sv_val );

				for( i = 0; i < attr_cnt; i++ ) {
					SV **asv = av_fetch( av, i, 0 );
					STRLEN len;
					char *s;

					s = SvPV( *asv, len );
					ber_str2bv( s, (ber_len_t) len, 1, &atail->a_vals[ i ] );
				}
			} else {
				STRLEN len;
				char *s;

				s = SvPV( sv_val, len );
				ber_str2bv( s, (ber_len_t) len, 1, &atail->a_vals[ 0 ] );
			}
			atail->a_vals[ attr_cnt ].bv_val = NULL;

			/* set normalized values */
			if( atail->a_desc->ad_type->sat_equality &&
			    atail->a_desc->ad_type->sat_equality->smr_normalize ) {
				atail->a_nvals = ch_malloc( (attr_cnt + 1) * sizeof(struct berval));
				if( atail->a_nvals == NULL ) {
					Debug( LDAP_DEBUG_ANY,
						"<= sv2entry: allocation failed for normalized values "
						"of attribute %s\n",
						bv_type.bv_val, 0, 0 );
					goto fail;
				}

				for( i = 0; i < attr_cnt; i++ ) {
#ifdef SLAP_ORDERED_PRETTYNORM
					rc = ordered_value_normalize(
						SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
						atail->a_desc,
						atail->a_desc->ad_type->sat_equality,
						&atail->a_vals[ i ], &atail->a_nvals[ i ], NULL );
#else /* ! SLAP_ORDERED_PRETTYNORM */
					rc = atail->a_desc->ad_type->sat_equality->smr_normalize(
						SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
						atail->a_desc->ad_type->sat_syntax,
						atail->a_desc->ad_type->sat_equality,
						&atail->a_vals[ i ], &atail->a_nvals[ i ], NULL );
#endif /* ! SLAP_ORDERED_PRETTYNORM */
					if ( rc ) {
						Debug( LDAP_DEBUG_ANY,
							"<= sv2entry NULL (smr_normalize %d)\n", rc, 0, 0 );
						goto fail;
					}
				}
				atail->a_nvals[ attr_cnt ].bv_val = NULL;
			} else {
		 		atail->a_nvals = atail->a_vals;
			}

		} /* type ne 'dn' */
	} /* hash iterate */

	atail->a_next = NULL;
	e->e_attrs = ahead.a_next;

	/* Check that a dn has been set */
	if( e->e_dn == NULL ) {
		/* XXX: print error */
	}

{
int len;
fprintf( stderr, "Entry: %s\n", entry2str( e, &len ) );
}
fprintf( stderr, "Entry: done\n" );

	if ( BER_BVISNULL( &e->e_name )) {
		Debug( LDAP_DEBUG_ANY, "sv2entry: entry %ld has no dn\n",
		(long) e->e_id, 0, 0 );
	}

	return e;

fail:
	/* XXX: free memory */
}

void
dump_attribute_description(
	AttributeDescription *ad )
{
	fprintf( stderr, "Attribute Description:\n" );
	fprintf( stderr, "   Type: XXX\n" );
	fprintf( stderr, "  CName: %s\n", ad->ad_cname.bv_val );
	fprintf( stderr, "   Tags: %s\n", ad->ad_tags.bv_val == NULL ? "(none)" : ad->ad_tags.bv_val );
	fprintf( stderr, "  Flags: %ul\n", ad->ad_flags );
	if( ad->ad_next != NULL ) {
		dump_attribute_description( ad->ad_next );
	}
/* Represents a recognized attribute description ( type + options ). */
/*
typedef struct slap_attr_desc {
        struct slap_attr_desc *ad_next;
        AttributeType *ad_type;         // attribute type, must be specified
        struct berval ad_cname;         // canonical name, must be specified
        struct berval ad_tags;          // empty if no tagging options
        unsigned ad_flags;
#define SLAP_DESC_NONE                  0x00U
#define SLAP_DESC_BINARY                0x01U
#define SLAP_DESC_TAG_RANGE             0x80U
} AttributeDescription;
*/
}

void
dump_attribute(
	Attribute *a )
{
	BerValue *bv;

	fprintf( stderr, "Attribute:\n" );
	dump_attribute_description( a->a_desc );

	fprintf( stderr, "  Values:\n", a->a_vals );
	for( bv = a->a_vals; bv->bv_val != NULL; bv++ ) {
		fprintf( stderr, "    Value: %s\n", bv->bv_val );
	}
	fprintf( stderr, "  Normalized Values:\n", a->a_nvals );
	for( bv = a->a_nvals; bv->bv_val != NULL; bv++ ) {
		fprintf( stderr, "    Normalized Value: %s\n", bv->bv_val );
	}

	fprintf( stderr, "  Flags: %d\n", a->a_flags );

	if( a->a_next != NULL ) {
		dump_attribute( a->a_next );
	}


}


void
dump_entry(
	Entry *e )
{
	Attribute *a;
	fprintf( stderr, "Entry\n" );
	fprintf( stderr, "               ID: %ul\n", e->e_id );
	fprintf( stderr, "             name: %s\n", e->e_name.bv_val );
	fprintf( stderr, "  normalized name: %s\n", e->e_nname.bv_val );
	for( a = e->e_attrs; a != NULL; a = a->a_next ) {
		dump_attribute( a );
	}
	fprintf( stderr, "          ocflags: XXX\n" );
	fprintf( stderr, "               bv: %s\n", e->e_bv.bv_val == NULL ? "(none)" : e->e_bv.bv_val );
	fprintf( stderr, "          private: %lx\n", e->e_private );
}
