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

/**********************************************************
 *
 * Search
 *
 **********************************************************/
void
pb_stack_prepare_search(
	pTHX_
	pSP_
	Operation *op,
	SlapReply *rs )
{
	AttributeName *an;
	AV *attrs;
	SV *sv_scope, *sv_deref;

	XPUSHs( sv_2mortal( newSVpv( "base", 0 ) ) );
	XPUSHs( sv_2mortal( newSVberval( &op->o_req_ndn ) ) );
 
	XPUSHs( sv_2mortal( newSVpv( "scope", 0 ) ) );
	/*
	 * Setup dual valued scalar, see "Extending and Embedding Perl"
	 * p. 111 (SvIOK and friends) for details
	 */
	if( op->ors_scope != LDAP_SCOPE_DEFAULT ) {
		switch( op->ors_scope ) {
			case LDAP_SCOPE_BASE:
				sv_scope = newSVpv( "base", 0 );
				break;
			case LDAP_SCOPE_ONE:
				sv_scope = newSVpv( "one", 0 );
				break;
			case LDAP_SCOPE_SUB:
				sv_scope = newSVpv( "sub", 0 );
				break;
		}
	}
	if( sv_scope ) {
		/* string representation is set, add integer value */
		SvUPGRADE( sv_scope, SVt_PVNV );
		SvIV_set( sv_scope, op->ors_scope );
		SvIOK_on( sv_scope );
	} else {
		sv_scope = newSViv( op->ors_scope );
	}
	XPUSHs( sv_2mortal( sv_scope ) );
                                      
	XPUSHs( sv_2mortal( newSVpv( "deref", 0 ) ) );
	/* Setup dual valued scalar, see "Extending and Embedding Perl"
	 * p. 111 (SvIOK and friends) for details
	 */
	switch( op->ors_deref ) {
		case LDAP_DEREF_NEVER:
			sv_deref = newSVpv( "never", 0 );
			break;
		case LDAP_DEREF_SEARCHING:
			sv_deref = newSVpv( "search", 0 );
			break;
		case LDAP_DEREF_FINDING:
			sv_deref = newSVpv( "find", 0 );
			break;
		case LDAP_DEREF_ALWAYS:
			sv_deref = newSVpv( "always", 0 );
			break;
	}
	if( sv_deref ) {
		/* string representation is set, add integer value */
		SvUPGRADE( sv_deref, SVt_PVNV );
		SvIV_set( sv_deref, op->ors_deref );
		SvIOK_on( sv_deref);
	} else {
		sv_deref = newSViv( op->ors_deref );
	}
	XPUSHs( sv_2mortal( sv_deref ) );
 
	XPUSHs( sv_2mortal( newSVpv( "sizelimit", 0 ) ) );
	XPUSHs( sv_2mortal( newSViv( op->ors_slimit ) ) );

	XPUSHs( sv_2mortal( newSVpv( "timelimit", 0 ) ) );
	XPUSHs( sv_2mortal( newSViv( op->ors_tlimit ) ) );

	XPUSHs( sv_2mortal( newSVpv( "filter", 0 ) ) );
	XPUSHs( sv_2mortal( newSVberval( &op->ors_filterstr ) ) );

	XPUSHs( sv_2mortal( newSVpv( "typesonly", 0 ) ) );
	XPUSHs( sv_2mortal( newSViv( op->ors_attrsonly ) ) );

	XPUSHs( sv_2mortal( newSVpv( "attrs", 0 ) ) );
	attrs = newAV();
	for ( an = op->ors_attrs; an && an->an_name.bv_val; an++ ) {
		av_push( attrs, newSVberval( &an->an_name ) );
	}
	XPUSHs( sv_2mortal( newRV_noinc( (SV *) attrs ) ) );
}

void
pb_stack_process_search(
	pTHX_
	pSP_
	Operation *op,
	SlapReply *rs,
	I32 count
) {
        PerlBackendDatabase *pbdb = (PerlBackendDatabase *) op->o_bd->be_private;
	I32 i;

	for ( i = 1; i < count; i++ ) {
		SV *sv = POPs;

		if( rs->sr_err != LDAP_SIZELIMIT_EXCEEDED ) {
			int send_entry;
			Entry *e = sv2entry( aTHX_ sv );
			if( e == NULL ) {
				Debug( LDAP_DEBUG_ANY, "sv2entry failed in "
					"perl_back_search for entry #%d\n",
					i, 0, 0 );
				continue;
			}
 
			if( pbdb->pbdb_filter_search_results )
				send_entry = (test_filter( op, e, op->ors_filter ) == LDAP_COMPARE_TRUE);
			else
				send_entry = 1;
      
			if( send_entry ) {
				rs->sr_entry = e;
				rs->sr_attrs = op->ors_attrs;
				rs->sr_flags = REP_ENTRY_MODIFIABLE;
				rs->sr_err = LDAP_SUCCESS;
				rs->sr_err = send_search_entry( op, rs );
				if ( rs->sr_err == LDAP_SIZELIMIT_EXCEEDED ) {
					rs->sr_entry = NULL;
				}
			}

			entry_free( e );
		}
	}
}
