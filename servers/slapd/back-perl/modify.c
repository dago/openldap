/* $OpenLDAP: pkg/ldap/servers/slapd/back-perl/modify.c,v 1.21.2.5 2007/01/02 21:44:06 kurt Exp $ */
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

void
pb_stack_prepare_modify(
	pTHX_
	pSP_
	Operation	*op,
	SlapReply	*rs
) {
	Modifications *modlist;
	AV *av_changes;

	XPUSHs(sv_2mortal(newSVberval( &op->o_req_dn )));

	XPUSHs(sv_2mortal(newSVpv("changes", 0 )));
	av_changes = newAV();
	for( modlist = op->orm_modlist; modlist != NULL; modlist = modlist->sml_next ) {
		Modification *mods = &modlist->sml_mod;
		AV *av_op, *av_values;
		int i;

		switch ( mods->sm_op & ~LDAP_MOD_BVALUES ) {
			case LDAP_MOD_ADD:
				av_push(av_changes,newSVpv("add", 0));
				break;
			case LDAP_MOD_DELETE:
				av_push(av_changes,newSVpv("delete", 0));
				break;
			case LDAP_MOD_REPLACE:
				av_push(av_changes,newSVpv("replace", 0));
				break;
		}

		av_op = newAV();
		av_push(av_op, newSVberval( &mods->sm_desc->ad_cname ));

		av_values = newAV();
		for ( i = 0; mods->sm_values != NULL && mods->sm_values[i].bv_val != NULL; i++ ) {
			av_push(av_values, newSVberval( &mods->sm_values[i] ));
		}

		av_push(av_op, newRV((SV *) av_values));
		av_push(av_changes, newRV((SV *) av_op));
	}
	XPUSHs(sv_2mortal(newRV( (SV *) av_changes)));
}
