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

void
pb_stack_prepare_add(
	pTHX_
	pSP_
	Operation	*op,
	SlapReply	*rs )
{
	Attribute *a;
	AV *av_attr;

	XPUSHs(sv_2mortal(newSVberval( &op->ora_e->e_name )));	/* dn (not normalized) */

	XPUSHs(sv_2mortal(newSVpv("attrs",0)));
	av_attr = newAV();
	for( a = op->ora_e->e_attrs; a != NULL; a = a->a_next ) {
		AV *av_values;
		int i;
                
		av_push(av_attr, newSVberval( &a->a_desc->ad_cname ));
               	av_values = newAV();
		for( i = 0; a->a_vals[i].bv_val != NULL; i++ ) {
			av_push(av_values, newSVberval( &a->a_vals[i] ));
		}
		av_push(av_attr, newRV((SV *) av_values));
	}
	XPUSHs(sv_2mortal(newRV_noinc( (SV *) av_attr)));
}
