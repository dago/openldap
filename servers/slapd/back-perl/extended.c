/* $OpenLDAP: pkg/ldap/servers/slapd/back-perl/modify.c,v 1.15.2.6 2004/04/28 23:23:16 kurt Exp $ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2004 The OpenLDAP Foundation.
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

/*
 * See servers/slapd/passwd.c for functional details
 */

void
pb_stack_prepare_extended(
	pTHX_
	pSP_
	Operation	*op,
	SlapReply	*rs )
{
	req_pwdexop_s *qpw = &op->oq_pwdexop;

	XPUSHs(sv_2mortal(newSVberval( &op->o_req_dn )));

	if( qpw->rs_old.bv_val != NULL ) {
		XPUSHs(sv_2mortal(newSVpv( "oldpassword", 0 )));
		XPUSHs(sv_2mortal(newSVberval( &qpw->rs_old )));
	}
	if( qpw->rs_new.bv_val != NULL ) {
		XPUSHs(sv_2mortal(newSVpv( "newpassword", 0 )));
		XPUSHs(sv_2mortal(newSVberval( &qpw->rs_new )));
	}
}
