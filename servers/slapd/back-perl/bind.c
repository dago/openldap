/* $OpenLDAP: pkg/ldap/servers/slapd/back-perl/bind.c,v 1.22.2.4 2007/01/02 21:44:06 kurt Exp $ */
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
pb_stack_prepare_bind(
	pTHX_
	pSP_
	Operation *op,
	SlapReply *rs )
{
	XPUSHs( sv_2mortal( newSVberval( &op->o_req_dn ) ) );
	XPUSHs( sv_2mortal( newSVpv( "password", 0 ) ) );
	XPUSHs( sv_2mortal( newSVberval( &op->orb_cred ) ) );
}

