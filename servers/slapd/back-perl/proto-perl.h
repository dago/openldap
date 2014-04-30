/* $OpenLDAP: pkg/ldap/servers/slapd/back-perl/proto-perl.h,v 1.2.2.5 2007/01/02 21:44:06 kurt Exp $ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2007 The OpenLDAP Foundation.
 * Portions Copyright 1999 John C. Quillan.
 * Portions Copyright 2002 myinternet Limited.
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

#ifndef PROTO_PERL_H
#define PROTO_PERL_H

LDAP_BEGIN_DECL

/*
 * config.c
 */

int perl_back_init_cf( BackendInfo *bi );
int perl_back_db_init_cf( BackendDB *be );

/*
 * former external.h
 */

extern BI_db_init	perl_back_db_init;
extern BI_db_open	perl_back_db_open;
extern BI_db_close	perl_back_db_close;
extern BI_db_destroy	perl_back_db_destroy;
extern BI_db_config	perl_back_db_config;

extern BI_connection_init	perl_back_connection_init;
extern BI_connection_destroy	perl_back_connection_destroy;

extern BI_op_func	perl_back_operation;
extern BI_op_modrdn	perl_back_modrdn;
extern BI_op_add	perl_back_add;
extern BI_op_delete	perl_back_delete;

extern BI_op_extended	perl_back_extended;

LDAP_END_DECL

#endif /* PROTO_PERL_H */
