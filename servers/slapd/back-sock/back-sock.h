/* sock.h - socket backend header file */
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

#ifndef SLAPD_SOCK_H
#define SLAPD_SOCK_H

#include "proto-sock.h"
#include <jansson.h>

LDAP_BEGIN_DECL

struct sockinfo {
	const char	*si_sockpath;
	slap_mask_t	si_extensions;
    json_t      *si_cookie;
};

#define	SOCK_EXT_BINDDN	1
#define	SOCK_EXT_PEERNAME	2
#define	SOCK_EXT_SSF		4

extern FILE *opensock LDAP_P((
	const char *sockpath));

extern void sock_print_suffixes LDAP_P((
	FILE *fp,
	BackendDB *bd));

extern int json_object_add_suffixes LDAP_P((
	json_t *j,
	BackendDB *bd));

extern void sock_print_conn LDAP_P((
	FILE *fp,
	Connection *conn,
	struct sockinfo *si));

extern int json_object_add_conn LDAP_P((
	json_t *j,
	Connection *conn,
	struct sockinfo *si));

extern int sock_read_and_send_results LDAP_P((
	Operation *op,
	SlapReply *rs,
	json_t *result));

extern Entry *json2entry LDAP_P((
	json_t *j));

static
json_t *json_stringbv(struct berval *bv)
{
    return json_stringn(bv->bv_val, bv->bv_len);
}

LDAP_END_DECL

#endif
