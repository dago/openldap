# $OpenLDAP: pkg/ldap/servers/slapd/back-perl/add.c,v 1.18.2.4 2007/01/02 21:44:06 kurt Exp $ */
# This work is part of OpenLDAP Software <http://www.openldap.org/>.
#
# Copyright 2007 The OpenLDAP Foundation.
# Copyright 2007 Dagobert Michelsen, Baltic Online Computer GmbH.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted only as authorized by the OpenLDAP
# Public License.
#
# A copy of this license is available in file LICENSE in the
# top-level directory of the distribution or, alternatively, at
# <http://www.OpenLDAP.org/license.html>.

package PerlLDAPProxy;

use Data::Dumper;

=pod

=head1 NAME

PerlLDAPProxy - Proxy that maps LDAP requests to Net::LDAP

=head1 SYNOPSIS

The following entries are needed to configure this module:

  perlModulePath /path/to/libs
  perlModule     PerlLDAPProxy
  ldapServer     ldap.mydomain

=head1 DESCRIPTION

This module is an example of how requests can be forwarded
to other LDAP servers and processed prior or after transmission.
It is meant to be used for demonstration purposes only as this can
be done more eficiently with back-ldap and back-meta.

=head1 METHODS

The following methods have been implemented:

=head2 new

The constructor takes the name of the class and a reference to the old-style object
as parameters. A reference to the translation object is returned.

=cut

sub new {
  print "new: ", Dumper( @_ );
  my ($class) = @_;

  my $translation = bless {
  }, $class;

  return $translation;
}

=pod

=head2 config

The C<config> method is called for each unrecognized config line and mapped
through to the old-style object.

=cut

sub config {
  print "config: ", Dumper( @_ );
  my ($this, @args) = @_;
  my $rc = 1;

  if( lc $args[0] eq 'ldapserver' ) {
    $this->{ldapserver} = $args[1];
    $rc = 0;
  }
  return $rc;
}

=pod

=head2 init

The C<init> method is called in scalar context without parameters.

=cut

sub init {
  print "init: ", Dumper( @_ );
  my ($this) = @_;

  my $ldap = Net::LDAP->new( $this->{ldapserver} );
  $this->{ldap} = $ldap;

  return 0;	# No error
}

=pod

=head2 bind

The C<bind> method is called with the C<dn> and the password to bind with.

=cut

sub bind {
  print "bind: ", Dumper( @_ );

  my ($this, $dn, %args) = @_;
  $this->{ldap}->bind( $dn, (exists $args{password} ? password => $args{password} : ()) );

  return;
}

=pod

=head2 unbind

The C<unbind> method was not present in the legacy API and is therefore ignored.

=cut

sub unbind {
  print "unbind: ", Dumper( @_ );
  # This method intentionally left blank
}

=pod

=head2 connection_init

Connection management was not present in the legacy API and C<connection_init> is
not mapped. The requests for all connections are mapped to the legacy object.

=cut

sub connection_init {
  print "connection_init: ", Dumper( @_ );
  my ($this) = @_;

  # Legacy API does not have connections. Return this translation
  # object for all connections
  return $this;
}

=pod

=head2 connection_destroy

Connection management was not present in the legacy API and C<connection_init> is
therefore not mapped.

=cut

sub connection_destroy {
  print "connection_destroy: ", Dumper( @_ );
  # This method intentionally left blank
}

=pod

=head2 add

The C<add> method is called for each unrecognized config line and mapped
through to the old-style object.

=cut

sub add {
  print "add: ", Dumper( @_ );
  my ($this, $element) = @_;

  return $this->{legacy_object}->add( $element );
}

=pod

=head2 modify

The C<modify> method is called with the mapped arguments.

=cut

sub modify {
  print "modify: ", Dumper( @_ );
  my ($this, @args) = @_;

  return $this->{legacy_object}->modify( @args );
}

=pod

=head2 search

The C<search> method is called with the mapped arguments.

=cut

sub search {
  print "search: ", Dumper( @_ );
  my ($this, %args) = @_;

  my $base =	$args{base};
  my $scope =	$args{scope} eq "base"	? 0 :
		$args{scope} eq "one"	? 1 :
		$args{scope} eq "sub"	? 2 :
		$args{scope};
  my $deref =	$args{deref} eq "never"	? 0 :
		$args{deref} eq "search" ? 1 :
		$args{deref} eq "find"	? 2 :
		$args{deref} eq "always" ? 3 :
		$args{deref};
  my $sizelimit = $args{sizelimit};
  my $timelimit = $args{timelimit};
  my $filter = $args{filter};
  my $attrsonly = $args{typesonly};
  my @attrs = @{$args{attrs}};

  return $this->{legacy_object}->search(
	$base,
	$scope,
	$deref,
	$sizelimit,
	$timelimit,
	$filter,
	$attrsonly,
	@attrs
  );
}

=pod

=head2 compare

The C<compare> method is called with the mapped arguments.

=cut

sub compare {
  print "compare: ", Dumper( @_ );
  my ($this, $dn, $ava) = @_;

  return $this->{legacy_object}->compare( $dn, $ava );
}

=pod

=head2 modrdn

The C<modrdn> method is called with the mapped arguments.

=cut

sub modrdn {
  print "modrdn: ", Dumper( @_ );
  my ($this, $dn, $new_rdn, $delete_old_rdn) = @_;

  return $this->{legacy_object}->modrdn( $dn, $new_rdn, $delete_old_rdn );
}

=pod

=head2 delete

The C<delete> method is called with the mapped arguments.

=cut

sub delete {
  print "delete: ", Dumper( @_ );
  my ($this, $dn) = @_;

  my $mesg = $this->{ldap}->delete( $dn );
  return { err => $mesg->code, text => $mesg->error() };
}

=pod

=head1 AUTHOR

Copyright 2007 Dagobert Michelsen

=head1 SEE ALSO

L<slapd-perl(5)>

=cut

1;
