# This is a sample Perl module for the OpenLDAP server slapd.
# $OpenLDAP$
## This work is part of OpenLDAP Software <http://www.openldap.org/>.
##
## Copyright 1998-2013 The OpenLDAP Foundation.
## Portions Copyright 1999 John C. Quillan.
## Portions Copyright 2007 Dagobert Michelsen, Baltic Online Computer GmbH
## All rights reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted only as authorized by the OpenLDAP
## Public License.
##
## A copy of this license is available in the file LICENSE in the
## top-level directory of the distribution or, alternatively, at
## <http://www.OpenLDAP.org/license.html>.

# Usage: Add something like this to slapd.conf:
#
#	database	perl
#	suffix		"o=AnyOrg,c=US"
#	perlModulePath	/directory/containing/this/module
#	perlModule	SampleLDAP
#
# See the slapd-perl(5) manual page for details.
#
# This demo module keeps an in-memory hash {"DN" => "LDIF entry", ...}
# built in sub add{} & co.  The data is lost when slapd shuts down.

package SampleLDAP;
use strict;
use warnings;
use POSIX;

sub new
{
	my $class = shift;

	my $this = {};
	bless $this, $class;
        print STDERR "Here in new\n";
	print STDERR "Posix Var " . BUFSIZ . " and " . FILENAME_MAX . "\n";
	return $this;
}

sub init
{
	return 0;
}

sub bind
{
	return 0;
}

sub search
{
	my $this = shift;
	my($base, $scope, $deref, $sizeLim, $timeLim, $filterStr, $attrOnly, @attrs ) = @_;
        print STDERR "====$filterStr====\n";
	$filterStr =~ s/\(|\)//g;
	$filterStr =~ s/=/: /;

	my @match_dn = ();
	foreach my $dn ( keys %$this ) {
		if ( $this->{ $dn } =~ /$filterStr/im ) {
			push @match_dn, $dn;
			last if ( scalar @match_dn == $sizeLim );

		}
	}

	my @match_entries = ();
	
	foreach my $dn ( @match_dn )  {
		push @match_entries, $this->{ $dn };
	}

	return ( 0 , @match_entries );

}

sub compare
{
	my $this = shift;
	my ( $dn, $avaStr ) = @_;
	my $rc = 5; # LDAP_COMPARE_FALSE

	$avaStr =~ s/=/: /;

	if ( $this->{ $dn } =~ /$avaStr/im ) {
		$rc = 6; # LDAP_COMPARE_TRUE
	}

	return $rc;
}

sub modify
{
	my $this = shift;

	my ( $dn, @list ) = @_;

	while ( @list > 0 ) {
		my $action = shift @list;
		my $key    = shift @list;
		my $value  = shift @list;

		if( $action eq "ADD" ) {
			$this->{ $dn } .= "$key: $value\n";

		}
		elsif( $action eq "DELETE" ) {
			$this->{ $dn } =~ s/^$key:\s*$value\n//mi ;

		}
		elsif( $action eq "REPLACE" ) {
			$this->{ $dn } =~ s/$key: .*$/$key: $value/im ;
		}
	}

	return 0;
}

sub add
{
	my $this = shift;

	my ( $entryStr ) = @_;

	my ( $dn ) = ( $entryStr =~ /dn:\s(.*)$/m );

	#
	# This needs to be here until a normalized dn is
	# passed to this routine.
	#
	$dn = uc( $dn );
	$dn =~ s/\s*//g;


	$this->{$dn} = $entryStr;

	return 0;
}

sub modrdn
{
	my $this = shift;

	my ( $dn, $newdn, $delFlag ) = @_;

	$this->{ $newdn } = $this->{ $dn };

	if( $delFlag ) {
		delete $this->{ $dn };
	}
	return 0;

}

sub delete
{
	my $this = shift;

	my ( $dn ) = @_;
	
        print STDERR "XXXXXX $dn XXXXXXX\n";
	delete $this->{$dn};
}

sub config
{
	my $this = shift;

	my ( @args ) = @_;
        local $, = " - ";
        print STDERR @args;
        print STDERR "\n";
	return 0;
}

1;

__END__

=pod

=head1 NAME

OpenLDAP::Backend - Perl backend to OpenLDAP

=head1 DESCRIPTION

This module allows the implementation of backends in Perl.
It does this by embedding a Perl interpreter.
It supports many of the entry points
provided by OpenLDAP and allows easy and fast implementation
of prototypes and complex applications.

This backend is a complete reimplementation of the
original Perl backend.
The functional extensions made an API change necessary,
please see the section L<Differences to the old backend>
for details.

=head1 USAGE

The module works by defining a perl backend in C<slapd.conf> with
at least the following options:

  database        perl
  suffix          dc=test,dc=org
  perlModulePath  /<path>/<to>/<Perl>/<module>
  perlModule      <Module_in_path>

All requests to DNs below that suffix will be directed to
the Perl module. 

Any parameter unknown to the backend is passed as a custom
option to the backend:

  myConfig        myParameter_1 ... myParameter_n

The functions and methods are usually called with some
positional parameters in front and a list of named
parameters. Don't make any assumptions on the order
of named parameters as it may change in future versions.

Methods triggered by an operation always return a SlapReply in
form of a an error code represented by a single integer or by
a reference to a hash of the form
  { err => <error_code>, text => "<error_text>" }
If no error code is given the default is 0 (LDAP_SUCCESS).
If no error text is given the default is the empty string.

=head2 database specific calls

The following entry points have been implemented on the database
level:

=head3 new

This method is called on the module specified with C<perlModule> in C<slapd.conf>.
It must return a reference to an object representing the database. New connections
are spawned from this object.

=head3 init

This method is called when the database is opened .

=head3 config( file => <filename>, line => <lineno>, args => [<arg1>, ... <argn>], ... )

This method is called once for each unknown database configuration
line. The filename of the configuration file and the linenumber containing
the directive passed as named parameters.

=head3 open

(see init)

=head3 close

(no corresponding method)

=head3 destroy

(no corresponding method, when are objects destroyed?)

=head3 connection_init

This method is called on the database object for each connection to
the LDAP server. It should return a reference to an object on which
methods for operations on that connection are called.

=head2 connection specific calls

These methods are called on the connection object:

=head3 bind( <dn>, password => <password> )

This method is called on a bind request. Anonymous binds do not
issue a call to the bind method.

=head3 unbind

This method is called on the connection object.

=head3 search ( OPTIONS )

=over 4

=item base =E<gt> DN

Base DN

=item scope =E<gt> SCOPE

Defined the scope of the search. The value is a dual valued scaler
which contains the numeric value for the scope when accessed
as integer and the description when access as string. String
descriptions are

=over 4

=item *

base

=item *

one

=item *

sub

=back

=item deref =E<gt>

Defines if dereferencing of the request should occur. The value is a dual
valued scalar which contains the numerix value for dereferencing when access
as integer and the description when accessed as string. String descriptions are

=over 4

=item *

never

=item *

search

=item *

find

=item *

always

=back

=item sizelimit =E<gt> SIZELIMIT

Defines the maximum expected size of the reply.

=item timelimit =E<gt> TIMELIMIT

Defines the maximum time the operation should take.

=item filter =E<gt> FILTERSTRING

Defines the filter string.

=item typesonly =E<gt> (0 | 1)

Set if only types are requested.

=item attrs =E<gt> [ <attr_1>, ..., <attr_n> ]

List of requested attributes.

=item connection =E<gt> { <connection-details> }

Details about the connection issuing the request. See
L<connection argument> for details.

=item operation =E<gt> { <operation-details> }

Details about the operation.
See L<operation argument> for details.

=back

=head3 search


=head3 compare

 - modify
 - modrdn
 - add
 - delete
 - extended (password change)
 - connection_destroy

=head3 connection details

Some methods supply an additional argument for connection details.
Specifically these are L<add>, L<bind>, L<compare>, L<connection_init>,
L<connection_destroy>, L<delete>, L<extended>, L<extended>, L<modify>,
L<modrdn> and L<search>.

The following parameters are defined in the hash reference:

=over 4

=item *

conn_idx

=item *

peer_domain

=item *

peer_name

=back

For C<peer_domain> and C<peer_name> OpenLDAP must be compiled with C<--enable-rlookups>
to work.

In future versions more keys may be supplied in the hash.


=head3 operation details

Some methods supply additional information about the issuing operation.
Specifically these are L<add>, L<bind>, L<compare>, L<delete>, L<extended>,
L<modify>, L<modrdn> and L<search>.

The following parameters are defined in the hash reference:

=over 4

=item *

opid

=item *

connid

=back

=head2 Using more than one Perl database

=head1 CAVEATS

=head2 Differences to the old backend


=head1 REFERENCE SECTION

=head2 API reference

=head2 Slapd configuration options

 max_idle_interpreters

 lazy_connection_init

=head1 BUGS AND FUTURE FEATURES

 - dynamic config
 - data sharing
 - entry points: abandon, check_referrals, more extended ops

=head1 AUTHOR

Dagobert Michelsen

=cut
