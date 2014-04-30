
package BackPerlLegacyAPI;

use Data::Dumper;

=pod

=head1 NAME

BackPerlLegacyAPI - Maps OpenLDAP Perl methods to legacy API format

=head1 SYNOPSIS

To use an existing OpenLDAP Perl backend module you can use this module
to translate the API-calls to the old style format. Enter this module in
slapd.conf and provide the existing module name:

  perl-module-path        %prefix/etc/openldap
  perl-module-name        BackPerlLegacyAPI
  old-perl-module-path    <path_to_old_module>
  old-perl-module-name    <name_of_old_module>

=head1 DESCRIPTION

The back-perl API to Perl methods have changed. To continue using existing
Perl backends this module maps the method calls from the Perl backend
to the old-style format by transforming the arguments to the old format
and by providing stubs for new methods which have not been defined in the old backend.

=head1 METHODS

The following methods have been implemented:

=head2 new

The constructor takes the name of the class and a reference to the old-style object
as parameters. A reference to the translation object is returned.

Please note that the old-style object already exists when this method is called.

=cut

sub new {
  print "new: ", Dumper( @_ );
  my ($class) = @_;

  my $translation = bless {
  }, $class;

  return $translation;
}

sub open {
  my ($class) = @_;
  print STDERR "open: ", Dumper( @_ ), "\n";

  return bless {}, $class;
}

=pod

=head2 init

The C<init> method is called in scalar context without parameters.

=cut

sub init {
  print "init: ", Dumper( @_ );
  my ($this) = @_;
  return $this;
#  return $this->{legacy_object}->init();
}

=pod

=head2 bind

The C<bind> method is called with the C<dn> and the password to bind with.

=cut

sub bind {
  print "bind: ", Dumper( @_ );

  my ($this, $dn, %args) = @_;

  return $this->{legacy_object}->bind( $dn, $args{password} );
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

=head2 config

The C<config> method is called for each unrecognized config line and mapped
through to the old-style object.

=cut

sub config {
  print "config: ", Dumper( @_ );
  my ($this, %args) = @_;
  my ($param, $arg)  = @{$args{args}};

  if( $param eq 'legacy-perl-module-path' ) {
    push @INC, $arg;
    return 0;
  } elsif( $param eq 'legacy-perl-module-name' ) {
print STDERR "XXXXXXXXX\n";
    require $arg . '.pm';
    $this->{legacy_object} = new $arg;
    return 0;
  } else {
    return $this->{legacy_object}->config( @args );
  }
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
  my $scope =	$args{scope} + 0;
  my $deref =	$args{deref} + 0;
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

  return $this->{legacy_object}->delete( $dn );
}

=pod

=head1 AUTHOR

Copyright 2005-2007 Dagobert Michelsen

=head1 SEE ALSO

L<slapd-perl(5)>

=cut

1;
