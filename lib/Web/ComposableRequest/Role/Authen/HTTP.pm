package Web::ComposableRequest::Role::Authen::HTTP;

use 5.010001;
use namespace::autoclean;
use version; our $VERSION = qv( sprintf '0.1.%d', q$Rev: 7 $ =~ /\d+/gmx );

use Authen::HTTP::Signature::Parser;
use Convert::SSH2;
use Digest                            qw( );
use HTTP::Status                      qw( HTTP_EXPECTATION_FAILED );
use Try::Tiny;
use Web::ComposableRequest::Constants qw( EXCEPTION_CLASS NUL );
use Web::ComposableRequest::Exception::Authen::HTTP;
use Web::ComposableRequest::Util      qw( add_config_role is_member throw );
use Unexpected::Functions             qw( ChecksumFailure MissingHeader
                                          MissingKey SigParserFailure
                                          SigVerifyFailure Unspecified );
use Moo::Role;

requires qw( _config _content _env );

add_config_role __PACKAGE__.'::Config';

my $public_key_cache = {};

# Private functions
my $_class2appdir = sub {
   (my $v = $_[ 0 ] // NUL) =~ s{ :: }{-}gmx; return lc $v;
};

my $_read_public_key = sub {
   my ($config, $key_id) = @_;

   my $key      = $public_key_cache->{ $key_id }; $key and return $key;
   my $prefix   = $_class2appdir->( $config->appclass );
   my $key_file = $config->ssh_dir->catfile( "${prefix}_${key_id}.pub" );

   try   { $key = Convert::SSH2->new( $key_file->all )->format_output }
   catch { throw MissingKey, error => $_ };

   return $public_key_cache->{ $key_id } = $key;
};

# Public mehhods
sub authenticate_headers {
   my $self = shift; my $sig;

   try   { $sig = Authen::HTTP::Signature::Parser->new( $self )->parse() }
   catch { throw SigParserFailure, error => $_ };

   $sig->key_id
      or throw Unspecified, [ 'key id' ], rv => HTTP_EXPECTATION_FAILED;

   if (is_member 'content-sha512', $sig->headers) {
      my $digest = Digest->new( 'SHA-512' ); $digest->add( $self->_content );

      $self->header( 'content-sha512' ) eq $digest->hexdigest
         or throw ChecksumFailure, [ $sig->key_id ];
   }
   elsif ($sig->headers->[ 0 ] ne 'request-line') {
      throw MissingHeader, [ $sig->key_id ];
   }

   $sig->key( $_read_public_key->( $self->_config, $sig->key_id ) );

   $sig->verify or throw SigVerifyFailure, [ $sig->key_id ];

   return; # Authentication was successful
}

sub header {
   my ($self, $name) = @_; $name =~ s{ [\-] }{_}gmx; $name = uc $name;

   exists $self->_env->{ "HTTP_${name}" }
      and return $self->_env->{ "HTTP_${name}" };

   return $self->_env->{ $name };
}

package Web::ComposableRequest::Role::Authen::HTTP::Config;

use namespace::autoclean;

use File::DataClass::Types     qw( Directory NonEmptySimpleStr );
use File::DataClass::Constants qw( TRUE );
use File::HomeDir;
use Moo::Role;

has 'appclass' => is => 'lazy', isa => NonEmptySimpleStr, required => TRUE;

has 'my_home'  => is => 'lazy', isa => Directory, coerce => TRUE,
   builder     => sub { File::HomeDir->my_home };

has 'ssh_dir'  => is => 'lazy', isa => Directory, coerce => TRUE,
   builder     => sub { $_[ 0 ]->my_home->catdir( '.ssh' ) };

1;

__END__

=pod

=encoding utf-8

=head1 Name

Web::ComposableRequest::Role::Authen::HTTP - Authenticates HTTP request headers

=head1 Synopsis

   use Moo;

   extends 'Web::ComposableRequest::Base';
   with    'Web::ComposableRequest::Role::Authen::HTTP';

=head1 Description

Authenticates HTTP request headers

=head1 Configuration and Environment

Defines the following configuration attributes;

=over 3

=item C<appclass>

Required non empty simple string which is used to create a prefix for the
public key file

=item C<my_home>

The users home directory as determined by L<File::HomeDir>

=item C<ssh_dir>

The directory containing SSH public keys. Defaults to F<~/.ssh>

=back

=head1 Subroutines/Methods

=head2 C<authenticate_headers>

Authenticates the request headers

=head2 C<header>

Retrieves request header values. Try prefixing the supplied name with
C<HTTP_>. If that value does not exists just trys the name. Attribute name
is uppercased either way

=head1 Diagnostics

None

=head1 Dependencies

=over 3

=item L<Authen::HTTP::Signature>

=item L<Convert::SSH2>

=item L<HTTP::Message>

=item L<Moo>

=item L<Unexpected>

=item L<Web::ComposableRequest>

=back

=head1 Incompatibilities

There are no known incompatibilities in this module

=head1 Bugs and Limitations

There are no known bugs in this module. Please report problems to
http://rt.cpan.org/NoAuth/Bugs.html?Dist=Web-ComposableRequest-Role-Authen-HTTP.
Patches are welcome

=head1 Acknowledgements

Larry Wall - For the Perl programming language

=head1 Author

Peter Flanigan, C<< <pjfl@cpan.org> >>

=head1 License and Copyright

Copyright (c) 2015 Peter Flanigan. All rights reserved

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself. See L<perlartistic>

This program is distributed in the hope that it will be useful,
but WITHOUT WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE

=cut

# Local Variables:
# mode: perl
# tab-width: 3
# End:
# vim: expandtab shiftwidth=3:
