use strict;
use warnings;

use Module::Build 0.4004;

my $perl_ver = 5.010001;
my $name     = 'Web-ComposableRequest-Role-Authen-HTTP'; $name =~ s{ - }{::}gmx;
my $prereqs  = {
  'build_requires' => {
    'Module::Build' => '0.4004',
    'version' => '0.88'
  },
  'configure_requires' => {
    'Module::Build' => '0.4004',
    'version' => '0.88'
  },
  'requires' => {
    'Authen::HTTP::Signature' => '0.03',
    'Convert::SSH2' => '0.01',
    'File::DataClass' => 'v0.66.0',
    'File::HomeDir' => '1.00',
    'HTTP::Message' => '6.06',
    'Moo' => '2.000001',
    'Try::Tiny' => '0.22',
    'Unexpected' => 'v0.40.0',
    'Web::ComposableRequest' => 'v0.4.0',
    'namespace::autoclean' => '0.26',
    'perl' => '5.010001'
  },
  'test_requires' => {
    'File::Spec' => '0',
    'Module::Build' => '0.4004',
    'Module::Metadata' => '0',
    'Sys::Hostname' => '0',
    'Test::Requires' => '0.06',
    'version' => '0.88'
  },
};
my $testing  = sub { $ENV{AUTOMATED_TESTING}
                  || $ENV{PERL_CPAN_REPORTER_CONFIG}
                  || $ENV{PERL5_CPANPLUS_IS_VERSION} };
my $whimper  = sub { print {*STDOUT} $_[ 0 ]."\n"; exit 0 };
my $stop     = sub {
   $testing->() or $whimper->( $_[ 0 ] );
   $prereqs->{build_requires} = { %{ $prereqs->{configure_requires} } };
   $prereqs->{test_requires } = { %{ $prereqs->{configure_requires} } };
   $prereqs->{test_requires }->{ 'Test::Requires' } = 0.06;
   delete $prereqs->{requires};
};

# Not interested in reports below min perl ver
$] < $perl_ver and $stop->( "Minimum required Perl version is ${perl_ver}" );

Module::Build->new(
   'module_name' => $name,
   'notes'       => { min_perl_version => $perl_ver, testing => $testing->() },
   %{ $prereqs },

)->create_build_script;

exit 0;
