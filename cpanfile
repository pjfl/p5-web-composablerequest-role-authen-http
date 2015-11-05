requires "Authen::HTTP::Signature" => "0.03";
requires "Convert::SSH2" => "0.01";
requires "File::DataClass" => "v0.66.0";
requires "File::HomeDir" => "1.00";
requires "HTTP::Message" => "6.06";
requires "Moo" => "2.000001";
requires "Try::Tiny" => "0.22";
requires "Unexpected" => "v0.40.0";
requires "Web::ComposableRequest" => "v0.4.0";
requires "namespace::autoclean" => "0.26";
requires "perl" => "5.010001";

on 'build' => sub {
  requires "Module::Build" => "0.4004";
  requires "version" => "0.88";
};

on 'test' => sub {
  requires "File::Spec" => "0";
  requires "Module::Build" => "0.4004";
  requires "Module::Metadata" => "0";
  requires "Sys::Hostname" => "0";
  requires "Test::Requires" => "0.06";
  requires "version" => "0.88";
};

on 'test' => sub {
  recommends "CPAN::Meta" => "2.120900";
};

on 'configure' => sub {
  requires "Module::Build" => "0.4004";
  requires "version" => "0.88";
};
