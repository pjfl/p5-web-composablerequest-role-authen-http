# Name

Web::ComposableRequest::Role::Authen::HTTP - Authenticates HTTP request headers

# Synopsis

    use Moo;

    extends 'Web::ComposableRequest::Base';
    with    'Web::ComposableRequest::Role::Authen::HTTP';

# Description

Authenticates HTTP request headers

# Configuration and Environment

Defines the following configuration attributes;

- `appclass`

    Required non empty simple string which is used to create a prefix for the
    public key file

- `my_home`

    The users home directory as determined by [File::HomeDir](https://metacpan.org/pod/File%3A%3AHomeDir)

- `ssh_dir`

    The directory containing SSH public keys. Defaults to `~/.ssh`

# Subroutines/Methods

## `authenticate_headers`

Authenticates the request headers

## `header`

Retrieves request header values. Try prefixing the supplied name with
`HTTP_`. If that value does not exists just trys the name. Attribute name
is uppercased either way

# Diagnostics

None

# Dependencies

- [Authen::HTTP::Signature](https://metacpan.org/pod/Authen%3A%3AHTTP%3A%3ASignature)
- [Convert::SSH2](https://metacpan.org/pod/Convert%3A%3ASSH2)
- [HTTP::Message](https://metacpan.org/pod/HTTP%3A%3AMessage)
- [Moo](https://metacpan.org/pod/Moo)
- [Unexpected](https://metacpan.org/pod/Unexpected)
- [Web::ComposableRequest](https://metacpan.org/pod/Web%3A%3AComposableRequest)

# Incompatibilities

There are no known incompatibilities in this module

# Bugs and Limitations

There are no known bugs in this module. Please report problems to
http://rt.cpan.org/NoAuth/Bugs.html?Dist=Web-ComposableRequest-Role-Authen-HTTP.
Patches are welcome

# Acknowledgements

Larry Wall - For the Perl programming language

# Author

Peter Flanigan, `<pjfl@cpan.org>`

# License and Copyright

Copyright (c) 2016 Peter Flanigan. All rights reserved

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself. See [perlartistic](https://metacpan.org/pod/perlartistic)

This program is distributed in the hope that it will be useful,
but WITHOUT WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE
