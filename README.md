# Name

Web::ComposableRequest::Role::Authen::HTTP - Authenticates HTTP request headers

# Synopsis

    use Moo;

    extends 'Web::ComposableRequest::Base';
    with    'Web::ComposableRequest::Role::Authen::HTTP';

# Description

Authenticates HTTP request headers

# Configuration and Environment

Defines the following attributes;

- `my_home`

    The users home directory as determined by [File::HomeDir](https://metacpan.org/pod/File::HomeDir)

- `ssh_dir`

    The directory containing SSH public keys. Defaults to `~/.ssh`

# Subroutines/Methods

## `authenticate`

Authenticates the request headers

## `header`

Retrieves request header values

# Diagnostics

None

# Dependencies

- [Authen::HTTP::Signature](https://metacpan.org/pod/Authen::HTTP::Signature)
- [Convert::SSH2](https://metacpan.org/pod/Convert::SSH2)
- [HTTP::Message](https://metacpan.org/pod/HTTP::Message)
- [Moo](https://metacpan.org/pod/Moo)
- [Unexpected](https://metacpan.org/pod/Unexpected)
- [Web::ComposableRequest](https://metacpan.org/pod/Web::ComposableRequest)

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

Copyright (c) 2015 Peter Flanigan. All rights reserved

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself. See [perlartistic](https://metacpan.org/pod/perlartistic)

This program is distributed in the hope that it will be useful,
but WITHOUT WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE
