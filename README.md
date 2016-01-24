# certificate_services

Cookbook to install and configure Active Directory Certificate Services

## Table of contents

1. [Requirements](#requirements)
    * [Platforms](#platforms)
    * [Cookbooks](#cookbooks)
2. [Usage](#usage)
3. [Attributes](#attributes)
4. [Recipes](#recipes)
    * [Public Recipes](#public-recipes)
    * [Private Recipes](#private-recipes)
5. [Versioning](#versioning)
6. [Testing](#testing)
7. [License and Author](#license-and-author)
8. [Contributing](#contributing)

## Requirements

### Platforms

This cookbook supports:


### Cookbooks

This cookbook does not depend on any other cookbooks.

## Usage

TODO: *Explain how to use the cookbook*

## Attributes

Attributes in this cookbook:

<table>
  <tr>
    <th>Key</th>
    <th>Type</th>
    <th>Description</th>
    <th>Default</th>
  </tr>
</table>

## Recipes

### Public Recipes

#### `certificate_services::default`

Installs and configures the application.

### Private Recipes

#### `certificate_services::_nrpe`

Installs and configures NRPE scripts and checks for Nagios monitoring if the `nrpe` cookbook is included earlier in the run-list.

#### `certificate_services::_selinux`

Configures required SELinux settings if certificate_services is installed on an SELinux enabled system.

## Versioning

This cookbook uses [Semantic Versioning 2.0.0](http://semver.org/).

Given a version number MAJOR.MINOR.PATCH, increment the:

* MAJOR version when you make functional cookbook changes,
* MINOR version when you add functionality in a backwards-compatible manner,
* PATCH version when you make backwards-compatible bug fixes.

## Testing

    rake foodcritic                 # Run Foodcritic lint checks
    rake integration                # Alias for kitchen:all
    rake kitchen:all                # Run all test instances
    rake kitchen:default-centos-67  # Run default-centos-67 test instance
    rake kitchen:default-centos-71  # Run default-centos-71 test instance
    rake rubocop                    # Run RuboCop style and lint checks
    rake rubocop:auto_correct       # Auto-correct RuboCop offenses
    rake spec                       # Run ChefSpec examples
    rake test                       # Run all tests

## License and Author

Authors and contributors:

* Daniel Paulus <dpaulus@schubergphilis.com>
* Sander van Harmelen <sander@xanzy.io>
* Sander van Harmelen <svanharmelen@schubergphilis.com>
* Stephen Hoekstra <shoekstra@schubergphilis.com>

Copyright (c) 2015, Schuberg Philis, All Rights Reserved.

## Contributing

We welcome contributed improvements and bug fixes via the usual work flow:

1. Fork this repository
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new pull request
