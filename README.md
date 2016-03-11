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
5. [Versioning](#versioning)
6. [Testing](#testing)
7. [License and Author](#license-and-author)
8. [Contributing](#contributing)

## Requirements

### Platforms

This cookbook supports:

* 6.3

### Cookbooks

This cookbook depends upon:

* [iis](https://supermarket.chef.io/cookbooks/iis) (4.1.6)
* [windows](https://supermarket.chef.io/cookbooks/windows) (1.39.2)

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
  <tr>
    <td><tt>['certificate_services']['crl_distribution_point']['cdp']['physical_dir_path']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>C:\inetpub\cdp</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['crl_distribution_point']['cdp']['virtual_dir_path']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>/cdp</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['crl_distribution_point']['cps']['physical_dir_path']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>C:\inetpub\cps</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['crl_distribution_point']['cps']['virtual_dir_path']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>/cps</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['aia_url']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>nil</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['allow_administrator_interaction']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>false</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['alternate_signature_algorithm']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>true</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['caconfig_dir']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>C:\CAConfig</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['cdp_url']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>nil</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['clock_skew_minutes']</tt></td>
    <td>Int</td>
    <td>Some info about the attribute</td>
    <td><tt>10</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['common_name']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>nil</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['crl_delta_period']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>days</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['crl_delta_period_units']</tt></td>
    <td>Int</td>
    <td>Some info about the attribute</td>
    <td><tt>1</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['crl_overlap_period']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>hours</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['crl_overlap_units']</tt></td>
    <td>Int</td>
    <td>Some info about the attribute</td>
    <td><tt>12</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['crl_period']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>weeks</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['crl_period_units']</tt></td>
    <td>Int</td>
    <td>Some info about the attribute</td>
    <td><tt>2</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['database_path']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>C:\Windows\system32\CertLog</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['domain_pass']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>nil</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['domain_user']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>nil</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['enable_auditing_eventlogs']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>true</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['enable_key_counting']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>false</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['force_utf8']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>false</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['hash_algorithm']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>SHA256</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['key_length']</tt></td>
    <td>Int</td>
    <td>Some info about the attribute</td>
    <td><tt>4096</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['load_default_templates']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>false</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['log_path']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>C:\Windows\system32\CertLog</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['ocsp_url']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>nil</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['output_cert_request_file']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>nil</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['overwrite_existing_ca_in_ds']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>false</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['overwrite_existing_database']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>false</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['overwrite_existing_key']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>false</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['policy']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>nil</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['renewal_key_length']</tt></td>
    <td>Int</td>
    <td>Some info about the attribute</td>
    <td><tt>4096</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['renewal_validity_period']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>years</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['renewal_validity_period_units']</tt></td>
    <td>Int</td>
    <td>Some info about the attribute</td>
    <td><tt>5</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['root_crl_file']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>nil</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['root_crt_file']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>nil</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['validity_period']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>years</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['enterprise_subordinate_ca']['validity_period_units']</tt></td>
    <td>Int</td>
    <td>Some info about the attribute</td>
    <td><tt>2</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['aia_url']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>nil</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['allow_administrator_interaction']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>false</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['alternate_signature_algorithm']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>true</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['caconfig_dir']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>C:\CAConfig</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['cdp_url']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>nil</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['clock_skew_minutes']</tt></td>
    <td>Int</td>
    <td>Some info about the attribute</td>
    <td><tt>10</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['common_name']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>nil</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['crl_delta_period']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>days</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['crl_delta_period_units']</tt></td>
    <td>Int</td>
    <td>Some info about the attribute</td>
    <td><tt>0</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['crl_overlap_period']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>hours</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['crl_overlap_units']</tt></td>
    <td>Int</td>
    <td>Some info about the attribute</td>
    <td><tt>12</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['crl_period']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>weeks</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['crl_period_units']</tt></td>
    <td>Int</td>
    <td>Some info about the attribute</td>
    <td><tt>26</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['database_path']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>C:\Windows\system32\CertLog</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['enable_auditing_eventlogs']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>true</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['enable_key_counting']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>false</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['force_utf8']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>false</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['hash_algorithm']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>SHA256</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['key_length']</tt></td>
    <td>Int</td>
    <td>Some info about the attribute</td>
    <td><tt>4096</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['load_default_templates']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>false</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['log_path']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>C:\Windows\system32\CertLog</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['ocsp_url']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>nil</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['output_cert_request_file']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>nil</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['overwrite_existing_ca_in_ds']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>false</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['overwrite_existing_database']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>false</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['overwrite_existing_key']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>false</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['policy']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>nil</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['renewal_key_length']</tt></td>
    <td>Int</td>
    <td>Some info about the attribute</td>
    <td><tt>4096</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['renewal_validity_period']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>years</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['renewal_validity_period_units']</tt></td>
    <td>Int</td>
    <td>Some info about the attribute</td>
    <td><tt>20</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['validity_period']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>years</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['validity_period_units']</tt></td>
    <td>Int</td>
    <td>Some info about the attribute</td>
    <td><tt>10</tt></td>
  </tr>
  <tr>
    <td><tt>['certificate_services']['standalone_root_ca']['windows_domain']</tt></td>
    <td>String</td>
    <td>Some info about the attribute</td>
    <td><tt>nil</tt></td>
  </tr>
</table>

## Recipes

### Public Recipes

#### `certificate_services::certificate_authority_web_enrollment`

TODO: *Explain what the recipe does here*

#### `certificate_services::certificate_enrollment_policy_web_service`

TODO: *Explain what the recipe does here*

#### `certificate_services::certificate_enrollment_web_service`

TODO: *Explain what the recipe does here*

#### `certificate_services::crl_distribution_point`

Installs and configures IIS with virtual directories for CDP and CPS

#### `certificate_services::enterprise_subordinate_ca`

Installs and configures an online Enterprise Subordinate CA

#### `certificate_services::network_device_enrollment_service`

TODO: *Explain what the recipe does here*

#### `certificate_services::ocsp`

TODO: *Explain what the recipe does here*

#### `certificate_services::standalone_root_ca`

Installs and configures an offline Standalone Root CA

## Versioning

This cookbook uses [Semantic Versioning 2.0.0](http://semver.org/).

Given a version number MAJOR.MINOR.PATCH, increment the:

* MAJOR version when you make functional cookbook changes,
* MINOR version when you add functionality in a backwards-compatible manner,
* PATCH version when you make backwards-compatible bug fixes.

## Testing

    rake foodcritic                              # Run Foodcritic lint checks
    rake integration                             # Alias for kitchen:all
    rake kitchen:DomainController-windows2012r2  # Run DomainController-windows2012r2 test instance
    rake kitchen:StandaloneRootCA-windows2012r2  # Run StandaloneRootCA-windows2012r2 test instance
    rake kitchen:SubordinateCA-windows2012r2     # Run SubordinateCA-windows2012r2 test instance
    rake kitchen:Web-windows2012r2               # Run Web-windows2012r2 test instance
    rake kitchen:all                             # Run all test instances
    rake rubocop                                 # Run RuboCop style and lint checks
    rake rubocop:auto_correct                    # Auto-correct RuboCop offenses
    rake spec                                    # Run ChefSpec examples
    rake test                                    # Run all tests

## License and Author

Authors and contributors:

* Stephen Hoekstra <shoekstra@schubergphilis.com>

Copyright (c) 2015, Schuberg Philis, All Rights Reserved.

## Contributing

We welcome contributed improvements and bug fixes via the usual work flow:

1. Fork this repository
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new pull request
