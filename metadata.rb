name             'certificate_services'
maintainer       'Stephen Hoekstra'
maintainer_email 'shoekstra@schubergphilis.com'
license          'Apache-2.0'
description      'Cookbook to install and configure Active Directory Certificate Services'
source_url       'https://github.com/shoekstra/chef-certificate_services'
issues_url       'https://github.com/shoekstra/chef-certificate_services/issues'
version          '0.1.0'

chef_version '>= 14'

supports 'windows', '>= 6.3'

depends 'iis'
depends 'pspki', '~> 0.2'
depends 'windows'
