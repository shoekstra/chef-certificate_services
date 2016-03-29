name             'certificate_services'
maintainer       'Stephen Hoekstra'
maintainer_email 'shoekstra@schubergphilis.com'
license          'All rights reserved'
description      'Cookbook to install and configure Active Directory Certificate Services'
version          '0.1.0'

recipe           'certificate_services::crl_distribution_point', 'Installs and configures IIS with virtual directories for CDP and CPS'
recipe           'certificate_services::enterprise_subordinate_ca', 'Installs and configures an online Enterprise Subordinate CA'
recipe           'certificate_services::standalone_root_ca', 'Installs and configures an offline Standalone Root CA'

supports         'windows', '= 6.3'

depends 'iis', '~> 4.1.6'
depends 'windows', '= 1.38.2'
