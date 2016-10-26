#
# Cookbook Name:: certificate_services
# Attributes:: default
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

# Default values for a Standalone Root CA

default['certificate_services']['standalone_root_ca']['aia_url']                                = nil
default['certificate_services']['standalone_root_ca']['allow_administrator_interaction']        = false
default['certificate_services']['standalone_root_ca']['alternate_signature_algorithm']          = false
default['certificate_services']['standalone_root_ca']['caconfig_dir']                           = 'C:\CAConfig'
default['certificate_services']['standalone_root_ca']['cdp_url']                                = nil
default['certificate_services']['standalone_root_ca']['clock_skew_minutes']                     = 10
default['certificate_services']['standalone_root_ca']['common_name']                            = nil
default['certificate_services']['standalone_root_ca']['crl_delta_period']                       = 'days'
default['certificate_services']['standalone_root_ca']['crl_delta_period_units']                 = 0
default['certificate_services']['standalone_root_ca']['crl_overlap_period']                     = 'hours'
default['certificate_services']['standalone_root_ca']['crl_overlap_units']                      = 12
default['certificate_services']['standalone_root_ca']['crl_period']                             = 'weeks'
default['certificate_services']['standalone_root_ca']['crl_period_units']                       = 26
default['certificate_services']['standalone_root_ca']['crypto_provider']                        = 'RSA#Microsoft Software Key Storage Provider'
default['certificate_services']['standalone_root_ca']['database_directory']                     = 'C:\Windows\system32\CertLog'
default['certificate_services']['standalone_root_ca']['enable_auditing_eventlogs']              = true
default['certificate_services']['standalone_root_ca']['enable_key_counting']                    = false
default['certificate_services']['standalone_root_ca']['enhanced_key_usage']                     = nil
default['certificate_services']['standalone_root_ca']['force_utf8']                             = false
default['certificate_services']['standalone_root_ca']['hash_algorithm']                         = 'SHA256'
default['certificate_services']['standalone_root_ca']['key_length']                             = 4096
default['certificate_services']['standalone_root_ca']['load_default_templates']                 = false
default['certificate_services']['standalone_root_ca']['ocsp_url']                               = nil
default['certificate_services']['standalone_root_ca']['overwrite_existing_ca_in_ds']            = false
default['certificate_services']['standalone_root_ca']['overwrite_existing_database']            = false
default['certificate_services']['standalone_root_ca']['overwrite_existing_key']                 = false
default['certificate_services']['standalone_root_ca']['policy']                                 = nil
default['certificate_services']['standalone_root_ca']['renewal_key_length']                     = 4096
default['certificate_services']['standalone_root_ca']['renewal_validity_period']                = 'years'
default['certificate_services']['standalone_root_ca']['renewal_validity_period_units']          = 10
default['certificate_services']['standalone_root_ca']['validity_period']                        = 'years'
default['certificate_services']['standalone_root_ca']['validity_period_units']                  = 5
default['certificate_services']['standalone_root_ca']['windows_domain']                         = nil

# Default values for an Enterprise Subordinate CA

default['certificate_services']['enterprise_subordinate_ca']['aia_url']                         = nil
default['certificate_services']['enterprise_subordinate_ca']['allow_administrator_interaction'] = false
default['certificate_services']['enterprise_subordinate_ca']['alternate_signature_algorithm']   = false
default['certificate_services']['enterprise_subordinate_ca']['caconfig_dir']                    = 'C:\CAConfig'
default['certificate_services']['enterprise_subordinate_ca']['cdp_url']                         = nil
default['certificate_services']['enterprise_subordinate_ca']['clock_skew_minutes']              = 10
default['certificate_services']['enterprise_subordinate_ca']['common_name']                     = nil
default['certificate_services']['enterprise_subordinate_ca']['crl_delta_period']                = 'days'
default['certificate_services']['enterprise_subordinate_ca']['crl_delta_period_units']          = 1
default['certificate_services']['enterprise_subordinate_ca']['crl_overlap_period']              = 'hours'
default['certificate_services']['enterprise_subordinate_ca']['crl_overlap_units']               = 12
default['certificate_services']['enterprise_subordinate_ca']['crl_period']                      = 'weeks'
default['certificate_services']['enterprise_subordinate_ca']['crl_period_units']                = 2
default['certificate_services']['enterprise_subordinate_ca']['crypto_provider']                 = 'RSA#Microsoft Software Key Storage Provider'
default['certificate_services']['enterprise_subordinate_ca']['database_directory']              = 'C:\Windows\system32\CertLog'
default['certificate_services']['enterprise_subordinate_ca']['domain_pass']                     = nil
default['certificate_services']['enterprise_subordinate_ca']['domain_user']                     = nil
default['certificate_services']['enterprise_subordinate_ca']['enable_auditing_eventlogs']       = true
default['certificate_services']['enterprise_subordinate_ca']['enable_key_counting']             = false
default['certificate_services']['enterprise_subordinate_ca']['enhanced_key_usage']              = nil
default['certificate_services']['enterprise_subordinate_ca']['failover_clustering']             = false
default['certificate_services']['enterprise_subordinate_ca']['force_utf8']                      = false
default['certificate_services']['enterprise_subordinate_ca']['hash_algorithm']                  = 'SHA256'
default['certificate_services']['enterprise_subordinate_ca']['install_cert_file']               = "#{node['fqdn']}_#{node['domain'].split('.')[0]}-#{node['hostname']}-CA.crt" if node['domain']
default['certificate_services']['enterprise_subordinate_ca']['key_length']                      = 4096
default['certificate_services']['enterprise_subordinate_ca']['load_default_templates']          = false
default['certificate_services']['enterprise_subordinate_ca']['manual_install']                  = false
default['certificate_services']['enterprise_subordinate_ca']['ocsp_url']                        = nil
default['certificate_services']['enterprise_subordinate_ca']['overwrite_existing_ca_in_ds']     = false
default['certificate_services']['enterprise_subordinate_ca']['overwrite_existing_database']     = false
default['certificate_services']['enterprise_subordinate_ca']['overwrite_existing_key']          = false
default['certificate_services']['enterprise_subordinate_ca']['policy']                          = nil
default['certificate_services']['enterprise_subordinate_ca']['renewal_key_length']              = 4096
default['certificate_services']['enterprise_subordinate_ca']['renewal_validity_period']         = 'years'
default['certificate_services']['enterprise_subordinate_ca']['renewal_validity_period_units']   = 5
default['certificate_services']['enterprise_subordinate_ca']['root_crl_file']                   = nil
default['certificate_services']['enterprise_subordinate_ca']['root_crt_file']                   = nil
default['certificate_services']['enterprise_subordinate_ca']['validity_period']                 = 'years'
default['certificate_services']['enterprise_subordinate_ca']['validity_period_units']           = 2

# Default values for a CRL Distribution Point Endpoint

default['certificate_services']['crl_distribution_point']['cdp']['physical_dir_path']           = 'C:\inetpub\cdp'
default['certificate_services']['crl_distribution_point']['cdp']['virtual_dir_path']            = '/cdp'

default['certificate_services']['crl_distribution_point']['cps']['physical_dir_path']           = 'C:\inetpub\cps'
default['certificate_services']['crl_distribution_point']['cps']['virtual_dir_path']            = '/cps'

# Default values for Certificate Enrollment Policy Web Services

# Default values for Certificate Enrollment Web Services



