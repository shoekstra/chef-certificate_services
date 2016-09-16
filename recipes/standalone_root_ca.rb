#
# Cookbook Name:: certificate_services
# Recipe:: standalone_root_ca
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

::Chef::Resource::Batch.send(:include, CertificateServices::Helper)
::Chef::Resource::PowershellScript.send(:include, CertificateServices::Helper)

caconfig = node['certificate_services']['standalone_root_ca']

#
# Install and configure the Certificate Authority
#
certificate_services_install 'StandaloneRootCA' do
  # allow_administrator_interaction caconfig['allow_administrator_interaction'] if caconfig['allow_administrator_interaction']
  aia_url caconfig['aia_url'] if caconfig['aia_url']
  alternate_signature_algorithm caconfig['alternate_signature_algorithm'] if caconfig['alternate_signature_algorithm']
  caconfig_dir caconfig['caconfig_dir'] if caconfig['caconfig_dir']
  cdp_url caconfig['cdp_url'] if caconfig['cdp_url']
  clock_skew_minutes caconfig['clock_skew_minutes'] if caconfig['clock_skew_minutes']
  common_name caconfig['common_name'] if caconfig['common_name']
  crl_delta_period caconfig['crl_delta_period'] if caconfig['crl_delta_period']
  crl_delta_period_units caconfig['crl_delta_period_units'] if caconfig['crl_delta_period_units']
  crl_overlap_period caconfig['crl_overlap_period'] if caconfig['crl_overlap_period']
  crl_overlap_units caconfig['crl_overlap_units'] if caconfig['crl_overlap_units']
  crl_period caconfig['crl_period'] if caconfig['crl_period']
  crl_period_units caconfig['crl_period_units'] if caconfig['crl_period_units']
  crypto_provider caconfig['crypto_provider'] if caconfig['crypto_provider']
  database_directory caconfig['database_directory'] if caconfig['database_directory']
  enable_auditing_eventlogs caconfig['enable_auditing_eventlogs'] if caconfig['enable_auditing_eventlogs']
  enable_key_counting caconfig['enable_key_counting'] if caconfig['enable_key_counting']
  enhanced_key_usage caconfig['enhanced_key_usage'] if caconfig['enhanced_key_usage']
  force_utf8 caconfig['force_utf8'] if caconfig['force_utf8']
  hash_algorithm caconfig['hash_algorithm'] if caconfig['hash_algorithm']
  key_length caconfig['key_length'] if caconfig['key_length']
  load_default_templates caconfig['load_default_templates'] if caconfig['load_default_templates']
  overwrite_existing_ca_in_ds caconfig['overwrite_existing_ca_in_ds'] if caconfig['overwrite_existing_ca_in_ds']
  overwrite_existing_database caconfig['overwrite_existing_database'] if caconfig['overwrite_existing_database']
  overwrite_existing_key caconfig['overwrite_existing_key'] if caconfig['overwrite_existing_key']
  policy caconfig['policy'] if caconfig['policy']
  renewal_key_length caconfig['renewal_key_length'] if caconfig['renewal_key_length']
  renewal_validity_period caconfig['renewal_validity_period'] if caconfig['renewal_validity_period']
  renewal_validity_period_units caconfig['renewal_validity_period_units'] if caconfig['renewal_validity_period_units']
  validity_period caconfig['validity_period'] if caconfig['validity_period']
  validity_period_units caconfig['validity_period_units'] if caconfig['validity_period_units']
  windows_domain caconfig['windows_domain'] if caconfig['windows_domain']
end

#
# Copy the root CA certificate and CRL to the PKI directory for easy access
#
batch 'Copy certificate and CRLs to the CAConfig directory' do
  architecture :x86_64
  code "robocopy \"C:\\Windows\\System32\\CertSrv\\CertEnroll\" \"#{node['certificate_services']['standalone_root_ca']['caconfig_dir']}\" /MIR /NDL /NJS /NJH"
  returns [0, 1]
  action :run
  only_if { ca_configured? }
end

#
# At this point the initial deployment is done, no future steps are needed to configure the offline root
# CA; once the subordinate certificates have been signed the offline root can be powered off.
#
certificate_services_sign_request 'C:/*.req'
