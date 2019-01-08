#
# Cookbook Name:: certificate_services
# Recipe:: standalone_root_ca
#
# Copyright 2019, Stephen Hoekstra
# Copyright 2019, Schuberg Philis
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

::Chef::Resource::Batch.send(:include, CertificateServices::Helper)
::Chef::Resource::PowershellScript.send(:include, CertificateServices::Helper)

config = node['certificate_services']['standalone_root_ca']

#
# Install and configure the Certificate Authority
#
certificate_services_install 'StandaloneRootCA' do
  # allow_administrator_interaction config['allow_administrator_interaction'] if config['allow_administrator_interaction']
  aia_url config['aia_url'] if config['aia_url']
  alternate_signature_algorithm config['alternate_signature_algorithm'] if config['alternate_signature_algorithm']
  caconfig_dir config['caconfig_dir'] if config['caconfig_dir']
  cdp_url config['cdp_url'] if config['cdp_url']
  clock_skew_minutes config['clock_skew_minutes'] if config['clock_skew_minutes']
  common_name config['common_name'] if config['common_name']
  crl_delta_period config['crl_delta_period'] if config['crl_delta_period']
  crl_delta_period_units config['crl_delta_period_units'] if config['crl_delta_period_units']
  crl_overlap_period config['crl_overlap_period'] if config['crl_overlap_period']
  crl_overlap_units config['crl_overlap_units'] if config['crl_overlap_units']
  crl_period config['crl_period'] if config['crl_period']
  crl_period_units config['crl_period_units'] if config['crl_period_units']
  crypto_provider config['crypto_provider'] if config['crypto_provider']
  database_directory config['database_directory'] if config['database_directory']
  enable_auditing_eventlogs config['enable_auditing_eventlogs'] if config['enable_auditing_eventlogs']
  enable_key_counting config['enable_key_counting'] if config['enable_key_counting']
  enhanced_key_usage config['enhanced_key_usage'] if config['enhanced_key_usage']
  force_utf8 config['force_utf8'] if config['force_utf8']
  hash_algorithm config['hash_algorithm'] if config['hash_algorithm']
  key_length config['key_length'] if config['key_length']
  load_default_templates config['load_default_templates'] if config['load_default_templates']
  overwrite_existing_ca_in_ds config['overwrite_existing_ca_in_ds'] if config['overwrite_existing_ca_in_ds']
  overwrite_existing_database config['overwrite_existing_database'] if config['overwrite_existing_database']
  overwrite_existing_key config['overwrite_existing_key'] if config['overwrite_existing_key']
  policy config['policy'] if config['policy']
  renewal_key_length config['renewal_key_length'] if config['renewal_key_length']
  renewal_validity_period config['renewal_validity_period'] if config['renewal_validity_period']
  renewal_validity_period_units config['renewal_validity_period_units'] if config['renewal_validity_period_units']
  validity_period config['validity_period'] if config['validity_period']
  validity_period_units config['validity_period_units'] if config['validity_period_units']
  windows_domain config['windows_domain'] if config['windows_domain']
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
