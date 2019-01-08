#
# Cookbook Name:: certificate_services
# Resource:: network_device_enrollment_service
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

include CertificateServices::Helper
include Windows::Helper

actions :install
default_action :install

property :app_pool_identity,        kind_of: [TrueClass, FalseClass], required: false, default: true
property :ca_config,                kind_of: String,                  required: true, name_property: true
property :domain_pass,              kind_of: String,                  required: true
property :domain_user,              kind_of: String,                  required: true
property :encryption_key_length,    kind_of: [Integer, String], required: false, default: 2048
property :encryption_provider_name, kind_of: String,                  required: false, default: 'Microsoft Strong Cryptographic Provider'
property :encryption_template,      kind_of: String,                  required: true, default: 'IPSECIntermediateOffline'
property :general_purpose_template, kind_of: String,                  required: true, default: 'IPSECIntermediateOffline'
property :ra_city,                  kind_of: String,                  required: false
property :ra_company,               kind_of: String,                  required: false
property :ra_country,               kind_of: String,                  required: false
property :ra_department,            kind_of: String,                  required: false
property :ra_email,                 kind_of: String,                  required: false
property :ra_name,                  kind_of: String,                  required: true, default: lazy { "#{node['hostname'].upcase}-MSCEP-RA" }
property :ra_state,                 kind_of: String,                  required: false
property :service_password,         kind_of: String,                  required: false
property :service_user,             kind_of: String,                  required: false
property :signature_template,       kind_of: String,                  required: true, default: 'IPSECIntermediateOffline'
property :signing_key_length,       kind_of: [Integer, String], required: false, default: 2048
property :signing_provider_name,    kind_of: String,                  required: false, default: 'Microsoft Strong Cryptographic Provider'
property :use_single_password,      kind_of: [TrueClass, FalseClass], required: false, default: false

action_class do
  def iis_vdir_installed?(iis_vdir)
    result = powershell_out("Import-Module WebAdministration; Test-Path 'IIS:\\Sites\\Default Web Site\\#{iis_vdir}'").stdout.chomp
    result == 'True'
  end
end

action :install do
  include_recipe "#{cookbook_name}::_iis" unless node.recipe?("#{cookbook_name}::_iis")

  powershell_out_options = { user: new_resource.domain_user, password: new_resource.domain_pass, domain: node['domain'] }

  iis_vdir = 'CertSrv\\mscep'

  windows_feature 'Adcs-Device-Enrollment' do
    action :install
    install_method :windows_feature_powershell
  end

  install_cmd = [
    'Install-AdcsNetworkDeviceEnrollmentService',
    "-CAConfig '#{new_resource.ca_config}'",
    "-RAName '#{new_resource.ra_name}'",
    "-EncryptionKeyLength #{new_resource.encryption_key_length}",
    "-EncryptionProviderName '#{new_resource.encryption_provider_name}'",
    "-SigningKeyLength #{new_resource.signing_key_length}",
    "-SigningProviderName '#{new_resource.signing_provider_name}'",
    '-Force',
  ]

  install_cmd << '-ApplicationPoolIdentity' if new_resource.app_pool_identity && !new_resource.service_user && !new_resource.service_password
  install_cmd << "-RACity '#{new_resource.ra_city}'" if new_resource.ra_city
  install_cmd << "-RACompany '#{new_resource.ra_company}'" if new_resource.ra_company
  install_cmd << "-RACountry '#{new_resource.ra_country}'" if new_resource.ra_country
  install_cmd << "-RADepartment '#{new_resource.ra_department}'" if new_resource.ra_department
  install_cmd << "-RAEmail '#{new_resource.ra_email}'" if new_resource.ra_email
  install_cmd << "-RAState '#{new_resource.ra_state}'" if new_resource.ra_state
  if new_resource.service_user && new_resource.service_password
    install_cmd << "-ServiceAccountName #{node['domain']}\\#{new_resource.service_user}"
    install_cmd << "-ServiceAccountPassword $(ConvertTo-SecureString '#{new_resource.service_password}' -AsPlainText -Force)"
  end

  ruby_block 'Configure ADCS Network Device Enrollment Service' do
    block { powershell_out!(install_cmd.join(' '), powershell_out_options) }
    not_if { iis_vdir_installed?(iis_vdir) }
    action :run
  end

  registry_key 'HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MSCEP' do
    values [
      { name: 'EncryptionTemplate', type: :string, data: new_resource.encryption_template },
      { name: 'GeneralPurposeTemplate', type: :string, data: new_resource.general_purpose_template },
      { name: 'SignatureTemplate', type: :string, data: new_resource.signature_template },
    ]
    action :create
    notifies :restart, 'windows_service[W3SVC]', :immediately
  end

  registry_key 'HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MSCEP\\UseSinglePassword' do
    values [
      { name: 'UseSinglePassword', type: :dword, data: new_resource.use_single_password ? '1' : '0' },
    ]
    action :create
    notifies :restart, 'windows_service[W3SVC]', :immediately
  end

  registry_key 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters' do
    values [
      { name: 'MaxFieldLength',  type: :dword, data: 65534 },
      { name: 'MaxRequestBytes', type: :dword, data: 65534 },
    ]
    action :create
    notifies :restart, 'windows_service[W3SVC]', :immediately
  end
end
