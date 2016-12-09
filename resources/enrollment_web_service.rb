#
# Cookbook Name:: certificate_services
# Resource:: enrollment_web_service
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

include CertificateServices::Helper
include Windows::Helper

actions :install
default_action :install

property :auth_type, kind_of: String, required: true, regex: /^(kerberos|username)$/i, name_property: true
property :allow_key_based_renewal, kind_of: [TrueClass, FalseClass], required: false, default: false
property :app_pool_identity, kind_of: [TrueClass, FalseClass], required: false, default: false
property :ca_config, kind_of: String, required: false
property :domain_pass, kind_of: String, required: true
property :domain_user, kind_of: String, required: true
property :renewal_only, kind_of: [TrueClass, FalseClass], required: false, default: false
property :service_password, kind_of: String, required: false
property :service_user, kind_of: String, required: false

action_class do
  def iis_vdir_installed?(iis_vdir)
    result = powershell_out("Import-Module WebAdministration; Test-Path 'IIS:\\Sites\\Default Web Site\\#{iis_vdir}'").stdout.chomp
    result == 'True'
  end
end

action :install do
  include_recipe "#{cookbook_name}::_iis" unless node.recipe?("#{cookbook_name}::_iis")

  powershell_out_options = { user: new_resource.domain_user, password: new_resource.domain_pass, domain: node['domain'] }

  auth_type = new_resource.auth_type.downcase.capitalize

  ca_common_name = new_resource.ca_config.split('\\')[1]
  iis_vdir = case auth_type
             when 'Kerberos'
               "#{ca_common_name}_CES_Kerberos"
             when 'Username'
               "#{ca_common_name}_CES_UsernamePassword"
             end

  windows_feature 'ADCS-Enroll-Web-Svc' do
    action :install
    install_method :windows_feature_powershell
  end

  install_cmd = [
    'Install-AdcsEnrollmentWebService',
    "-AuthenticationType #{auth_type}",
    '-Force'
  ]

  install_cmd << "-CAConfig '#{new_resource.ca_config}'" if new_resource.ca_config
  install_cmd << '-AllowKeyBasedRenewal' if new_resource.allow_key_based_renewal
  install_cmd << '-RenewalOnly' if new_resource.renewal_only
  install_cmd << '-ApplicationPoolIdentity' if new_resource.app_pool_identity && !new_resource.service_user && !new_resource.service_password
  if new_resource.service_user && new_resource.service_password
    install_cmd << "-ServiceAccountName #{node['domain']}\\#{new_resource.service_user}"
    install_cmd << "-ServiceAccountPassword $(ConvertTo-SecureString '#{new_resource.service_password}' -AsPlainText -Force)"
  end

  ruby_block 'Configure ADCS Enrollment Web Service' do
    block { powershell_out!(install_cmd.join(' '), powershell_out_options) }
    not_if { iis_vdir_installed?(iis_vdir) }
    action :run
  end
end
