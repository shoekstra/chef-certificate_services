#
# Cookbook Name:: certificate_services
# Resource:: enrollment_policy_web_service
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
property :domain_pass, kind_of: String, required: true
property :domain_user, kind_of: String, required: true
property :friendly_name, kind_of: String, required: false
property :key_based_renewal, kind_of: [TrueClass, FalseClass], required: false, default: false

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
  friendly_name = "Enrollment Policy Web Service (#{auth_type})"
  friendly_name = new_resource.friendly_name if new_resource.friendly_name
  iis_vdir = case auth_type
             when 'Kerberos'
               'ADPolicyProvider_CEP_Kerberos'
             when 'Username'
               'ADPolicyProvider_CEP_UsernamePassword'
             end

  windows_feature 'Adcs-Enroll-Web-Pol' do
    action :install
    install_method :windows_feature_powershell
  end

  install_cmd = [
    'Install-AdcsEnrollmentPolicyWebService',
    "-AuthenticationType #{auth_type}",
    '-Force'
  ]

  install_cmd << '-KeyBasedRenewal' if new_resource.key_based_renewal

  ruby_block 'Configure ADCS Enrollment Web Service' do
    block { powershell_out!(install_cmd.join(' '), powershell_out_options) }
    not_if { iis_vdir_installed?(iis_vdir) }
    action :run
  end

  powershell_script "Set Application FriendlyName to \"#{friendly_name}\" for \"IIS:\\Sites\\Default Web Site\\#{iis_vdir}\"" do
    code "Set-WebConfigurationProperty -Filter \"/appSettings/add[@key='FriendlyName']\" -Pspath \"IIS:\\Sites\\Default Web Site\\#{iis_vdir}\" -Name \"Value\" -Value \"#{friendly_name}\""
    only_if { iis_vdir_installed?(iis_vdir) }
    not_if "((Get-WebConfigurationProperty -Filter /appSettings -Pspath \"IIS:\\Sites\\Default Web Site\\#{iis_vdir}\" -Name .).collection | ?{$_.Key -eq \"FriendlyName\"}).Value -eq \"#{friendly_name}\""
    notifies :restart, 'windows_service[W3SVC]'
  end
end
