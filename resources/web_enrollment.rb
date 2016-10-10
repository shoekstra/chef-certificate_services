#
# Cookbook Name:: certificate_services
# Resource:: web_enrollment
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

include CertificateServices::Helper
include Windows::Helper

actions :install, :uninstall
default_action :install

# CA type to install/configure

property :name, kind_of: String, required: true, name_property: true

property :ca_config,   kind_of: String, required: true
property :domain_pass, kind_of: String, required: false
property :domain_user, kind_of: String, required: false

action_class do
  def certsrv_vdir_installed?
    result = powershell_out('Import-Module WebAdministration; Test-Path \"IIS:\\Sites\\Default Web Site\\CertSrv\"').stdout.chomp
    result == 'True'
  end
end

action :install do
  windows_feature 'ADCS-Web-Enrollment' do
    action :install
    provider :windows_feature_powershell
  end

  powershell_out_options = { user: new_resource.domain_user, password: new_resource.domain_pass, domain: node['domain'] }

  ruby_block 'Configure ADCS Web Enrollment' do
    block { powershell_out!("Install-AdcsWebEnrollment -CAConfig '#{new_resource.ca_config}' -Force", powershell_out_options) }
    not_if { certsrv_vdir_installed? }
    action :run
  end

  ruby_block 'Allow CertSrv overrides' do
    block do
      apphost_config = Chef::Util::FileEdit.new("#{ENV['SystemRoot']}\\System32\\inetsrv\\config\\applicationHost.config")
      apphost_config.search_file_replace_line(
        /<location path=\"Default Web Site\/CertSrv\"/,
        '    <location path="Default Web Site/CertSrv" overrideMode="Allow">'
      )
      apphost_config.write_file
    end
  end

  #
  # These should be made parameters at same stage but are required if proxying non Windows clients, so for now
  # they are not optional and could even be ported back to the IIS cookbook
  #
  powershell_script 'Set basic authentication enabled = true for "IIS:\Sites\Default Web Site\CertSrv"' do
    code 'Set-WebConfigurationProperty -Filter /system.WebServer/security/authentication/basicAuthentication -PSPath "IIS:\Sites\Default Web Site\CertSrv" -Name Enabled -Value "True"'
    not_if '(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/basicAuthentication -PSPath "IIS:\Sites\Default Web Site\CertSrv" -Name Enabled).Value -eq "True"'
    notifies :restart, 'windows_service[W3SVC]'
  end

  powershell_script 'Set basic authentication logonMethod = ClearText for "IIS:\Sites\Default Web Site\CertSrv"' do
    code 'Set-WebConfigurationProperty -Filter /system.WebServer/security/authentication/basicAuthentication -PSPath "IIS:\Sites\Default Web Site\CertSrv" -Name logonMethod -Value "ClearText"'
    not_if '(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/basicAuthentication -PSPath "IIS:\Sites\Default Web Site\CertSrv" -Name logonMethod) -eq "ClearText"'
    notifies :restart, 'windows_service[W3SVC]'
  end

  powershell_script 'Set windows authentication enabled = false for "IIS:\Sites\Default Web Site\CertSrv"' do
    code 'Set-WebConfigurationProperty -Filter /system.WebServer/security/authentication/windowsAuthentication -PSPath "IIS:\Sites\Default Web Site\CertSrv" -Name Enabled -Value "False"'
    not_if '(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/windowsAuthentication -PSPath "IIS:\Sites\Default Web Site\CertSrv" -Name Enabled).Value -eq $False'
    notifies :restart, 'windows_service[W3SVC]'
  end
end

action :uninstall do
  ruby_block 'Configure ADCS Web Enrollment' do
    block { powershell_out!('Uninstall-AdcsWebEnrollment -Force', powershell_out_options) }
    only_if { certsrv_vdir_installed? }
    action :run
  end

  windows_feature 'ADCS-Web-Enrollment' do
    action :uninstall
    provider :windows_feature_powershell
  end
end
