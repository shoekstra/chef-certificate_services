#
# Cookbook Name:: certificate_services
# Resource:: web_enrollment
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

default_action :install

property :ca_config, String, name_property: true

property :domain_pass, String, required: true
property :domain_user, String, required: true

action_class do
  def certsrv_vdir_installed?
    result = powershell_out('Import-Module WebAdministration; Test-Path "IIS:\\Sites\\Default Web Site\\CertSrv"').stdout.chomp
    result == 'True'
  end
end

action :install do
  include_recipe "#{cookbook_name}::_iis" unless node.recipe?("#{cookbook_name}::_iis")

  windows_feature 'ADCS-Web-Enrollment' do
    action :install
    install_method :windows_feature_powershell
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
        %r{<location path="Default Web Site/CertSrv"},
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
