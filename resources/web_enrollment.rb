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
