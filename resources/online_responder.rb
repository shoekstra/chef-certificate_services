#
# Cookbook Name:: certificate_services
# Resource:: online_responder
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

include CertificateServices::Helper
include Windows::Helper

actions :install, :uninstall
default_action :install

property :ca_name,          kind_of: String, required: true, name_property: true

property :array_controller, kind_of: String, required: true
property :array_members,    kind_of: String, required: false
property :cdp_url_base,     kind_of: String, required: true
property :domain_pass,      kind_of: String, required: true
property :domain_user,      kind_of: String, required: true

action_class do
  def ocsp_vdir_installed?
    result = powershell_out('Import-Module WebAdministration; Test-Path "IIS:\\Sites\\Default Web Site\\ocsp"').stdout.chomp
    result == 'True'
  end
end

action :install do
  windows_feature 'ADCS-Online-Cert' do
    action :install
    install_method :windows_feature_powershell
  end

  windows_feature 'RSAT-Online-Responder' do
    action :install
    install_method :windows_feature_powershell
  end

  powershell_out_options = { user: new_resource.domain_user, password: new_resource.domain_pass, domain: node['domain'] }

  ruby_block 'Configure ADCS Online Responder' do
    block { powershell_out!('Install-AdcsOnlineResponder -Force', powershell_out_options) }
    not_if { ocsp_vdir_installed? }
    action :run
  end

  if new_resource.array_members
    array_members = to_array(new_resource.array_members)
  else
    array_members = []

    unless Chef::Config[:solo]
      search(
        :node,
        "(chef_environment:#{node.chef_environment} AND recipes:certificate_services\\:\\:online_responder)",
        filter_result: { 'fqdn' => ['fqdn'] }
      ).each do |node|
        array_members << node['fqdn'] unless node['fqdn'].match(/"#{new_resource.array_controller}"/i)
      end
    end
  end

  template "#{Chef::Config['file_cache_path']}/OCSPFirstNode.ps1" do
    source 'OCSPFirstNode.ps1.erb'
    variables(
      array_controller: new_resource.array_controller,
      ca_name: new_resource.ca_name,
      cdp_url_base: new_resource.cdp_url_base,
      domain: node['domain'],
      fqdn: node['fqdn']
    )
  end

  template "#{Chef::Config['file_cache_path']}/OCSPAddNodes.ps1" do
    source 'OCSPAddNodes.ps1.erb'
    variables(
      array_controller: new_resource.array_controller,
      array_members: array_members
    )
  end
end

action :uninstall do
  ruby_block 'Uninstall ADCS Online Responder' do
    block { powershell_out!('Install-AdcsOnlineResponder -Force', powershell_out_options) }
    only_if { ocsp_vdir_installed? }
    action :run
  end

  windows_feature 'ADCS-Online-Cert' do
    action :uninstall
    install_method :windows_feature_powershell
  end

  windows_feature 'RSAT-Online-Responder' do
    action :uninstall
    install_method :windows_feature_powershell
  end
end
