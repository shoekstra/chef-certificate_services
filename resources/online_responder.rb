#
# Cookbook Name:: certificate_services
# Resource:: online_responder
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

property :ca_name, String, name_property: true

property :array_controller, String, required: true
property :array_members, String, required: false
property :cdp_url_base, String, required: true
property :domain_pass, String, required: true
property :domain_user, String, required: true

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
        array_members << node['fqdn'] unless node['fqdn'] =~ /"#{new_resource.array_controller}"/i
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

action :remove do
  ruby_block 'Uninstall ADCS Online Responder' do
    block { powershell_out!('Install-AdcsOnlineResponder -Force', powershell_out_options) }
    only_if { ocsp_vdir_installed? }
    action :run
  end

  windows_feature 'ADCS-Online-Cert' do
    action :remove
    install_method :windows_feature_powershell
  end

  windows_feature 'RSAT-Online-Responder' do
    action :remove
    install_method :windows_feature_powershell
  end
end
