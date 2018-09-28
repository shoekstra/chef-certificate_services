#
# Cookbook Name:: certificate_services
# Recipe:: crl_distribution_point
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

include_recipe "#{cookbook_name}::_iis" unless node.recipe?("#{cookbook_name}::_iis")

#
# Configure CDP virtual directory
#
cdp = node['certificate_services']['crl_distribution_point']['cdp']

enterprise_subordinates = []

unless Chef::Config[:solo]
  search(
    :node,
    "(chef_environment:#{node.chef_environment} AND recipes:certificate_services\\:\\:enterprise_subordinate_ca)",
    filter_result: { 'hostname' => ['hostname'] }
  ).each do |node|
    enterprise_subordinates << node['hostname'].upcase
  end
end

directory cdp['physical_dir_path'] do
  rights :read_execute, 'IIS APPPOOL\\DefaultAppPool'
  rights :modify, "#{node['domain']}\\Cert Publishers"
  enterprise_subordinates.each do |enterprise_subordinate|
    rights :modify, "#{node['domain']}\\#{enterprise_subordinate}$"
  end
  ignore_failure true # This resource would fail if nodes built in parallel and the "Cert Publishers" does not yet exist
end

smb_full_access = []
smb_full_access << 'SYSTEM'
smb_full_access << "'#{node['domain']}\\Domain Admins'"

powershell_script 'Create AIA/CDP SMB share' do
  code "New-SmbShare -Name CDP -Path #{cdp['physical_dir_path']} -FullAccess SYSTEM,'#{node['domain']}\\Domain Admins' -ChangeAccess 'Authenticated Users'"
  not_if 'Get-SmbShare -Name CDP'
end

iis_vdir cdp['virtual_dir_path'] do
  application_name 'Default Web Site'
  path cdp['virtual_dir_path']
  physical_path cdp['physical_dir_path']
end

powershell_script "Allow allowDoubleEscaping \"IIS:\\Sites\\Default Web Site\\#{cdp['virtual_dir_path'].delete('/')}\"" do
  code "Set-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering -PSPath \"IIS:\\Sites\\Default Web Site\\#{cdp['virtual_dir_path'].delete('/')}\" -Name allowDoubleEscaping -Value True"
  not_if "(Get-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering -PSPath \"IIS:\\Sites\\Default Web Site\\#{cdp['virtual_dir_path'].delete('/')}\" -Name allowDoubleEscaping).Value -eq 'True'"
  notifies :restart, 'windows_service[W3SVC]'
end

powershell_script "Set anonymous authentication \"IIS:\\Sites\\Default Web Site\\#{cdp['virtual_dir_path'].delete('/')}\"" do
  code "Set-WebConfigurationProperty -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath \"IIS:\\Sites\\Default Web Site\\#{cdp['virtual_dir_path'].delete('/')}\" -Name username -Value ''"
  not_if "(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath \"IIS:\\Sites\\Default Web Site\\#{cdp['virtual_dir_path'].delete('/')}\" -Name username).Value -eq ''"
  notifies :restart, 'windows_service[W3SVC]'
end

#
# Configure CPS virtual directory
#
cps = node['certificate_services']['crl_distribution_point']['cps']

directory cps['physical_dir_path'] do
  rights :read_execute, 'IIS APPPOOL\\DefaultAppPool'
end

iis_vdir cps['virtual_dir_path'] do
  application_name 'Default Web Site'
  path cps['virtual_dir_path']
  physical_path cps['physical_dir_path']
end

powershell_script "Allow allowDoubleEscaping \"IIS:\\Sites\\Default Web Site\\#{cps['virtual_dir_path'].delete('/')}\"" do
  code "Set-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering -PSPath \"IIS:\\Sites\\Default Web Site\\#{cps['virtual_dir_path'].delete('/')}\" -Name allowDoubleEscaping -Value True"
  not_if "(Get-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering -PSPath \"IIS:\\Sites\\Default Web Site\\#{cps['virtual_dir_path'].delete('/')}\" -Name allowDoubleEscaping).Value -eq 'True'"
  notifies :restart, 'windows_service[W3SVC]'
end

powershell_script "Set anonymous authentication \"IIS:\\Sites\\Default Web Site\\#{cps['virtual_dir_path'].delete('/')}\"" do
  code "Set-WebConfigurationProperty -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath \"IIS:\\Sites\\Default Web Site\\#{cps['virtual_dir_path'].delete('/')}\" -Name username -Value ''"
  not_if "(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath \"IIS:\\Sites\\Default Web Site\\#{cps['virtual_dir_path'].delete('/')}\" -Name username).Value -eq ''"
  notifies :restart, 'windows_service[W3SVC]'
end
