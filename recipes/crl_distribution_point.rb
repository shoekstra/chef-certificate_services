#
# Cookbook Name:: certificate_services
# Recipe:: crl_distribution_point
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

#
# Install and configure IIS
#
%w(Web-Mgmt-Console Web-Mgmt-Service Web-Mgmt-Tools Web-WebServer).each do |feature_name|
  windows_feature feature_name do
    action :install
    provider :windows_feature_powershell
  end
end

%w(W3SVC WMSvc).each do |service_name|
  windows_service service_name do
    action [:enable, :start]
  end
end

registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WebManagement\\Server' do
  values [{ name: 'EnableRemoteManagement', type: :dword, data: '1' }]
  notifies :restart, 'windows_service[WMSvc]'
end

#
# Configure anonymous authentication to use the DefaultAppPool
#
powershell_script 'Set anonymous authentication (WebConfiguration)' do
  code 'Set-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost -Metadata overrideMode -Value Allow'
  notifies :restart, 'windows_service[W3SVC]'
end

#
# Configure CDP virtual directory
#
cdp = node['certificate_services']['crl_distribution_point']['cdp']

directory cdp['physical_dir_path'] do
  rights :read_execute, 'IIS APPPOOL\\DefaultAppPool'
  rights :modify, "#{node['domain']}\\Cert Publishers"
  ignore_failure true # This resource would fail if nodes built in parallel and the "Cert Publishers" does not yet exist
end

powershell_script 'Create AIA/CDP SMB share' do
  code "New-SmbShare -Name CDP -Path #{cdp['physical_dir_path']} -FullAccess SYSTEM,'#{node['domain']}\\Domain Admins' -ChangeAccess '#{node['domain']}\\Cert Publishers'"
  not_if 'Get-SmbShare -Name CDP'
end

iis_vdir cdp['virtual_dir_path'] do
  application_name 'Default Web Site'
  path cdp['virtual_dir_path']
  physical_path cdp['physical_dir_path']
end

powershell_script "Allow allowDoubleEscaping \"IIS:\\Sites\\Default Web Site\\#{cdp['virtual_dir_path'].delete('/')}\"" do
  code "Set-WebConfigurationProperty -Filter system.webServer/security/requestFiltering -PSPath \"IIS:\\Sites\\Default Web Site\\#{cdp['virtual_dir_path'].delete('/')}\" -Name allowDoubleEscaping -Value True"
  notifies :restart, 'windows_service[W3SVC]'
end

powershell_script "Set anonymous authentication \"IIS:\\Sites\\Default Web Site\\#{cdp['virtual_dir_path'].delete('/')}\"" do
  code "Set-WebConfigurationProperty -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath \"IIS:\\Sites\\Default Web Site\\#{cdp['virtual_dir_path'].delete('/')}\" -Name username -Value \"\""
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
  code "Set-WebConfigurationProperty -Filter system.webServer/security/requestFiltering -PSPath \"IIS:\\Sites\\Default Web Site\\#{cps['virtual_dir_path'].delete('/')}\" -Name allowDoubleEscaping -Value True"
  notifies :restart, 'windows_service[W3SVC]'
end

powershell_script "Set anonymous authentication \"IIS:\\Sites\\Default Web Site\\#{cps['virtual_dir_path'].delete('/')}\"" do
  code "Set-WebConfigurationProperty -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath \"IIS:\\Sites\\Default Web Site\\#{cps['virtual_dir_path'].delete('/')}\" -Name username -Value \"\""
  notifies :restart, 'windows_service[W3SVC]'
end

[
  node['certificate_services']['standalone_root_ca']['policy'],
  node['certificate_services']['enterprise_subordinate_ca']['policy']
].each do |policy|
  next if policy.nil?
  policy.each do |p|
    next unless p.last.has_key?('url')

    file ::File.join(cps['physical_dir_path'], File.basename(p.last['url'].downcase)) do
      content p.last['notice']
    end
  end
end
