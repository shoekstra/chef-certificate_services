#
# Cookbook Name:: certificate_services
# Recipe:: _iis
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

#
# Install and configure IIS
#
windows_feature %w(Web-Basic-Auth Web-Mgmt-Console Web-Mgmt-Service Web-Mgmt-Tools Web-WebServer) do
  action :install
  install_method :windows_feature_powershell
end

%w(W3SVC WMSvc).each do |service_name|
  windows_service service_name do
    timeout 180
    action [:enable, :start]
  end
end

registry_key 'HKLM\\SOFTWARE\\Microsoft\\WebManagement\\Server' do
  values [{ name: 'EnableRemoteManagement', type: :dword, data: 1 }]
  notifies :restart, 'windows_service[WMSvc]'
end

#
# Configure anonymous authentication to use the DefaultAppPool
#
powershell_script 'Set anonymous authentication (WebConfiguration)' do
  code 'Set-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost -Metadata overrideMode -Value Allow'
  not_if '(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"'
  notifies :restart, 'windows_service[W3SVC]'
end

#
# Set authPersistNonNTLM to True (https://support.microsoft.com/en-us/kb/954873)
#
iis_config '/section:windowsAuthentication /authPersistNonNTLM:true' do
  action :set
end
