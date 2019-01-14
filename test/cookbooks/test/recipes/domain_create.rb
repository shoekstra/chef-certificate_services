#
# Cookbook Name:: test
# Recipe:: domain_create
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

windows_feature 'AD-Domain-Services' do
  action :install
  install_method :windows_feature_powershell
end

windows_ad_domain 'contoso.com' do
  action :create
  type 'forest'
  safe_mode_pass 'Passw0rd!'
  domain_pass 'Passw0rd!'
  domain_user 'Administrator'
end

powershell_script 'Create A record for pki.contoso.com' do
  code 'Get-DnsServerZone contoso.com | Add-DnsServerResourceRecordA -Name "pki" -IPv4Address 192.168.33.13 '
  not_if 'if (Get-DnsServerResourceRecord -ZoneName contoso.com -Name pki -ErrorAction SilentlyContinue) { $true } else { $false }'
end
