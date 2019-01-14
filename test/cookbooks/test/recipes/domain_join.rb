#
# Cookbook Name:: test
# Recipe:: domain_join
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

powershell_script 'Set DNS resolver' do
  code 'Get-DnsClient | ?{$_.InterfaceAlias -eq "Ethernet 2"} | Set-DnsClientServerAddress -ServerAddresses ("192.168.33.10")'
  not_if '(Get-DnsClientServerAddress | ?{$_.InterfaceAlias -eq "Ethernet 2" -and $_.Address -ne ""}).ServerAddresses -eq "192.168.10.10")'
end

windows_ad_computer node['hostname'] do
  action :join
  domain_pass 'Passw0rd!'
  domain_user 'Administrator'
  domain_name 'contoso.com'
  restart false
end

ohai 'reload' do
  action :reload
end
