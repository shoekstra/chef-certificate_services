#
# Cookbook Name:: certificate_services_test
# Recipe:: default
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

powershell_script 'Disable Administrator change password at next logon' do
  code 'net user Administrator /logonpasswordchg:no'
end

powershell_script 'Set-NetFirewallProfile -Profile * -Enabled False'

user 'Administrator' do
  password 'Passw0rd!'
  provider Chef::Provider::User::Windows
end

powershell_script 'Grant SeAssignPrimaryTokenPrivilege access right' do
  code <<-EOS
    secedit /export /cfg c:\\secpol.cfg
    (gc c:\\secpol.cfg).replace('SeAssignPrimaryTokenPrivilege = ', 'SeAssignPrimaryTokenPrivilege = vagrant,') | Out-File c:\\secpol.cfg
    secedit /configure /db $env:windir\\security\\local.sdb /cfg c:\\secpol.cfg /areas User_Rights
    rm -force c:\\secpol.cfg -confirm:$false
  EOS
end
