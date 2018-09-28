#
# Cookbook Name:: certificate_services
# Spec:: crl_distribution_point
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

require 'spec_helper'

require_relative '_iis_spec.rb'

describe 'certificate_services::crl_distribution_point' do
  context 'when all attributes are default' do
    cached(:chef_run) do
      ChefSpec::ServerRunner.new do |node|
        node.automatic['domain'] = 'CONTOSO'
      end.converge(described_recipe)
    end

    before do
      stub_command('Get-SmbShare -Name CDP').and_return(false)
      stub_search(:node, "(chef_environment:_default AND recipes:certificate_services\\:\\:enterprise_subordinate_ca)").and_return([{ hostname: 'subca1' }, { hostname: 'subca2' }])
    end

    it 'should converge successfully' do
      expect { chef_run }.to_not raise_error
    end

    it 'should install and configure IIS' do
      %w(Web-Mgmt-Console Web-Mgmt-Service Web-Mgmt-Tools Web-WebServer).each do |feature_name|
        expect(chef_run).to install_windows_feature(feature_name)
      end

      expect(chef_run).to create_registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WebManagement\\Server').with_values(
        [name: 'EnableRemoteManagement', type: :dword, data: Chef::Digester.instance.generate_checksum(1)]
      )
      expect(chef_run.registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WebManagement\\Server')).to notify('windows_service[WMSvc]').to(:restart).delayed

      %w(W3SVC WMSvc).each do |service_name|
        expect(chef_run).to enable_windows_service(service_name)
        expect(chef_run).to start_windows_service(service_name)
      end

      expect(chef_run).to run_powershell_script('Set anonymous authentication (WebConfiguration)').with_code(
        'Set-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost -Metadata overrideMode -Value Allow'
      )
      expect(chef_run.powershell_script('Set anonymous authentication (WebConfiguration)')).to notify('windows_service[W3SVC]').to(:restart).delayed
    end

    it 'should create a /cdp virtual dir' do
      expect(chef_run).to create_directory('C:\inetpub\cdp').with_rights(
        [
          { permissions: :read_execute, principals: 'IIS APPPOOL\\DefaultAppPool' },
          { permissions: :modify,       principals: 'CONTOSO\\Cert Publishers' },
          { permissions: :modify,       principals: 'CONTOSO\\SUBCA1$' },
          { permissions: :modify,       principals: 'CONTOSO\\SUBCA2$' }
        ]
      )

      expect(chef_run).to run_powershell_script('Create AIA/CDP SMB share').with(
        code: 'New-SmbShare -Name CDP -Path C:\inetpub\cdp -FullAccess SYSTEM,\'CONTOSO\Domain Admins\' -ChangeAccess \'Authenticated Users\''
      )

      expect(chef_run).to add_iis_vdir('/cdp').with(
        application_name: 'Default Web Site',
        path: '/cdp',
        physical_path: 'C:\inetpub\cdp'
      )

      expect(chef_run).to run_powershell_script('Set anonymous authentication "IIS:\Sites\Default Web Site\cdp"').with_code(
        'Set-WebConfigurationProperty -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath "IIS:\\Sites\\Default Web Site\\cdp" -Name username -Value ""'
      )

      expect(chef_run).to run_powershell_script('Allow allowDoubleEscaping "IIS:\Sites\Default Web Site\cdp"').with_code(
        'Set-WebConfigurationProperty -Filter system.webServer/security/requestFiltering -PSPath "IIS:\\Sites\\Default Web Site\\cdp" -Name allowDoubleEscaping -Value True'
      )
    end

    it 'should create a /cps virtual dir' do
      expect(chef_run).to create_directory('C:\inetpub\cps').with_rights(
        [
          { permissions: :read_execute, principals: 'IIS APPPOOL\\DefaultAppPool' }
        ]
      )

      expect(chef_run).to add_iis_vdir('/cps').with(
        application_name: 'Default Web Site',
        path: '/cps',
        physical_path: 'C:\inetpub\cps'
      )

      expect(chef_run).to run_powershell_script('Set anonymous authentication "IIS:\Sites\Default Web Site\cps"').with_code(
        'Set-WebConfigurationProperty -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath "IIS:\\Sites\\Default Web Site\\cps" -Name username -Value ""'
      )

      expect(chef_run).to run_powershell_script('Allow allowDoubleEscaping "IIS:\Sites\Default Web Site\cps"').with_code(
        'Set-WebConfigurationProperty -Filter system.webServer/security/requestFiltering -PSPath "IIS:\\Sites\\Default Web Site\\cps" -Name allowDoubleEscaping -Value True'
      )
    end
  end
end
