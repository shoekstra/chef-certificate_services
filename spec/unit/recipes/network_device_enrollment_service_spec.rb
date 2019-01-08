require 'spec_helper'

require_relative '_iis_spec.rb'

describe 'certificate_services::network_device_enrollment_service' do
  let(:powershell_flags) { '-NoLogo -NonInteractive -NoProfile -ExecutionPolicy Unrestricted -InputFormat None' }
  let(:shellout_options_runas) { { user: 'USER', password: 'PASSWORD', domain: 'contoso.com', environment: { 'LC_ALL' => 'en_US.UTF-8', 'LANGUAGE' => 'en_US.UTF-8', 'LANG' => 'en_US.UTF-8' } } }

  describe 'when all attributes are default' do
    cached(:chef_run) do
      ChefSpec::SoloRunner.new.converge(described_recipe)
    end

    it 'should raise RuntimeError' do
      expect { chef_run }.to raise_error(
        ArgumentError,
        'You must supply a name when declaring a certificate_services_network_device_enrollment_service resource'
      )
    end
  end

  describe 'when specified with minimum attributes' do
    describe 'when the feature is not yet installed/configured' do
      cached(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_network_device_enrollment_service, :ruby_block]) do |node|
          node.automatic['domain'] = 'contoso.com'
          node.automatic['hostname'] = 'web1'
          node.normal['certificate_services']['network_device_enrollment_service']['ca_config'] = 'contoso-SUBCA\\CA'
          node.normal['certificate_services']['network_device_enrollment_service']['domain_user'] = 'USER'
          node.normal['certificate_services']['network_device_enrollment_service']['domain_pass'] = 'PASSWORD'
        end.converge(described_recipe)
      end

      before(:each) do
        allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).and_return(false)

        stub_command('(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"').and_return(false)
        stub_command('(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/basicAuthentication -PSPath "IIS:\\Sites\\Default Web Site\\CertSrv\\mscep_admin" -Name Enabled).Value -eq "True"').and_return(false)
        stub_command('(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/basicAuthentication -PSPath "IIS:\\Sites\\Default Web Site\\CertSrv\\mscep_admin" -Name logonMethod) -eq "ClearText"').and_return(false)
        stub_command('(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/windowsAuthentication -PSPath "IIS:\\Sites\\Default Web Site\\CertSrv\\mscep_admin" -Name Enabled).Value -eq $False').and_return(false)

        shellout_adcs_network_device_enrollment_service = double(run_command: nil, error!: nil, stdout: '', stderr: double(empty?: true))
        install_cmd = [
          'Install-AdcsNetworkDeviceEnrollmentService',
          '-CAConfig \'contoso-SUBCA\\CA\'',
          '-RAName \'WEB1-MSCEP-RA\'',
          '-EncryptionKeyLength 2048',
          '-EncryptionProviderName \'Microsoft Strong Cryptographic Provider\'',
          '-SigningKeyLength 2048',
          '-SigningProviderName \'Microsoft Strong Cryptographic Provider\'',
          '-Force',
          '-ApplicationPoolIdentity',
        ]
        Mixlib::ShellOut.stub(:new).with(
          "powershell.exe #{powershell_flags} -Command \"#{install_cmd.join(' ')}\"",
          shellout_options_runas).and_return(shellout_adcs_network_device_enrollment_service)
        allow(shellout_adcs_network_device_enrollment_service).to receive(:live_stream).and_return(nil)
        allow(shellout_adcs_network_device_enrollment_service).to receive(:live_stream=).and_return(nil)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_network_device_enrollment_service[contoso-SUBCA\\CA] resource' do
        expect(chef_run).to install_certificate_services_network_device_enrollment_service('contoso-SUBCA\\CA').with(
          'app_pool_identity' => true,
          'ca_config' => 'contoso-SUBCA\\CA',
          'domain_pass' => 'PASSWORD',
          'domain_user' => 'USER',
          'encryption_key_length' => 2048,
          'encryption_provider_name' => 'Microsoft Strong Cryptographic Provider',
          'ra_city' => nil,
          'ra_company' => nil,
          'ra_country' =>  nil,
          'ra_department' => nil,
          'ra_email' => nil,
          'ra_name' => 'WEB1-MSCEP-RA',
          'ra_state' => nil,
          'service_password' => nil,
          'service_user' => nil,
          'signing_key_length' => 2048,
          'signing_provider_name' => 'Microsoft Strong Cryptographic Provider'
        )
      end

      describe 'steps into certificate_network_device_enrollment_service[contoso-SUBCA\\CA]' do
        it_behaves_like 'IIS should be installed/configured'

        it 'should install Windows features' do
          %w(Adcs-Device-Enrollment).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should configure ADCS Network Device Enrollment Service' do
          expect(chef_run).to run_ruby_block('Configure ADCS Network Device Enrollment Service')
        end

        it 'should configure HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MSCEP registry keys' do
          expect(chef_run).to create_registry_key('HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MSCEP').with_values(
            [
              { name: 'EncryptionTemplate',     type: :string, data: 'IPSECIntermediateOffline' },
              { name: 'GeneralPurposeTemplate', type: :string, data: 'IPSECIntermediateOffline' },
              { name: 'SignatureTemplate',      type: :string, data: 'IPSECIntermediateOffline' },
            ]
          )
        end

        it 'should configure HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MSCEP\\UseSinglePassword registry keys' do
          expect(chef_run).to create_registry_key('HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MSCEP\\UseSinglePassword').with_values(
            [
              { name: 'UseSinglePassword', type: :dword, data: Chef::Digester.instance.generate_checksum(StringIO.new(0.to_s)) },
            ]
          )
        end

        it 'should configure HKLM\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters registry keys' do
          expect(chef_run).to create_registry_key('HKLM\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters').with_values(
            [
              { name: 'MaxFieldLength',  type: :dword, data: Chef::Digester.instance.generate_checksum(StringIO.new(65534.to_s)) },
              { name: 'MaxRequestBytes', type: :dword, data: Chef::Digester.instance.generate_checksum(StringIO.new(65534.to_s)) },
            ]
          )
        end
      end
    end

    describe 'when the feature is already installed/configured' do
      cached(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_network_device_enrollment_service, :ruby_block]) do |node|
          node.automatic['domain'] = 'contoso.com'
          node.automatic['hostname'] = 'web1'
          node.normal['certificate_services']['network_device_enrollment_service']['ca_config'] = 'contoso-SUBCA\\CA'
          node.normal['certificate_services']['network_device_enrollment_service']['domain_user'] = 'USER'
          node.normal['certificate_services']['network_device_enrollment_service']['domain_pass'] = 'PASSWORD'
        end.converge(described_recipe)
      end

      before(:each) do
        allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).with(anything).and_return(true)

        stub_command('(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"').and_return(true)
        stub_command('(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/basicAuthentication -PSPath "IIS:\\Sites\\Default Web Site\\CertSrv\\mscep_admin" -Name Enabled).Value -eq "True"').and_return(true)
        stub_command('(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/basicAuthentication -PSPath "IIS:\\Sites\\Default Web Site\\CertSrv\\mscep_admin" -Name logonMethod) -eq "ClearText"').and_return(true)
        stub_command('(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/windowsAuthentication -PSPath "IIS:\\Sites\\Default Web Site\\CertSrv\\mscep_admin" -Name Enabled).Value -eq $False').and_return(true)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_network_device_enrollment_service[contoso-SUBCA\\CA] resource' do
        expect(chef_run).to install_certificate_services_network_device_enrollment_service('contoso-SUBCA\\CA').with(
          'app_pool_identity' => true,
          'ca_config' => 'contoso-SUBCA\\CA',
          'domain_pass' => 'PASSWORD',
          'domain_user' => 'USER',
          'encryption_key_length' => 2048,
          'encryption_provider_name' => 'Microsoft Strong Cryptographic Provider',
          'ra_city' => nil,
          'ra_company' => nil,
          'ra_country' =>  nil,
          'ra_department' => nil,
          'ra_email' => nil,
          'ra_name' => 'WEB1-MSCEP-RA',
          'ra_state' => nil,
          'service_password' => nil,
          'service_user' => nil,
          'signing_key_length' => 2048,
          'signing_provider_name' => 'Microsoft Strong Cryptographic Provider'
        )
      end

      describe 'steps into certificate_network_device_enrollment_service[contoso-SUBCA\\CA]' do
        it_behaves_like 'IIS is already installed/configured'

        it 'should install Windows features' do
          %w(Adcs-Device-Enrollment).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should not configure ADCS Network Device Enrollment Service' do
          expect(chef_run).to_not run_ruby_block('Configure ADCS Network Device Enrollment Service')
        end

        it 'should configure HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MSCEP registry keys' do
          expect(chef_run).to create_registry_key('HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MSCEP').with_values(
            [
              { name: 'EncryptionTemplate',     type: :string, data: 'IPSECIntermediateOffline' },
              { name: 'GeneralPurposeTemplate', type: :string, data: 'IPSECIntermediateOffline' },
              { name: 'SignatureTemplate',      type: :string, data: 'IPSECIntermediateOffline' },
            ]
          )
        end

        it 'should configure HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MSCEP\\UseSinglePassword registry keys' do
          expect(chef_run).to create_registry_key('HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MSCEP\\UseSinglePassword').with_values(
            [
              { name: 'UseSinglePassword', type: :dword, data: Chef::Digester.instance.generate_checksum(StringIO.new(0.to_s)) },
            ]
          )
        end

        it 'should configure HKLM\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters registry keys' do
          expect(chef_run).to create_registry_key('HKLM\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters').with_values(
            [
              { name: 'MaxFieldLength',  type: :dword, data: Chef::Digester.instance.generate_checksum(StringIO.new(65534.to_s)) },
              { name: 'MaxRequestBytes', type: :dword, data: Chef::Digester.instance.generate_checksum(StringIO.new(65534.to_s)) },
            ]
          )
        end
      end
    end
  end

  describe 'when specified with all attributes' do
    describe 'when the feature is not yet installed/configured' do
      cached(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_network_device_enrollment_service, :ruby_block]) do |node|
          node.automatic['domain'] = 'contoso.com'
          node.automatic['hostname'] = 'web1'
          node.normal['certificate_services']['network_device_enrollment_service']['app_pool_identity'] = true
          node.normal['certificate_services']['network_device_enrollment_service']['ca_config'] = 'contoso-SUBCA\\CA'
          node.normal['certificate_services']['network_device_enrollment_service']['domain_pass'] = 'PASSWORD'
          node.normal['certificate_services']['network_device_enrollment_service']['domain_user'] = 'USER'
          node.normal['certificate_services']['network_device_enrollment_service']['encryption_key_length'] =  4096
          node.normal['certificate_services']['network_device_enrollment_service']['encryption_provider_name'] = 'Some CSP'
          node.normal['certificate_services']['network_device_enrollment_service']['encryption_template'] = 'CustomTemplate'
          node.normal['certificate_services']['network_device_enrollment_service']['general_purpose_template'] = 'CustomTemplate'
          node.normal['certificate_services']['network_device_enrollment_service']['ra_city'] = 'CITY'
          node.normal['certificate_services']['network_device_enrollment_service']['ra_company'] = 'COMP'
          node.normal['certificate_services']['network_device_enrollment_service']['ra_country'] =  'CC'
          node.normal['certificate_services']['network_device_enrollment_service']['ra_department'] = 'DEPT'
          node.normal['certificate_services']['network_device_enrollment_service']['ra_email'] = 'MAIL'
          node.normal['certificate_services']['network_device_enrollment_service']['ra_name'] = 'NAME'
          node.normal['certificate_services']['network_device_enrollment_service']['ra_state'] = 'STATE'
          node.normal['certificate_services']['network_device_enrollment_service']['service_password'] = 'SVC_PASSWORD'
          node.normal['certificate_services']['network_device_enrollment_service']['service_user'] = 'SVC_USER'
          node.normal['certificate_services']['network_device_enrollment_service']['signature_template'] = 'CustomTemplate'
          node.normal['certificate_services']['network_device_enrollment_service']['signing_key_length'] = 4096
          node.normal['certificate_services']['network_device_enrollment_service']['signing_provider_name'] = 'Some CSP'
          node.normal['certificate_services']['network_device_enrollment_service']['use_single_password'] = true
        end.converge(described_recipe)
      end

      before(:each) do
        allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).and_return(false)

        stub_command('(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"').and_return(false)
        stub_command('(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/basicAuthentication -PSPath "IIS:\\Sites\\Default Web Site\\CertSrv\\mscep_admin" -Name Enabled).Value -eq "True"').and_return(false)
        stub_command('(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/basicAuthentication -PSPath "IIS:\\Sites\\Default Web Site\\CertSrv\\mscep_admin" -Name logonMethod) -eq "ClearText"').and_return(false)
        stub_command('(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/windowsAuthentication -PSPath "IIS:\\Sites\\Default Web Site\\CertSrv\\mscep_admin" -Name Enabled).Value -eq $False').and_return(false)

        shellout_adcs_network_device_enrollment_service = double(run_command: nil, error!: nil, stdout: '', stderr: double(empty?: true))
        install_cmd = [
          'Install-AdcsNetworkDeviceEnrollmentService',
          '-CAConfig \'contoso-SUBCA\\CA\'',
          '-RAName \'NAME\'',
          '-EncryptionKeyLength 4096',
          '-EncryptionProviderName \'Some CSP\'',
          '-SigningKeyLength 4096',
          '-SigningProviderName \'Some CSP\'',
          '-Force',
          '-RACity \'CITY\' -RACompany \'COMP\' -RACountry \'CC\' -RADepartment \'DEPT\' -RAEmail \'MAIL\' -RAState \'STATE\'',
          '-ServiceAccountName contoso.com\\SVC_USER -ServiceAccountPassword $(ConvertTo-SecureString \'SVC_PASSWORD\' -AsPlainText -Force)',
        ]
        Mixlib::ShellOut.stub(:new).with(
          "powershell.exe #{powershell_flags} -Command \"#{install_cmd.join(' ')}\"",
          shellout_options_runas).and_return(shellout_adcs_network_device_enrollment_service)
        allow(shellout_adcs_network_device_enrollment_service).to receive(:live_stream).and_return(nil)
        allow(shellout_adcs_network_device_enrollment_service).to receive(:live_stream=).and_return(nil)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_network_device_enrollment_service[contoso-SUBCA\\CA] resource' do
        expect(chef_run).to install_certificate_services_network_device_enrollment_service('contoso-SUBCA\\CA').with(
          'app_pool_identity' => true,
          'ca_config' => 'contoso-SUBCA\\CA',
          'domain_pass' => 'PASSWORD',
          'domain_user' => 'USER',
          'encryption_key_length' =>  4096,
          'encryption_provider_name' => 'Some CSP',
          'encryption_template' => 'CustomTemplate',
          'general_purpose_template' => 'CustomTemplate',
          'ra_city' => 'CITY',
          'ra_company' => 'COMP',
          'ra_country' =>  'CC',
          'ra_department' => 'DEPT',
          'ra_email' => 'MAIL',
          'ra_name' => 'NAME',
          'ra_state' => 'STATE',
          'service_password' => 'SVC_PASSWORD',
          'service_user' => 'SVC_USER',
          'signature_template' => 'CustomTemplate',
          'signing_key_length' => 4096,
          'signing_provider_name' => 'Some CSP',
          'use_single_password' => true
        )
      end

      describe 'steps into certificate_network_device_enrollment_service[contoso-SUBCA\\CA]' do
        it_behaves_like 'IIS should be installed/configured'

        it 'should install Windows features' do
          %w(Adcs-Device-Enrollment).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should configure ADCS Network Device Enrollment Service' do
          expect(chef_run).to run_ruby_block('Configure ADCS Network Device Enrollment Service')
        end

        it 'should configure HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MSCEP registry keys' do
          expect(chef_run).to create_registry_key('HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MSCEP').with_values(
            [
              { name: 'EncryptionTemplate',     type: :string, data: 'CustomTemplate' },
              { name: 'GeneralPurposeTemplate', type: :string, data: 'CustomTemplate' },
              { name: 'SignatureTemplate',      type: :string, data: 'CustomTemplate' },
            ]
          )
        end

        it 'should configure HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MSCEP\\UseSinglePassword registry keys' do
          expect(chef_run).to create_registry_key('HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MSCEP\\UseSinglePassword').with_values(
            [
              { name: 'UseSinglePassword', type: :dword, data: Chef::Digester.instance.generate_checksum(StringIO.new(1.to_s)) },
            ]
          )
        end

        it 'should configure HKLM\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters registry keys' do
          expect(chef_run).to create_registry_key('HKLM\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters').with_values(
            [
              { name: 'MaxFieldLength',  type: :dword, data: Chef::Digester.instance.generate_checksum(StringIO.new(65534.to_s)) },
              { name: 'MaxRequestBytes', type: :dword, data: Chef::Digester.instance.generate_checksum(StringIO.new(65534.to_s)) },
            ]
          )
        end
      end
    end

    describe 'when the feature is already installed/configured' do
      cached(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_network_device_enrollment_service, :ruby_block]) do |node|
          node.automatic['domain'] = 'contoso.com'
          node.normal['certificate_services']['network_device_enrollment_service']['app_pool_identity'] = true
          node.normal['certificate_services']['network_device_enrollment_service']['ca_config'] = 'contoso-SUBCA\\CA'
          node.normal['certificate_services']['network_device_enrollment_service']['domain_pass'] = 'PASSWORD'
          node.normal['certificate_services']['network_device_enrollment_service']['domain_user'] = 'USER'
          node.normal['certificate_services']['network_device_enrollment_service']['encryption_key_length'] =  4096
          node.normal['certificate_services']['network_device_enrollment_service']['encryption_provider_name'] = 'Some CSP'
          node.normal['certificate_services']['network_device_enrollment_service']['encryption_template'] = 'CustomTemplate'
          node.normal['certificate_services']['network_device_enrollment_service']['general_purpose_template'] = 'CustomTemplate'
          node.normal['certificate_services']['network_device_enrollment_service']['ra_city'] = 'CITY'
          node.normal['certificate_services']['network_device_enrollment_service']['ra_company'] = 'COMP'
          node.normal['certificate_services']['network_device_enrollment_service']['ra_country'] =  'CC'
          node.normal['certificate_services']['network_device_enrollment_service']['ra_department'] = 'DEPT'
          node.normal['certificate_services']['network_device_enrollment_service']['ra_email'] = 'MAIL'
          node.normal['certificate_services']['network_device_enrollment_service']['ra_name'] = 'NAME'
          node.normal['certificate_services']['network_device_enrollment_service']['ra_state'] = 'STATE'
          node.normal['certificate_services']['network_device_enrollment_service']['service_password'] = 'SVC_PASSWORD'
          node.normal['certificate_services']['network_device_enrollment_service']['service_user'] = 'SVC_USER'
          node.normal['certificate_services']['network_device_enrollment_service']['signature_template'] = 'CustomTemplate'
          node.normal['certificate_services']['network_device_enrollment_service']['signing_key_length'] = 4096
          node.normal['certificate_services']['network_device_enrollment_service']['signing_provider_name'] = 'Some CSP'
          node.normal['certificate_services']['network_device_enrollment_service']['use_single_password'] = true
        end.converge(described_recipe)
      end

      before(:each) do
        allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).with(anything).and_return(true)

        stub_command('(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"').and_return(true)
        stub_command('(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/basicAuthentication -PSPath "IIS:\\Sites\\Default Web Site\\CertSrv\\mscep_admin" -Name Enabled).Value -eq "True"').and_return(true)
        stub_command('(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/basicAuthentication -PSPath "IIS:\\Sites\\Default Web Site\\CertSrv\\mscep_admin" -Name logonMethod) -eq "ClearText"').and_return(true)
        stub_command('(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/windowsAuthentication -PSPath "IIS:\\Sites\\Default Web Site\\CertSrv\\mscep_admin" -Name Enabled).Value -eq $False').and_return(true)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_network_device_enrollment_service[contoso-SUBCA\\CA] resource' do
        expect(chef_run).to install_certificate_services_network_device_enrollment_service('contoso-SUBCA\\CA').with(
          'app_pool_identity' => true,
          'ca_config' => 'contoso-SUBCA\\CA',
          'domain_pass' => 'PASSWORD',
          'domain_user' => 'USER',
          'encryption_key_length' =>  4096,
          'encryption_provider_name' => 'Some CSP',
          'encryption_template' => 'CustomTemplate',
          'general_purpose_template' => 'CustomTemplate',
          'ra_city' => 'CITY',
          'ra_company' => 'COMP',
          'ra_country' =>  'CC',
          'ra_department' => 'DEPT',
          'ra_email' => 'MAIL',
          'ra_name' => 'NAME',
          'ra_state' => 'STATE',
          'service_password' => 'SVC_PASSWORD',
          'service_user' => 'SVC_USER',
          'signature_template' => 'CustomTemplate',
          'signing_key_length' => 4096,
          'signing_provider_name' => 'Some CSP',
          'use_single_password' => true
        )
      end

      describe 'steps into certificate_network_device_enrollment_service[contoso-SUBCA\\CA]' do
        it_behaves_like 'IIS is already installed/configured'

        it 'should install Windows features' do
          %w(Adcs-Device-Enrollment).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should not configure ADCS Network Device Enrollment Service' do
          expect(chef_run).to_not run_ruby_block('Configure ADCS Network Device Enrollment Service')
        end

        it 'should configure HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MSCEP registry keys' do
          expect(chef_run).to create_registry_key('HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MSCEP').with_values(
            [
              { name: 'EncryptionTemplate',     type: :string, data: 'CustomTemplate' },
              { name: 'GeneralPurposeTemplate', type: :string, data: 'CustomTemplate' },
              { name: 'SignatureTemplate',      type: :string, data: 'CustomTemplate' },
            ]
          )
        end

        it 'should configure HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MSCEP\\UseSinglePassword registry keys' do
          expect(chef_run).to create_registry_key('HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MSCEP\\UseSinglePassword').with_values(
            [
              { name: 'UseSinglePassword', type: :dword, data: Chef::Digester.instance.generate_checksum(StringIO.new(1.to_s)) },
            ]
          )
        end

        it 'should configure HKLM\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters registry keys' do
          expect(chef_run).to create_registry_key('HKLM\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters').with_values(
            [
              { name: 'MaxFieldLength',  type: :dword, data: Chef::Digester.instance.generate_checksum(StringIO.new(65534.to_s)) },
              { name: 'MaxRequestBytes', type: :dword, data: Chef::Digester.instance.generate_checksum(StringIO.new(65534.to_s)) },
            ]
          )
        end
      end
    end
  end
end
