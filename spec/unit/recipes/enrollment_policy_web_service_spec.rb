#
# Cookbook Name:: certificate_services
# Spec:: enrollment_policy_web_service
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

require 'spec_helper'

require_relative '_iis_spec.rb'

describe 'certificate_services::enrollment_policy_web_service' do
  let(:powershell_flags) { '-NoLogo -NonInteractive -NoProfile -ExecutionPolicy Unrestricted -InputFormat None' }
  let(:shellout_options_runas) { { user: 'USER', password: 'PASSWORD', domain: 'contoso.com', environment: { 'LC_ALL' => 'en_US.UTF-8', 'LANGUAGE' => 'en_US.UTF-8', 'LANG' => 'en_US.UTF-8' } } }

  describe 'when all attributes are default' do
    let(:chef_run) do
      ChefSpec::SoloRunner.new.converge(described_recipe)
    end

    it 'should raise RuntimeError' do
      expect { chef_run }.to raise_error(
        RuntimeError,
        "To use certificate_services::enrollment_policy_web_service you must configure node['certificate_services']['enrollment_policy_web_service'] attributes"
      )
    end
  end

  describe 'when a Kerberos CEP is specified with minimum attributes' do
    describe 'when the feature is not yet installed/configured' do
      let(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_enrollment_policy_web_service, :ruby_block]) do |node|
          node.automatic['domain'] = 'contoso.com'
          node.normal['certificate_services']['enrollment_policy_web_service']['kerberos']['domain_user'] = 'USER'
          node.normal['certificate_services']['enrollment_policy_web_service']['kerberos']['domain_pass'] = 'PASSWORD'
        end.converge(described_recipe)
      end

      before(:each) do
        allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).and_return(false)

        stub_command('(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"').and_return(false)
        stub_command('((Get-WebConfigurationProperty -Filter /appSettings -Pspath "IIS:\\Sites\\Default Web Site\\ADPolicyProvider_CEP_Kerberos" -Name .).collection | ?{$_.Key -eq "FriendlyName"}).Value -eq "Enrollment Policy Web Service (Kerberos)"').and_return(false)

        shellout_adcs_enrollment_policy_web_service = double(run_command: nil, error!: nil, stdout: '', stderr: double(empty?: true))
        Mixlib::ShellOut.stub(:new).with(
          "powershell.exe #{powershell_flags} -Command \"Install-AdcsEnrollmentPolicyWebService -AuthenticationType Kerberos -Force\"",
          shellout_options_runas).and_return(shellout_adcs_enrollment_policy_web_service)
        allow(shellout_adcs_enrollment_policy_web_service).to receive(:live_stream).and_return(nil)
        allow(shellout_adcs_enrollment_policy_web_service).to receive(:live_stream=).and_return(nil)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_enrollment_policy_web_service[Kerberos] resource' do
        expect(chef_run).to install_certificate_services_enrollment_policy_web_service('kerberos').with(
          'domain_user' => 'USER',
          'domain_pass' => 'PASSWORD'
        )
      end

      describe 'steps into certificate_enrollment_policy_web_service[Kerberos]' do
        it_behaves_like 'IIS should be installed/configured'

        it 'should install Windows features' do
          %w(Adcs-Enroll-Web-Pol).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should configure ADCS Enrollment Policy Web Service' do
          expect(chef_run).to run_ruby_block('Configure ADCS Enrollment Web Service')
        end

        it 'should set Application FriendlyName to "Enrollment Policy Web Service (Kerberos)" for "IIS:\Sites\Default Web Site\ADPolicyProvider_CEP_Kerberos' do
          allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).and_return(true)

          expect(chef_run).to run_powershell_script('Set Application FriendlyName to "Enrollment Policy Web Service (Kerberos)" for "IIS:\Sites\Default Web Site\ADPolicyProvider_CEP_Kerberos"').with_code(
            'Set-WebConfigurationProperty -Filter "/appSettings/add[@key=\'FriendlyName\']" -Pspath "IIS:\\Sites\\Default Web Site\\ADPolicyProvider_CEP_Kerberos" -Name "Value" -Value "Enrollment Policy Web Service (Kerberos)"'
          )
          expect(chef_run.powershell_script('Set Application FriendlyName to "Enrollment Policy Web Service (Kerberos)" for "IIS:\Sites\Default Web Site\ADPolicyProvider_CEP_Kerberos"')).to notify('windows_service[W3SVC]').to(:restart).delayed
        end
      end
    end

    describe 'when the feature is already installed/configured' do
      let(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_enrollment_policy_web_service, :ruby_block]) do |node|
          node.automatic['domain'] = 'contoso.com'
          node.normal['certificate_services']['enrollment_policy_web_service']['kerberos']['domain_user'] = 'USER'
          node.normal['certificate_services']['enrollment_policy_web_service']['kerberos']['domain_pass'] = 'PASSWORD'
        end.converge(described_recipe)
      end

      before(:each) do
        allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).and_return(true)

        stub_command('(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"').and_return(true)
        stub_command('((Get-WebConfigurationProperty -Filter /appSettings -Pspath "IIS:\\Sites\\Default Web Site\\ADPolicyProvider_CEP_Kerberos" -Name .).collection | ?{$_.Key -eq "FriendlyName"}).Value -eq "Enrollment Policy Web Service (Kerberos)"').and_return(true)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_enrollment_policy_web_service[Kerberos] resource' do
        expect(chef_run).to install_certificate_services_enrollment_policy_web_service('kerberos').with(
          'domain_user' => 'USER',
          'domain_pass' => 'PASSWORD'
        )
      end

      describe 'steps into certificate_enrollment_policy_web_service[Kerberos]' do
        it_behaves_like 'IIS is already installed/configured'

        it 'should install Windows features' do
          %w(Adcs-Enroll-Web-Pol).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should not configure ADCS Enrollment Policy Web Service' do
          expect(chef_run).to_not run_ruby_block('Configure ADCS Enrollment Web Service')
        end

        it 'should not set Application FriendlyName to "Enrollment Policy Web Service (Kerberos)" for "IIS:\Sites\Default Web Site\ADPolicyProvider_CEP_Kerberos' do
          expect(chef_run).to_not run_powershell_script('Set Application FriendlyName to "Enrollment Policy Web Service (Kerberos)" for "IIS:\Sites\Default Web Site\ADPolicyProvider_CEP_Kerberos"')
        end
      end
    end
  end

  describe 'when a Kerberos CEP is specified with all attributes' do
    describe 'when the feature is not yet installed/configured' do
      let(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_enrollment_policy_web_service, :ruby_block]) do |node|
          node.automatic['domain'] = 'contoso.com'
          node.normal['certificate_services']['enrollment_policy_web_service']['kerberos']['domain_pass'] = 'PASSWORD'
          node.normal['certificate_services']['enrollment_policy_web_service']['kerberos']['domain_user'] = 'USER'
          node.normal['certificate_services']['enrollment_policy_web_service']['kerberos']['friendly_name'] = 'KERBEROS'
          node.normal['certificate_services']['enrollment_policy_web_service']['kerberos']['key_based_renewal'] = true
        end.converge(described_recipe)
      end

      before(:each) do
        allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).and_return(false)

        stub_command('(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"').and_return(false)
        stub_command('((Get-WebConfigurationProperty -Filter /appSettings -Pspath "IIS:\\Sites\\Default Web Site\\ADPolicyProvider_CEP_Kerberos" -Name .).collection | ?{$_.Key -eq "FriendlyName"}).Value -eq "KERBEROS"').and_return(false)

        shellout_adcs_enrollment_policy_web_service = double(run_command: nil, error!: nil, stdout: '', stderr: double(empty?: true))
        Mixlib::ShellOut.stub(:new).with(
          "powershell.exe #{powershell_flags} -Command \"Install-AdcsEnrollmentPolicyWebService -AuthenticationType Kerberos -Force -KeyBasedRenewal\"",
          shellout_options_runas).and_return(shellout_adcs_enrollment_policy_web_service)
        allow(shellout_adcs_enrollment_policy_web_service).to receive(:live_stream).and_return(nil)
        allow(shellout_adcs_enrollment_policy_web_service).to receive(:live_stream=).and_return(nil)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_enrollment_policy_web_service[Kerberos] resource' do
        expect(chef_run).to install_certificate_services_enrollment_policy_web_service('kerberos').with(
          'domain_pass' => 'PASSWORD',
          'domain_user' => 'USER',
          'key_based_renewal' => true
        )
      end

      describe 'steps into certificate_enrollment_policy_web_service[Kerberos]' do
        it_behaves_like 'IIS should be installed/configured'

        it 'should install Windows features' do
          %w(Adcs-Enroll-Web-Pol).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should configure ADCS Enrollment Policy Web Service' do
          expect(chef_run).to run_ruby_block('Configure ADCS Enrollment Web Service')
        end

        it 'should set Application FriendlyName to "KERBEROS" for "IIS:\Sites\Default Web Site\ADPolicyProvider_CEP_Kerberos' do
          allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).and_return(true)

          expect(chef_run).to run_powershell_script('Set Application FriendlyName to "KERBEROS" for "IIS:\Sites\Default Web Site\ADPolicyProvider_CEP_Kerberos"').with_code(
            'Set-WebConfigurationProperty -Filter "/appSettings/add[@key=\'FriendlyName\']" -Pspath "IIS:\\Sites\\Default Web Site\\ADPolicyProvider_CEP_Kerberos" -Name "Value" -Value "KERBEROS"'
          )
          expect(chef_run.powershell_script('Set Application FriendlyName to "KERBEROS" for "IIS:\Sites\Default Web Site\ADPolicyProvider_CEP_Kerberos"')).to notify('windows_service[W3SVC]').to(:restart).delayed
        end
      end
    end

    describe 'when the feature is already installed/configured' do
      let(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_enrollment_policy_web_service, :ruby_block]) do |node|
          node.automatic['domain'] = 'contoso.com'
          node.normal['certificate_services']['enrollment_policy_web_service']['kerberos']['domain_pass'] = 'PASSWORD'
          node.normal['certificate_services']['enrollment_policy_web_service']['kerberos']['domain_user'] = 'USER'
          node.normal['certificate_services']['enrollment_policy_web_service']['kerberos']['friendly_name'] = 'KERBEROS'
          node.normal['certificate_services']['enrollment_policy_web_service']['kerberos']['key_based_renewal'] = true
        end.converge(described_recipe)
      end

      before(:each) do
        allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).and_return(true)

        stub_command('(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"').and_return(true)
        stub_command('((Get-WebConfigurationProperty -Filter /appSettings -Pspath "IIS:\\Sites\\Default Web Site\\ADPolicyProvider_CEP_Kerberos" -Name .).collection | ?{$_.Key -eq "FriendlyName"}).Value -eq "KERBEROS"').and_return(true)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_enrollment_policy_web_service[Kerberos] resource' do
        expect(chef_run).to install_certificate_services_enrollment_policy_web_service('kerberos').with(
          'domain_pass' => 'PASSWORD',
          'domain_user' => 'USER',
          'key_based_renewal' => true
        )
      end

      describe 'steps into certificate_enrollment_policy_web_service[Kerberos]' do
        it_behaves_like 'IIS is already installed/configured'

        it 'should install Windows features' do
          %w(Adcs-Enroll-Web-Pol).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should not configure ADCS Enrollment Policy Web Service' do
          expect(chef_run).to_not run_ruby_block('Configure ADCS Enrollment Web Service')
        end

        it 'should not set Application FriendlyName to "KERBEROS" for "IIS:\Sites\Default Web Site\ADPolicyProvider_CEP_Kerberos' do
          expect(chef_run).to_not run_powershell_script('Set Application FriendlyName to "KERBEROS" for "IIS:\Sites\Default Web Site\ADPolicyProvider_CEP_Kerberos"')
        end
      end
    end
  end

  describe 'when a Username CEP is specified with minimum attributes' do
    describe 'when the feature is not yet installed/configured' do
      let(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_enrollment_policy_web_service, :ruby_block]) do |node|
          node.automatic['domain'] = 'contoso.com'
          node.normal['certificate_services']['enrollment_policy_web_service']['username']['domain_user'] = 'USER'
          node.normal['certificate_services']['enrollment_policy_web_service']['username']['domain_pass'] = 'PASSWORD'
        end.converge(described_recipe)
      end

      before(:each) do
        allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).and_return(false)

        stub_command('(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"').and_return(false)
        stub_command('((Get-WebConfigurationProperty -Filter /appSettings -Pspath "IIS:\\Sites\\Default Web Site\\ADPolicyProvider_CEP_UsernamePassword" -Name .).collection | ?{$_.Key -eq "FriendlyName"}).Value -eq "Enrollment Policy Web Service (Username)"').and_return(false)

        shellout_adcs_enrollment_policy_web_service = double(run_command: nil, error!: nil, stdout: '', stderr: double(empty?: true))
        Mixlib::ShellOut.stub(:new).with(
          "powershell.exe #{powershell_flags} -Command \"Install-AdcsEnrollmentPolicyWebService -AuthenticationType Username -Force\"",
          shellout_options_runas).and_return(shellout_adcs_enrollment_policy_web_service)
        allow(shellout_adcs_enrollment_policy_web_service).to receive(:live_stream).and_return(nil)
        allow(shellout_adcs_enrollment_policy_web_service).to receive(:live_stream=).and_return(nil)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_enrollment_policy_web_service[username] resource' do
        expect(chef_run).to install_certificate_services_enrollment_policy_web_service('username').with(
          'domain_user' => 'USER',
          'domain_pass' => 'PASSWORD'
        )
      end

      describe 'steps into certificate_enrollment_policy_web_service[username]' do
        it_behaves_like 'IIS should be installed/configured'

        it 'should install Windows features' do
          %w(Adcs-Enroll-Web-Pol).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should configure ADCS Enrollment Policy Web Service' do
          expect(chef_run).to run_ruby_block('Configure ADCS Enrollment Web Service')
        end

        it 'should set Application FriendlyName to "Enrollment Policy Web Service (Username)" for "IIS:\Sites\Default Web Site\ADPolicyProvider_CEP_UsernamePassword' do
          allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).and_return(true)

          expect(chef_run).to run_powershell_script('Set Application FriendlyName to "Enrollment Policy Web Service (Username)" for "IIS:\Sites\Default Web Site\ADPolicyProvider_CEP_UsernamePassword"').with_code(
            'Set-WebConfigurationProperty -Filter "/appSettings/add[@key=\'FriendlyName\']" -Pspath "IIS:\\Sites\\Default Web Site\\ADPolicyProvider_CEP_UsernamePassword" -Name "Value" -Value "Enrollment Policy Web Service (Username)"'
          )
          expect(chef_run.powershell_script('Set Application FriendlyName to "Enrollment Policy Web Service (Username)" for "IIS:\Sites\Default Web Site\ADPolicyProvider_CEP_UsernamePassword"')).to notify('windows_service[W3SVC]').to(:restart).delayed
        end
      end
    end

    describe 'when the feature is already installed/configured' do
      let(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_enrollment_policy_web_service, :ruby_block]) do |node|
          node.automatic['domain'] = 'contoso.com'
          node.normal['certificate_services']['enrollment_policy_web_service']['username']['domain_user'] = 'USER'
          node.normal['certificate_services']['enrollment_policy_web_service']['username']['domain_pass'] = 'PASSWORD'
        end.converge(described_recipe)
      end

      before(:each) do
        allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).and_return(true)

        stub_command('(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"').and_return(true)
        stub_command('((Get-WebConfigurationProperty -Filter /appSettings -Pspath "IIS:\\Sites\\Default Web Site\\ADPolicyProvider_CEP_UsernamePassword" -Name .).collection | ?{$_.Key -eq "FriendlyName"}).Value -eq "Enrollment Policy Web Service (Username)"').and_return(true)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_enrollment_policy_web_service[username] resource' do
        expect(chef_run).to install_certificate_services_enrollment_policy_web_service('username').with(
          'domain_user' => 'USER',
          'domain_pass' => 'PASSWORD'
        )
      end

      describe 'steps into certificate_enrollment_policy_web_service[username]' do
        it_behaves_like 'IIS is already installed/configured'

        it 'should install Windows features' do
          %w(Adcs-Enroll-Web-Pol).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should not configure ADCS Enrollment Policy Web Service' do
          expect(chef_run).to_not run_ruby_block('Configure ADCS Enrollment Web Service')
        end

        it 'should not set Application FriendlyName to "Enrollment Policy Web Service (Username)" for "IIS:\Sites\Default Web Site\ADPolicyProvider_CEP_UsernamePassword' do
          expect(chef_run).to_not run_powershell_script('Set Application FriendlyName to "Enrollment Policy Web Service (Username)" for "IIS:\Sites\Default Web Site\ADPolicyProvider_CEP_UsernamePassword"')
        end
      end
    end
  end

  describe 'when a Username CEP is specified with all attributes' do
    describe 'when the feature is not yet installed/configured' do
      let(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_enrollment_policy_web_service, :ruby_block]) do |node|
          node.automatic['domain'] = 'contoso.com'
          node.normal['certificate_services']['enrollment_policy_web_service']['username']['domain_pass'] = 'PASSWORD'
          node.normal['certificate_services']['enrollment_policy_web_service']['username']['domain_user'] = 'USER'
          node.normal['certificate_services']['enrollment_policy_web_service']['username']['friendly_name'] = 'USER'
          node.normal['certificate_services']['enrollment_policy_web_service']['username']['key_based_renewal'] = true
        end.converge(described_recipe)
      end

      before(:each) do
        allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).and_return(false)

        stub_command('(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"').and_return(false)
        stub_command('((Get-WebConfigurationProperty -Filter /appSettings -Pspath "IIS:\\Sites\\Default Web Site\\ADPolicyProvider_CEP_UsernamePassword" -Name .).collection | ?{$_.Key -eq "FriendlyName"}).Value -eq "USER"').and_return(false)

        shellout_adcs_enrollment_policy_web_service = double(run_command: nil, error!: nil, stdout: '', stderr: double(empty?: true))
        Mixlib::ShellOut.stub(:new).with(
          "powershell.exe #{powershell_flags} -Command \"Install-AdcsEnrollmentPolicyWebService -AuthenticationType Username -Force -KeyBasedRenewal\"",
          shellout_options_runas).and_return(shellout_adcs_enrollment_policy_web_service)
        allow(shellout_adcs_enrollment_policy_web_service).to receive(:live_stream).and_return(nil)
        allow(shellout_adcs_enrollment_policy_web_service).to receive(:live_stream=).and_return(nil)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_enrollment_policy_web_service[username] resource' do
        expect(chef_run).to install_certificate_services_enrollment_policy_web_service('username').with(
          'domain_pass' => 'PASSWORD',
          'domain_user' => 'USER',
          'key_based_renewal' => true
        )
      end

      describe 'steps into certificate_enrollment_policy_web_service[username]' do
        it_behaves_like 'IIS should be installed/configured'

        it 'should install Windows features' do
          %w(Adcs-Enroll-Web-Pol).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should configure ADCS Enrollment Policy Web Service' do
          expect(chef_run).to run_ruby_block('Configure ADCS Enrollment Web Service')
        end

        it 'should set Application FriendlyName to "USER" for "IIS:\Sites\Default Web Site\ADPolicyProvider_CEP_UsernamePassword' do
          allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).and_return(true)

          expect(chef_run).to run_powershell_script('Set Application FriendlyName to "USER" for "IIS:\Sites\Default Web Site\ADPolicyProvider_CEP_UsernamePassword"').with_code(
            'Set-WebConfigurationProperty -Filter "/appSettings/add[@key=\'FriendlyName\']" -Pspath "IIS:\\Sites\\Default Web Site\\ADPolicyProvider_CEP_UsernamePassword" -Name "Value" -Value "USER"'
          )
          expect(chef_run.powershell_script('Set Application FriendlyName to "USER" for "IIS:\Sites\Default Web Site\ADPolicyProvider_CEP_UsernamePassword"')).to notify('windows_service[W3SVC]').to(:restart).delayed
        end
      end
    end

    describe 'when the feature is already installed/configured' do
      let(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_enrollment_policy_web_service, :ruby_block]) do |node|
          node.automatic['domain'] = 'contoso.com'
          node.normal['certificate_services']['enrollment_policy_web_service']['username']['domain_pass'] = 'PASSWORD'
          node.normal['certificate_services']['enrollment_policy_web_service']['username']['domain_user'] = 'USER'
          node.normal['certificate_services']['enrollment_policy_web_service']['username']['friendly_name'] = 'USER'
          node.normal['certificate_services']['enrollment_policy_web_service']['username']['key_based_renewal'] = true
        end.converge(described_recipe)
      end

      before(:each) do
        allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).and_return(true)

        stub_command('(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"').and_return(true)
        stub_command('((Get-WebConfigurationProperty -Filter /appSettings -Pspath "IIS:\\Sites\\Default Web Site\\ADPolicyProvider_CEP_UsernamePassword" -Name .).collection | ?{$_.Key -eq "FriendlyName"}).Value -eq "USER"').and_return(true)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_enrollment_policy_web_service[username] resource' do
        expect(chef_run).to install_certificate_services_enrollment_policy_web_service('username').with(
          'domain_pass' => 'PASSWORD',
          'domain_user' => 'USER',
          'key_based_renewal' => true
        )
      end

      describe 'steps into certificate_enrollment_policy_web_service[username]' do
        it_behaves_like 'IIS is already installed/configured'

        it 'should install Windows features' do
          %w(Adcs-Enroll-Web-Pol).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should not configure ADCS Enrollment Policy Web Service' do
          expect(chef_run).to_not run_ruby_block('Configure ADCS Enrollment Web Service')
        end

        it 'should not set Application FriendlyName to "USER" for "IIS:\Sites\Default Web Site\ADPolicyProvider_CEP_UsernamePassword' do
          expect(chef_run).to_not run_powershell_script('Set Application FriendlyName to "USER" for "IIS:\Sites\Default Web Site\ADPolicyProvider_CEP_UsernamePassword"')
        end
      end
    end
  end

  describe 'when both CEP types are specified' do
    let(:chef_run) do
      ChefSpec::SoloRunner.new do |node|
        node.automatic['domain'] = 'contoso.com'
        node.normal['certificate_services']['enrollment_policy_web_service']['kerberos']['domain_pass'] = 'PASSWORD'
        node.normal['certificate_services']['enrollment_policy_web_service']['kerberos']['domain_user'] = 'USER'
        node.normal['certificate_services']['enrollment_policy_web_service']['username']['domain_pass'] = 'PASSWORD'
        node.normal['certificate_services']['enrollment_policy_web_service']['username']['domain_user'] = 'USER'
      end.converge(described_recipe)
    end

    it 'should converge successfully' do
      expect { chef_run }.to_not raise_error
    end

    it 'should create a certificate_enrollment_policy_web_service[kerberos] resource' do
      expect(chef_run).to install_certificate_services_enrollment_policy_web_service('kerberos').with(
        'domain_pass' => 'PASSWORD',
        'domain_user' => 'USER'
      )
    end

    it 'should create a certificate_enrollment_policy_web_service[username] resource' do
      expect(chef_run).to install_certificate_services_enrollment_policy_web_service('username').with(
        'domain_pass' => 'PASSWORD',
        'domain_user' => 'USER'
      )
    end
  end
end
