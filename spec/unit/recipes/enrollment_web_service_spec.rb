#
# Cookbook Name:: certificate_services
# Spec:: enrollment_web_service
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

require 'spec_helper'

require_relative '_iis_spec.rb'

describe 'certificate_services::enrollment_web_service' do
  let(:powershell_flags) { '-NoLogo -NonInteractive -NoProfile -ExecutionPolicy Unrestricted -InputFormat None' }
  let(:shellout_options_runas) { { user: 'USER', password: 'PASSWORD', domain: 'contoso.com', environment: { 'LC_ALL' => 'en_US.UTF-8', 'LANGUAGE' => 'en_US.UTF-8', 'LANG' => 'en_US.UTF-8' } } }

  describe 'when all attributes are default' do
    cached(:chef_run) do
      ChefSpec::SoloRunner.new.converge(described_recipe)
    end

    it 'should raise RuntimeError' do
      expect { chef_run }.to raise_error(
        RuntimeError,
        "To use certificate_services::enrollment_web_service you must configure node['certificate_services']['enrollment_web_service'] attributes"
      )
    end
  end

  describe 'when a Kerberos CES is specified with minimum attributes' do
    describe 'when the feature is not yet installed/configured' do
      cached(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_enrollment_web_service, :ruby_block]) do |node|
          node.automatic['domain'] = 'contoso.com'
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['ca_config'] = 'contoso-SUBCA\\CA'
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['domain_user'] = 'USER'
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['domain_pass'] = 'PASSWORD'
        end.converge(described_recipe)
      end

      before(:each) do
        allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).and_return(false)

        stub_command('(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"').and_return(false)

        shellout_adcs_enrollment_web_service = double(run_command: nil, error!: nil, stdout: '', stderr: double(empty?: true))
        Mixlib::ShellOut.stub(:new).with(
          "powershell.exe #{powershell_flags} -Command \"Install-AdcsEnrollmentWebService -AuthenticationType Kerberos -Force -CAConfig 'contoso-SUBCA\\CA'\"",
          shellout_options_runas).and_return(shellout_adcs_enrollment_web_service)
        allow(shellout_adcs_enrollment_web_service).to receive(:live_stream).and_return(nil)
        allow(shellout_adcs_enrollment_web_service).to receive(:live_stream=).and_return(nil)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_services_enrollment_web_service[Kerberos] resource' do
        expect(chef_run).to install_certificate_services_enrollment_web_service('kerberos').with(
          'ca_config' => 'contoso-SUBCA\\CA',
          'domain_user' => 'USER',
          'domain_pass' => 'PASSWORD'
        )
      end

      describe 'steps into certificate_services_enrollment_web_service[Kerberos]' do
        it_behaves_like 'IIS should be installed/configured'

        it 'should install Windows features' do
          %w(ADCS-Enroll-Web-Svc).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should configure ADCS Enrollment Web Service' do
          expect(chef_run).to run_ruby_block('Configure ADCS Enrollment Web Service')
        end
      end
    end

    describe 'when the feature is already installed/configured' do
      cached(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_enrollment_web_service, :ruby_block]) do |node|
          node.automatic['domain'] = 'contoso.com'
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['ca_config'] = 'contoso-SUBCA\\CA'
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['domain_user'] = 'USER'
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['domain_pass'] = 'PASSWORD'
        end.converge(described_recipe)
      end

      before(:each) do
        allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).with(anything).and_return(true)

        stub_command('(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"').and_return(true)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_services_enrollment_web_service[Kerberos] resource' do
        expect(chef_run).to install_certificate_services_enrollment_web_service('kerberos').with(
          'ca_config' => 'contoso-SUBCA\\CA',
          'domain_user' => 'USER',
          'domain_pass' => 'PASSWORD'
        )
      end

      describe 'steps into certificate_services_enrollment_web_service[Kerberos]' do
        it_behaves_like 'IIS is already installed/configured'

        it 'should install Windows features' do
          %w(ADCS-Enroll-Web-Svc).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should not configure ADCS Enrollment Web Service' do
          expect(chef_run).to_not run_ruby_block('Configure ADCS Enrollment Web Service')
        end
      end
    end
  end

  describe 'when a Kerberos CES is specified with all attributes' do
    describe 'when the feature is not yet installed/configured' do
      cached(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_enrollment_web_service, :ruby_block]) do |node|
          node.automatic['domain'] = 'contoso.com'
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['allow_key_based_renewal'] = true
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['app_pool_identity'] = true
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['ca_config'] = 'contoso-SUBCA\\CA'
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['domain_pass'] = 'PASSWORD'
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['domain_user'] = 'USER'
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['renewal_only'] = true
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['service_password'] = 'SVC_PASSWORD'
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['service_user'] = 'SVC_USER'
        end.converge(described_recipe)
      end

      before(:each) do
        allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).and_return(false)

        stub_command('(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"').and_return(false)

        shellout_adcs_enrollment_web_service = double(run_command: nil, error!: nil, stdout: '', stderr: double(empty?: true))
        Mixlib::ShellOut.stub(:new).with(
          "powershell.exe #{powershell_flags} -Command \"Install-AdcsEnrollmentWebService -AuthenticationType Kerberos -Force -CAConfig 'contoso-SUBCA\\CA' -AllowKeyBasedRenewal -RenewalOnly -ServiceAccountName contoso.com\\SVC_USER -ServiceAccountPassword $(ConvertTo-SecureString 'SVC_PASSWORD' -AsPlainText -Force)\"",
          shellout_options_runas).and_return(shellout_adcs_enrollment_web_service)
        allow(shellout_adcs_enrollment_web_service).to receive(:live_stream).and_return(nil)
        allow(shellout_adcs_enrollment_web_service).to receive(:live_stream=).and_return(nil)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_services_enrollment_web_service[Kerberos] resource' do
        expect(chef_run).to install_certificate_services_enrollment_web_service('kerberos').with(
          'allow_key_based_renewal' => true,
          'app_pool_identity' => true,
          'ca_config' => 'contoso-SUBCA\\CA',
          'domain_pass' => 'PASSWORD',
          'domain_user' => 'USER',
          'renewal_only' => true,
          'service_password' => 'SVC_PASSWORD',
          'service_user' => 'SVC_USER'
        )
      end

      describe 'steps into certificate_services_enrollment_web_service[Kerberos]' do
        it_behaves_like 'IIS should be installed/configured'

        it 'should install Windows features' do
          %w(ADCS-Enroll-Web-Svc).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should configure ADCS Enrollment Web Service' do
          expect(chef_run).to run_ruby_block('Configure ADCS Enrollment Web Service')
        end
      end
    end

    describe 'when the feature is already installed/configured' do
      cached(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_enrollment_web_service, :ruby_block]) do |node|
          node.automatic['domain'] = 'contoso.com'
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['allow_key_based_renewal'] = true
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['app_pool_identity'] = true
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['ca_config'] = 'contoso-SUBCA\\CA'
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['domain_pass'] = 'PASSWORD'
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['domain_user'] = 'USER'
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['renewal_only'] = true
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['service_password'] = 'SVC_PASSWORD'
          node.normal['certificate_services']['enrollment_web_service']['kerberos']['service_user'] = 'SVC_USER'
        end.converge(described_recipe)
      end

      before(:each) do
        allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).with(anything).and_return(true)

        stub_command('(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"').and_return(true)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_services_enrollment_web_service[Kerberos] resource' do
        expect(chef_run).to install_certificate_services_enrollment_web_service('kerberos').with(
          'allow_key_based_renewal' => true,
          'app_pool_identity' => true,
          'ca_config' => 'contoso-SUBCA\\CA',
          'domain_pass' => 'PASSWORD',
          'domain_user' => 'USER',
          'renewal_only' => true,
          'service_password' => 'SVC_PASSWORD',
          'service_user' => 'SVC_USER'
        )
      end

      describe 'steps into certificate_services_enrollment_web_service[Kerberos]' do
        it_behaves_like 'IIS is already installed/configured'

        it 'should install Windows features' do
          %w(ADCS-Enroll-Web-Svc).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should not configure ADCS Enrollment Web Service' do
          expect(chef_run).to_not run_ruby_block('Configure ADCS Enrollment Web Service')
        end
      end
    end
  end

  describe 'when a Username CES is specified with minimum attributes' do
    describe 'when the feature is not yet installed/configured' do
      cached(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_enrollment_web_service, :ruby_block]) do |node|
          node.automatic['domain'] = 'contoso.com'
          node.normal['certificate_services']['enrollment_web_service']['username']['ca_config'] = 'contoso-SUBCA\\CA'
          node.normal['certificate_services']['enrollment_web_service']['username']['domain_user'] = 'USER'
          node.normal['certificate_services']['enrollment_web_service']['username']['domain_pass'] = 'PASSWORD'
        end.converge(described_recipe)
      end

      before(:each) do
        allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).and_return(false)

        stub_command('(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"').and_return(false)

        shellout_adcs_enrollment_web_service = double(run_command: nil, error!: nil, stdout: '', stderr: double(empty?: true))
        Mixlib::ShellOut.stub(:new).with(
          "powershell.exe #{powershell_flags} -Command \"Install-AdcsEnrollmentWebService -AuthenticationType Username -Force -CAConfig 'contoso-SUBCA\\CA'\"",
          shellout_options_runas).and_return(shellout_adcs_enrollment_web_service)
        allow(shellout_adcs_enrollment_web_service).to receive(:live_stream).and_return(nil)
        allow(shellout_adcs_enrollment_web_service).to receive(:live_stream=).and_return(nil)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_services_enrollment_web_service[username] resource' do
        expect(chef_run).to install_certificate_services_enrollment_web_service('username').with(
          'ca_config' => 'contoso-SUBCA\\CA',
          'domain_user' => 'USER',
          'domain_pass' => 'PASSWORD'
        )
      end

      describe 'steps into certificate_services_enrollment_web_service[username]' do
        it_behaves_like 'IIS should be installed/configured'

        it 'should install Windows features' do
          %w(ADCS-Enroll-Web-Svc).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should configure ADCS Enrollment Web Service' do
          expect(chef_run).to run_ruby_block('Configure ADCS Enrollment Web Service')
        end
      end
    end

    describe 'when the feature is already installed/configured' do
      cached(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_enrollment_web_service, :ruby_block]) do |node|
          node.automatic['domain'] = 'contoso.com'
          node.normal['certificate_services']['enrollment_web_service']['username']['ca_config'] = 'contoso-SUBCA\\CA'
          node.normal['certificate_services']['enrollment_web_service']['username']['domain_user'] = 'USER'
          node.normal['certificate_services']['enrollment_web_service']['username']['domain_pass'] = 'PASSWORD'
        end.converge(described_recipe)
      end

      before(:each) do
        allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).with(anything).and_return(true)

        stub_command('(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"').and_return(true)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_services_enrollment_web_service[username] resource' do
        expect(chef_run).to install_certificate_services_enrollment_web_service('username').with(
          'ca_config' => 'contoso-SUBCA\\CA',
          'domain_user' => 'USER',
          'domain_pass' => 'PASSWORD'
        )
      end

      describe 'steps into certificate_services_enrollment_web_service[username]' do
        it_behaves_like 'IIS is already installed/configured'

        it 'should install Windows features' do
          %w(ADCS-Enroll-Web-Svc).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should not configure ADCS Enrollment Web Service' do
          expect(chef_run).to_not run_ruby_block('Configure ADCS Enrollment Web Service')
        end
      end
    end
  end

  describe 'when a Username CES is specified with all attributes' do
    describe 'when the feature is not yet installed/configured' do
      cached(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_enrollment_web_service, :ruby_block]) do |node|
          node.automatic['domain'] = 'contoso.com'
          node.normal['certificate_services']['enrollment_web_service']['username']['allow_key_based_renewal'] = true
          node.normal['certificate_services']['enrollment_web_service']['username']['app_pool_identity'] = true
          node.normal['certificate_services']['enrollment_web_service']['username']['ca_config'] = 'contoso-SUBCA\\CA'
          node.normal['certificate_services']['enrollment_web_service']['username']['domain_pass'] = 'PASSWORD'
          node.normal['certificate_services']['enrollment_web_service']['username']['domain_user'] = 'USER'
          node.normal['certificate_services']['enrollment_web_service']['username']['renewal_only'] = true
          node.normal['certificate_services']['enrollment_web_service']['username']['service_password'] = 'SVC_PASSWORD'
          node.normal['certificate_services']['enrollment_web_service']['username']['service_user'] = 'SVC_USER'
        end.converge(described_recipe)
      end

      before(:each) do
        allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).and_return(false)

        stub_command('(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"').and_return(false)

        shellout_adcs_enrollment_web_service = double(run_command: nil, error!: nil, stdout: '', stderr: double(empty?: true))
        Mixlib::ShellOut.stub(:new).with(
          "powershell.exe #{powershell_flags} -Command \"Install-AdcsEnrollmentWebService -AuthenticationType Username -Force -CAConfig 'contoso-SUBCA\\CA' -AllowKeyBasedRenewal -RenewalOnly -ServiceAccountName contoso.com\\SVC_USER -ServiceAccountPassword $(ConvertTo-SecureString 'SVC_PASSWORD' -AsPlainText -Force)\"",
          shellout_options_runas).and_return(shellout_adcs_enrollment_web_service)
        allow(shellout_adcs_enrollment_web_service).to receive(:live_stream).and_return(nil)
        allow(shellout_adcs_enrollment_web_service).to receive(:live_stream=).and_return(nil)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_services_enrollment_web_service[username] resource' do
        expect(chef_run).to install_certificate_services_enrollment_web_service('username').with(
          'allow_key_based_renewal' => true,
          'app_pool_identity' => true,
          'ca_config' => 'contoso-SUBCA\\CA',
          'domain_pass' => 'PASSWORD',
          'domain_user' => 'USER',
          'renewal_only' => true,
          'service_password' => 'SVC_PASSWORD',
          'service_user' => 'SVC_USER'
        )
      end

      describe 'steps into certificate_services_enrollment_web_service[username]' do
        it_behaves_like 'IIS should be installed/configured'

        it 'should install Windows features' do
          %w(ADCS-Enroll-Web-Svc).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should configure ADCS Enrollment Web Service' do
          expect(chef_run).to run_ruby_block('Configure ADCS Enrollment Web Service')
        end
      end
    end

    describe 'when the feature is already installed/configured' do
      cached(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_enrollment_web_service, :ruby_block]) do |node|
          node.automatic['domain'] = 'contoso.com'
          node.normal['certificate_services']['enrollment_web_service']['username']['allow_key_based_renewal'] = true
          node.normal['certificate_services']['enrollment_web_service']['username']['app_pool_identity'] = true
          node.normal['certificate_services']['enrollment_web_service']['username']['ca_config'] = 'contoso-SUBCA\\CA'
          node.normal['certificate_services']['enrollment_web_service']['username']['domain_pass'] = 'PASSWORD'
          node.normal['certificate_services']['enrollment_web_service']['username']['domain_user'] = 'USER'
          node.normal['certificate_services']['enrollment_web_service']['username']['renewal_only'] = true
          node.normal['certificate_services']['enrollment_web_service']['username']['service_password'] = 'SVC_PASSWORD'
          node.normal['certificate_services']['enrollment_web_service']['username']['service_user'] = 'SVC_USER'
        end.converge(described_recipe)
      end

      before(:each) do
        allow_any_instance_of(Chef::Resource).to receive(:iis_vdir_installed?).with(anything).and_return(true)

        stub_command('(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq "Allow"').and_return(true)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_services_enrollment_web_service[username] resource' do
        expect(chef_run).to install_certificate_services_enrollment_web_service('username').with(
          'allow_key_based_renewal' => true,
          'app_pool_identity' => true,
          'ca_config' => 'contoso-SUBCA\\CA',
          'domain_pass' => 'PASSWORD',
          'domain_user' => 'USER',
          'renewal_only' => true,
          'service_password' => 'SVC_PASSWORD',
          'service_user' => 'SVC_USER'
        )
      end

      describe 'steps into certificate_services_enrollment_web_service[username]' do
        it_behaves_like 'IIS is already installed/configured'

        it 'should install Windows features' do
          %w(ADCS-Enroll-Web-Svc).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should not configure ADCS Enrollment Web Service' do
          expect(chef_run).to_not run_ruby_block('Configure ADCS Enrollment Web Service')
        end
      end
    end
  end

  describe 'when both CES types are specified' do
    cached(:chef_run) do
      ChefSpec::SoloRunner.new do |node|
        node.automatic['domain'] = 'contoso.com'
        node.normal['certificate_services']['enrollment_web_service']['kerberos']['ca_config'] = 'contoso-SUBCA\\CA'
        node.normal['certificate_services']['enrollment_web_service']['kerberos']['domain_pass'] = 'PASSWORD'
        node.normal['certificate_services']['enrollment_web_service']['kerberos']['domain_user'] = 'USER'
        node.normal['certificate_services']['enrollment_web_service']['username']['ca_config'] = 'contoso-SUBCA\\CA'
        node.normal['certificate_services']['enrollment_web_service']['username']['domain_pass'] = 'PASSWORD'
        node.normal['certificate_services']['enrollment_web_service']['username']['domain_user'] = 'USER'
      end.converge(described_recipe)
    end

    it 'should converge successfully' do
      expect { chef_run }.to_not raise_error
    end

    it 'should create a certificate_services_enrollment_web_service[kerberos] resource' do
      expect(chef_run).to install_certificate_services_enrollment_web_service('kerberos').with(
        'ca_config' => 'contoso-SUBCA\\CA',
        'domain_pass' => 'PASSWORD',
        'domain_user' => 'USER'
      )
    end

    it 'should create a certificate_services_enrollment_web_service[username] resource' do
      expect(chef_run).to install_certificate_services_enrollment_web_service('username').with(
        'ca_config' => 'contoso-SUBCA\\CA',
        'domain_pass' => 'PASSWORD',
        'domain_user' => 'USER'
      )
    end
  end
end
