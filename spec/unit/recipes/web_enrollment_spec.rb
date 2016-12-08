#
# Cookbook Name:: certificate_services
# Spec:: web_enrollment
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

require 'spec_helper'

require_relative '_iis_spec.rb'

describe 'certificate_services::web_enrollment' do
  describe 'when the feature is not yet installed/configured' do
    context 'when all attributes are default' do
      cached(:chef_run) do
        ChefSpec::SoloRunner.new.converge(described_recipe)
      end

      it 'should raise ArgumentError' do
        expect { chef_run }.to raise_error(ArgumentError)
      end
    end

    context 'when "domain_user" and "domain_pass" attributes are specified' do
      before(:each) do
        ENV.stub(:[])
        ENV.stub(:[]).with('SystemRoot').and_return("C:\\")

        allow_any_instance_of(Chef::DSL::RegistryHelper).to receive(:registry_get_values).with('HKLM\SOFTWARE\Microsoft\WebManagement\Server').and_return(false)
        allow_any_instance_of(Chef::Resource).to receive(:certsrv_vdir_installed?).and_return(false)

        @file = Object.new
        allow(Chef::Util::FileEdit).to receive(:new).and_return(@file)
        allow(@file).to receive(:search_file_replace_line).and_return(true)
        allow(@file).to receive(:write_file).and_return(true)

        powershell_flags = '-NoLogo -NonInteractive -NoProfile -ExecutionPolicy Unrestricted -InputFormat None'
        shellout_options_runas = { user: 'USER', password: 'PASSWORD', domain: 'CONTOSO', environment: { 'LC_ALL' => 'en_US.UTF-8', 'LANGUAGE' => 'en_US.UTF-8', 'LANG' => 'en_US.UTF-8' } }

        stub_command("(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq \"Allow\"").and_return(false)
        stub_command("(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/basicAuthentication -PSPath \"IIS:\\Sites\\Default Web Site\\CertSrv\" -Name Enabled).Value -eq \"True\"").and_return(false)
        stub_command("(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/basicAuthentication -PSPath \"IIS:\\Sites\\Default Web Site\\CertSrv\" -Name logonMethod) -eq \"ClearText\"").and_return(false)
        stub_command("(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/windowsAuthentication -PSPath \"IIS:\\Sites\\Default Web Site\\CertSrv\" -Name Enabled).Value -eq $False").and_return(false)

        shellout_adcs_web_enrollment = double(run_command: nil, error!: nil, stdout: '', stderr: double(empty?: true))
        Mixlib::ShellOut.stub(:new).with(
          "powershell.exe #{powershell_flags} -Command \"Install-AdcsWebEnrollment -CAConfig 'contoso-SUBCA\\CA' -Force\"",
          shellout_options_runas).and_return(shellout_adcs_web_enrollment)
        allow(shellout_adcs_web_enrollment).to receive(:live_stream).and_return(nil)
        allow(shellout_adcs_web_enrollment).to receive(:live_stream=).and_return(nil)
      end

      cached(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_web_enrollment, :ruby_block]) do |node|
          node.automatic['domain'] = 'CONTOSO'
          node.normal['certificate_services']['web_enrollment']['ca_config'] = 'contoso-SUBCA\\CA'
          node.normal['certificate_services']['web_enrollment']['domain_user'] = 'USER'
          node.normal['certificate_services']['web_enrollment']['domain_pass'] = 'PASSWORD'
        end.converge(described_recipe)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_services_web_enrollment[contoso-SUBCA\CA] resource' do
        expect(chef_run).to install_certificate_services_web_enrollment('contoso-SUBCA\CA')
      end

      describe 'steps into certificate_services_web_enrollment' do
        it_behaves_like 'IIS should be installed/configured'

        it 'should install Windows features' do
          %w(ADCS-Web-Enrollment).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should configure ADCS Web Enrollment' do
          expect(chef_run).to run_ruby_block('Configure ADCS Web Enrollment')
        end

        it 'should configure CertSrv overrides' do
          expect(chef_run).to run_ruby_block('Allow CertSrv overrides')
        end

        it 'should set basic authentication enabled to "true" for "IIS:\Sites\Default Web Site\CertSrv"' do
          expect(chef_run).to run_powershell_script('Set basic authentication enabled = true for "IIS:\Sites\Default Web Site\CertSrv"')
          expect(chef_run.powershell_script('Set basic authentication enabled = true for "IIS:\Sites\Default Web Site\CertSrv"')).to notify('windows_service[W3SVC]').to(:restart).delayed
        end

        it 'should set basic authentication logonMethod to "ClearText" for "IIS:\Sites\Default Web Site\CertSrv"' do
          expect(chef_run).to run_powershell_script('Set basic authentication logonMethod = ClearText for "IIS:\Sites\Default Web Site\CertSrv"')
          expect(chef_run.powershell_script('Set basic authentication logonMethod = ClearText for "IIS:\Sites\Default Web Site\CertSrv"')).to notify('windows_service[W3SVC]').to(:restart).delayed
        end

        it ' should set windows authentication enabled to "false" for "IIS:\Sites\Default Web Site\CertSrv"' do
          expect(chef_run).to run_powershell_script('Set windows authentication enabled = false for "IIS:\Sites\Default Web Site\CertSrv"')
          expect(chef_run.powershell_script('Set windows authentication enabled = false for "IIS:\Sites\Default Web Site\CertSrv"')).to notify('windows_service[W3SVC]').to(:restart).delayed
        end
      end
    end
  end

  describe 'when the feature is already installed/configured' do
    context 'when all attributes are default' do
      cached(:chef_run) do
        ChefSpec::SoloRunner.new.converge(described_recipe)
      end

      it 'should raise ArgumentError' do
        expect { chef_run }.to raise_error(ArgumentError)
      end
    end

    context 'when "domain_user" and "domain_pass" attributes are specified' do
      before(:each) do
        ENV.stub(:[])
        ENV.stub(:[]).with('SystemRoot').and_return("C:\\")

        @file = Object.new
        allow(Chef::Util::FileEdit).to receive(:new).and_return(@file)
        allow(@file).to receive(:search_file_replace_line).and_return(true)
        allow(@file).to receive(:write_file).and_return(true)

        allow_any_instance_of(Chef::DSL::RegistryHelper).to receive(:registry_get_values).with('HKLM\SOFTWARE\Microsoft\WebManagement\Server').and_return(true)
        allow_any_instance_of(Chef::Resource).to receive(:certsrv_vdir_installed?).and_return(true)

        stub_command("(Get-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost).OverrideMode -eq \"Allow\"").and_return(true)
        stub_command("(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/basicAuthentication -PSPath \"IIS:\\Sites\\Default Web Site\\CertSrv\" -Name Enabled).Value -eq \"True\"").and_return(true)
        stub_command("(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/basicAuthentication -PSPath \"IIS:\\Sites\\Default Web Site\\CertSrv\" -Name logonMethod) -eq \"ClearText\"").and_return(true)
        stub_command("(Get-WebConfigurationProperty -Filter /system.WebServer/security/authentication/windowsAuthentication -PSPath \"IIS:\\Sites\\Default Web Site\\CertSrv\" -Name Enabled).Value -eq $False").and_return(true)

        powershell_flags = '-NoLogo -NonInteractive -NoProfile -ExecutionPolicy Unrestricted -InputFormat None'
        shellout_options_runas = { user: 'USER', password: 'PASSWORD', domain: 'CONTOSO', environment: { 'LC_ALL' => 'en_US.UTF-8', 'LANGUAGE' => 'en_US.UTF-8', 'LANG' => 'en_US.UTF-8' } }

        shellout_adcs_web_enrollment = double(run_command: nil, error!: nil, stdout: '', stderr: double(empty?: true))
        Mixlib::ShellOut.stub(:new).with(
          "powershell.exe #{powershell_flags} -Command \"Install-AdcsWebEnrollment -CAConfig 'contoso-SUBCA\\CA' -Force\"",
          shellout_options_runas).and_return(shellout_adcs_web_enrollment)
        allow(shellout_adcs_web_enrollment).to receive(:live_stream).and_return(nil)
        allow(shellout_adcs_web_enrollment).to receive(:live_stream=).and_return(nil)
      end

      cached(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_web_enrollment, :ruby_block]) do |node|
          node.automatic['domain'] = 'CONTOSO'
          node.normal['certificate_services']['web_enrollment']['ca_config'] = 'contoso-SUBCA\\CA'
          node.normal['certificate_services']['web_enrollment']['domain_user'] = 'USER'
          node.normal['certificate_services']['web_enrollment']['domain_pass'] = 'PASSWORD'
        end.converge(described_recipe)
      end

      it 'should converge successfully' do
        expect { chef_run }.to_not raise_error
      end

      it 'should create a certificate_services_web_enrollment[contoso-SUBCA\CA] resource' do
        expect(chef_run).to install_certificate_services_web_enrollment('contoso-SUBCA\CA')
      end

      describe 'steps into certificate_services_web_enrollment' do
        it_behaves_like 'IIS is already installed/configured'

        it 'should install Windows features' do
          %w(ADCS-Web-Enrollment).each do |feature_name|
            expect(chef_run).to install_windows_feature(feature_name)
          end
        end

        it 'should not configure ADCS Web Enrollment' do
          expect(chef_run).to_not run_ruby_block('Configure ADCS Web Enrollment')
        end

        it 'should configure CertSrv overrides' do
          expect(chef_run).to run_ruby_block('Allow CertSrv overrides')
        end

        it 'should not set basic authentication enabled to "true" for "IIS:\Sites\Default Web Site\CertSrv"' do
          expect(chef_run).to_not run_powershell_script('Set basic authentication enabled = true for "IIS:\Sites\Default Web Site\CertSrv"')
        end

        it 'should not set basic authentication logonMethod to "ClearText" for "IIS:\Sites\Default Web Site\CertSrv"' do
          expect(chef_run).to_not run_powershell_script('Set basic authentication logonMethod = ClearText for "IIS:\Sites\Default Web Site\CertSrv"')
        end

        it ' should not set windows authentication enabled to "false" for "IIS:\Sites\Default Web Site\CertSrv"' do
          expect(chef_run).to_not run_powershell_script('Set windows authentication enabled = false for "IIS:\Sites\Default Web Site\CertSrv"')
        end
      end
    end
  end
end
