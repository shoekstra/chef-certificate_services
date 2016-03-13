require 'spec_helper'
require 'infrataster/rspec'

Infrataster::Server.define(:localhost, '127.0.0.1')

describe 'A Web Server' do
  describe 'acting as a CRL Distribution Point' do
    describe 'has IIS installed' do
      %w(Web-Mgmt-Tools Web-WebServer).each do |feature_name|
        describe windows_feature(feature_name) do
          it { should be_installed.by('powershell') }
        end
      end

      %w(W3SVC WMSvc).each do |service_name|
        describe service(service_name) do
          it { should be_installed }
          it { should be_running }
        end
      end

      describe windows_registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WebManagement\Server') do
        it { should have_property_value('EnableRemoteManagement', :type_string, '1') }
      end
    end

    describe 'has a /cdp virtual directory in the Default Web Site website' do
      describe iis_website('Default Web Site') do
        it { should exist }
        it { should be_enabled }
        it { should be_running }
        it { should be_in_app_pool('DefaultAppPool') }
      end

      describe 'with virtual directory configured for CDP' do
        describe iis_website('Default Web Site') do
          it{ should have_virtual_dir('cdp').with_path('C:\\inetpub\\cdp') }
        end

        describe command('icacls C:\\inetpub\\cdp') do
          [
            /CONTOSO\\Cert Publishers:.*(M)/,
            /IIS APPPOOL\\DefaultAppPool:.*(RX)/
          ].each do |line|
            its(:stdout) { should contain(line) }
          end
        end
      end
    end

    describe 'has a /cps virtual directory in the Default Web Site website' do
      describe 'with virtual directory configured for CPS' do
        describe iis_website('Default Web Site') do
          it{ should have_virtual_dir('cps').with_path('C:\\inetpub\\cps') }
        end

        describe server(:localhost) do
          describe http('http://localhost/cps/legal.txt') do
            it "responds content equals 'Legal Policy Statement'" do
              expect(response.body).to eq('Legal Policy Statement')
            end
          end
        end
      end
    end
  end

  describe 'acting as a Certificate Enrollment Policy Web Server' do
  end

  describe 'acting as a Certificate Enrollment Web Server' do
  end

  describe 'acting as a Certification Authority Web Enrollment Server' do
  end

  describe 'acting as a Network Device Enrollment Server' do
  end

  describe 'acting as an Online Responder' do
  end
end
