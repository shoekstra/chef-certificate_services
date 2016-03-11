require 'spec_helper'
require 'infrataster/rspec'

Infrataster::Server.define(:localhost, '127.0.0.1')

describe 'A Web Server' do
  describe 'acting as a CDP' do
    describe 'has IIS installed' do
      [
        'Web-Mgmt-Tools',
        'Web-WebServer'
      ].each do |feature|
        describe windows_feature(feature) do
          it { should be_installed.by('powershell') }
        end
      end

      describe service('WMSvc') do
        it { should be_installed }
        it { should be_running }
      end

      describe iis_app_pool('DefaultAppPool') do
        it { should exist }
      end

      describe iis_website('Default Web Site') do
        it { should exist }
        it { should be_enabled }
        it { should be_running }
        it { should be_in_app_pool('DefaultAppPool') }
      end

      describe 'with virtual directory configured for CDP' do
        describe iis_website('Default Website') do
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

      describe 'with virtual directory configured for CPS' do
        describe iis_website('Default Website') do
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

  describe 'acting as a CEP endpoint' do
  end

  describe 'acting as a CEWS endpoint' do
  end

  describe 'acting as an OCSP endpoint' do
  end
end
