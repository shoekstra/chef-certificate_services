require 'spec_helper'

describe 'A Standalone Root CA' do
  describe 'should have the CA role installed and configured' do
    %w(ADCS-Cert-Authority RSAT-ADCS-Mgmt).each do |feature|
      describe windows_feature(feature) do
        it { should be_installed.by('powershell') }
      end
    end

    describe service('CertSvc') do
      it { should be_installed }
      it { should be_running }
    end

    describe command('certutil -getconfig') do
      its(:stdout) { should match "CertUtil: -getconfig command completed successfully.\n" }
    end

    describe command('certutil -ping') do
      its(:stdout) { should match "CertUtil: -ping command completed successfully.\n" }
    end

    describe windows_registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\ROOTCA-CA') do
      it { should have_property_value('AuditFilter',         :type_string, '127') }
      it { should have_property_value('CRLDeltaPeriod',      :type_string, 'Days') }
      it { should have_property_value('CRLDeltaPeriodUnits', :type_string, '0') }
      it { should have_property_value('CRLOverlapPeriod',    :type_string, 'Hours') }
      it { should have_property_value('CRLOverlapUnits',     :type_string, '12') }
      it { should have_property_value('CRLPeriod',           :type_string, 'Weeks') }
      it { should have_property_value('CRLPeriodUnits',      :type_string, '26') }
      it { should have_property_value('DSConfigDN',          :type_string, 'CN=Configuration,DC=CONTOSO,DC=COM') }
      it { should have_property_value('DSDomainDN',          :type_string, 'DC=CONTOSO,DC=COM') }
      it { should have_property_value('ValidityPeriod',      :type_string, 'Years') }
      it { should have_property_value('ValidityPeriodUnits', :type_string, '10') }
    end
  end

  describe 'should have the root CRL and CRT should be in C:\CAConfig' do
    describe file('C:\\CAConfig') do
      it { should be_directory }
    end

    %w(C:\CAConfig\ROOTCA-CA.crl C:\CAConfig\ROOTCA_ROOTCA-CA.crt).each do |file|
      describe file(file) do
        it { should exist }
      end
    end
  end

  describe 'should have AIA and CDP configured as expected' do
    describe command('(Get-CAAuthorityInformationAccess).uri') do
      its(:stdout) { should eq '' }
    end

    describe command('(Get-CACrlDistributionPoint).uri') do
      its(:stdout) do
        should eq [
          'C:\Windows\System32\CertSrv\CertEnroll\<CAName><CRLNameSuffix>.crl',
          'C:\CAConfig\<CAName><CRLNameSuffix>.crl',
          'http://pki.contoso.com/cdp/<CAName><CRLNameSuffix>.crl',
          ''
        ].join("\n")
      end
    end
  end
end
