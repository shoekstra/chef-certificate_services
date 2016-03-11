require 'spec_helper'

describe 'An Enterprise Subordinate CA server' do
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

    describe windows_registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\SUBCA-CA') do
      it { should have_property_value('AuditFilter',         :type_string, '127') }
      # it { should have_property_value('CRLDeltaPeriod',      :type_string, 'Days') }
      # it { should have_property_value('CRLDeltaPeriodUnits', :type_string, '0') }
      # it { should have_property_value('CRLOverlapPeriod',    :type_string, 'Hours') }
      # it { should have_property_value('CRLOverlapUnits',     :type_string, '12') }
      # it { should have_property_value('CRLPeriod',           :type_string, 'Weeks') }
      # it { should have_property_value('CRLPeriodUnits',      :type_string, '26') }
      # it { should have_property_value('DSConfigDN',          :type_string, 'CN=Configuration,DC=CONTOSO,DC=COM') }
      # it { should have_property_value('DSDomainDN',          :type_string, 'DC=CONTOSO,DC=COM') }
      # it { should have_property_value('ValidityPeriod',      :type_string, 'Years') }
      # it { should have_property_value('ValidityPeriodUnits', :type_string, '20') }
    end
  end

  describe file('C:\CAConfig') do
    it { should be_directory }
  end

  describe 'should have AIA and CDP configured as expected' do
    describe command('(Get-CAAuthorityInformationAccess).uri') do
      its(:stdout) do
        should eq [
          "http://pki.contoso.com/cdp/<CAName><CertificateName>.crt\n",
          "http://pki.contoso.com/ocsp\n",
          ''
        ].join("\n")
      end
    end

    describe command('(Get-CACrlDistributionPoint).uri') do
      its(:stdout) do
        should eq [
          'C:\Windows\System32\CertSrv\CertEnroll\<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl',
          'C:\CAConfig\<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl',
          'http://pki.contoso.com/cdp/<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl',
          ''
        ].join("\n")
      end
    end
  end
end
