#
# Cookbook Name:: certificate_services
# Spec:: enterprise_subordinate_ca
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

require 'spec_helper'

describe 'certificate_services::enterprise_subordinate_ca' do
  let(:code_configure_aia) do
    [
      'Get-CAAuthorityInformationAccess | %{ Remove-CAAuthorityInformationAccess $_.uri -Force }'
    ].join('; ')
  end

  let(:code_configure_cdp) do
    [
      'Get-CACrlDistributionPoint | %{ Remove-CACrlDistributionPoint $_.uri -Force }',
      'Add-CACrlDistributionPoint -Uri C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%8%9.crl -PublishToServer -PublishDeltaToServer -Force',
      'Add-CACrlDistributionPoint -Uri C:\\CAConfig\\%3%8%9.crl -PublishToServer -PublishDeltaToServer -Force'
    ].join('; ')
  end

  let(:command_install_adcs) do
    command = [
      'Install-AdcsCertificationAuthority',
      '-Force',
      '-CAType EnterpriseSubordinateCA',
      "-CryptoProviderName '#{attributes[:crypto_provider]}'",
      "-DatabaseDirectory '#{attributes[:database_directory]}'",
      "-HashAlgorithmName #{attributes[:hash_algorithm]}",
      "-KeyLength #{attributes[:key_length]}",
      "-LogDirectory '#{attributes[:log_directory]}'"
    ]
    command << "-CACommonName '#{attributes[:common_name]}'" if attributes[:common_name]
    command << '-OverwriteExistingCAinDS' if attributes[:overwrite_existing_ca_in_ds]
    command << '-OverwriteExistingDatabase' if attributes[:overwrite_existing_database]
    command << '-OverwriteExistingKey' if attributes[:overwrite_existing_key]
    command.join(' ')
  end

  let(:content_capolicy) do <<-EOF.gsub(/^ {6}/, '')
      [Version]
      Signature="$Windows NT$"

      [Certsrv_Server]
      RenewalKeyLength=4096
      RenewalValidityPeriod=Years
      RenewalValidityPeriodUnits=5
      CRLPeriod=Weeks
      CRLPeriodUnits=2
      CRLDeltaPeriod=Days
      CRLDeltaPeriodUnits=1
      ClockSkewMinutes=10
      LoadDefaultTemplates=0
      AlternateSignatureAlgorithm=1
      ForceUTF8=0
      EnableKeyCounting=0
    EOF
  end

  let(:default_attributes) do
    {
      aia_url: nil,
      # allow_administrator_interaction: false,
      alternate_signature_algorithm: true,
      caconfig_dir: 'C:\CAConfig',
      cdp_url: nil,
      clock_skew_minutes: 10,
      # common_name: nil,
      crl_delta_period: 'days',
      crl_delta_period_units: 1,
      # crl_overlap_period: 'hours',
      # crl_overlap_units: 12,
      crl_period: 'weeks',
      crl_period_units: 2,
      crypto_provider: 'RSA#Microsoft Software Key Storage Provider',
      database_directory: 'C:\Windows\system32\CertLog',
      # domain_pass: nil,
      # domain_user: nil,
      enable_auditing_eventlogs: true,
      enable_key_counting: false,
      # enforce_x500_name_lengths:,
      force_utf8: false,
      hash_algorithm: 'SHA256',
      install_cert_file: 'SUBCA.contoso.com_CONTOSO-SUBCA-CA.crt',
      key_length: 4096,
      load_default_templates: false,
      # log_level:,
      log_directory: 'C:\Windows\system32\CertLog',
      ocsp_url: nil,
      # output_cert_request_file: nil,
      overwrite_existing_ca_in_ds: false,
      overwrite_existing_database: false,
      overwrite_existing_key: false,
      policy: nil,
      renewal_key_length: 4096,
      renewal_validity_period: 'years',
      renewal_validity_period_units: 5,
      root_crl_file: nil,
      root_crt_file: nil,
      validity_period: 'years',
      validity_period_units: 2
    }
  end

  let(:powershell_flags) { '-NoLogo -NonInteractive -NoProfile -ExecutionPolicy Unrestricted -InputFormat None' }
  let(:shellout_options) { { environment: { 'LC_ALL' => 'en_US.UTF-8', 'LANGUAGE' => 'en_US.UTF-8', 'LANG' => 'en_US.UTF-8' } } }
  let(:shellout_options_runas) { { user: nil, password: nil, domain: 'CONTOSO', environment: { 'LC_ALL' => 'en_US.UTF-8', 'LANGUAGE' => 'en_US.UTF-8', 'LANG' => 'en_US.UTF-8' } } }

  describe 'when all attributes are default' do
    let(:attributes) { default_attributes }

    let(:chef_run) do
      ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
        node.automatic['domain'] = 'CONTOSO'
        node.automatic['fqdn'] = 'SUBCA.contoso.com'
        node.automatic['hostname'] = 'SUBCA'
      end.converge(described_recipe)
    end

    describe 'and the Certificate Authority is not installed and is not configured' do
      it_behaves_like 'EnterpriseSubordinateCA is not installed and is not configured'
    end

    describe 'and the Certificate Authority is installed and is not configured' do
      it_behaves_like 'EnterpriseSubordinateCA is installed and is not configured'
    end

    describe 'and the Certificate Authority is installed and is configured' do
      it_behaves_like 'EnterpriseSubordinateCA is installed and is configured'
    end
  end

  describe 'when "aia_url" attribute is set to "http://pki.contoso.com/cdp/%3%4.crt"' do
    let(:attributes) do
      default_attributes.merge(aia_url: 'http://pki.contoso.com/cdp/%3%4.crt')
    end

    let(:code_configure_aia) do
      [
        'Get-CAAuthorityInformationAccess | %{ Remove-CAAuthorityInformationAccess $_.uri -Force }',
        'Add-CAAuthorityInformationAccess -Uri http://pki.contoso.com/cdp/%3%4.crt -AddToCertificateAia -Force'
      ].join('; ')
    end

    let(:chef_run) do
      ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
        node.automatic['domain'] = 'CONTOSO'
        node.automatic['fqdn'] = 'SUBCA.contoso.com'
        node.automatic['hostname'] = 'SUBCA'
        node.set['certificate_services']['enterprise_subordinate_ca']['aia_url'] = 'http://pki.contoso.com/cdp/%3%4.crt'
      end.converge(described_recipe)
    end

    describe 'and the Certificate Authority is not installed and is not configured' do
      it_behaves_like 'EnterpriseSubordinateCA is not installed and is not configured'
    end

    describe 'and the Certificate Authority is installed and is not configured' do
      it_behaves_like 'EnterpriseSubordinateCA is installed and is not configured'
    end

    describe 'and the Certificate Authority is installed and is configured' do
      it_behaves_like 'EnterpriseSubordinateCA is installed and is configured'
    end
  end

  describe 'when "cdp_url" attribute is set to "http://pki.contoso.com/cdp/%3%8%9.crl"' do
    let(:attributes) do
      default_attributes.merge(cdp_url: 'http://pki.contoso.com/cdp/%3%8%9.crl')
    end

    let(:code_configure_cdp) do
      [
        'Get-CACrlDistributionPoint | %{ Remove-CACrlDistributionPoint $_.uri -Force }',
        'Add-CACrlDistributionPoint -Uri C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%8%9.crl -PublishToServer -PublishDeltaToServer -Force',
        'Add-CACrlDistributionPoint -Uri C:\\CAConfig\\%3%8%9.crl -PublishToServer -PublishDeltaToServer -Force',
        'Add-CACrlDistributionPoint -Uri http://pki.contoso.com/cdp/%3%8%9.crl -AddToCertificateCDP -AddToFreshestCrl -Force'
      ].join('; ')
    end

    let(:chef_run) do
      ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
        node.automatic['domain'] = 'CONTOSO'
        node.automatic['fqdn'] = 'SUBCA.contoso.com'
        node.automatic['hostname'] = 'SUBCA'
        node.set['certificate_services']['enterprise_subordinate_ca']['cdp_url'] = 'http://pki.contoso.com/cdp/%3%8%9.crl'
      end.converge(described_recipe)
    end

    describe 'and the Certificate Authority is not installed and is not configured' do
      it_behaves_like 'EnterpriseSubordinateCA is not installed and is not configured'
    end

    describe 'and the Certificate Authority is installed and is not configured' do
      it_behaves_like 'EnterpriseSubordinateCA is installed and is not configured'
    end

    describe 'and the Certificate Authority is installed and is configured' do
      it_behaves_like 'EnterpriseSubordinateCA is installed and is configured'
    end
  end

  describe 'when "common_name" attribute is set to "ENTERPRISE_ISSUINGCA"' do
    let(:attributes) do
      default_attributes.merge(common_name: 'ENTERPRISE_ISSUINGCA')
    end

    let(:chef_run) do
      ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
        node.automatic['domain'] = 'CONTOSO'
        node.automatic['fqdn'] = 'SUBCA.contoso.com'
        node.automatic['hostname'] = 'SUBCA'
        node.set['certificate_services']['enterprise_subordinate_ca']['common_name'] = 'ENTERPRISE_ISSUINGCA'
      end.converge(described_recipe)
    end

    describe 'and the Certificate Authority is not installed and is not configured' do
      it_behaves_like 'EnterpriseSubordinateCA is not installed and is not configured'
    end

    describe 'and the Certificate Authority is installed and is not configured' do
      it_behaves_like 'EnterpriseSubordinateCA is installed and is not configured'
    end

    describe 'and the Certificate Authority is installed and is configured' do
      it_behaves_like 'EnterpriseSubordinateCA is installed and is configured'
    end
  end

  describe 'when "database_directory" and "log_directory" attributes are set to "C:\Test"' do
    let(:attributes) do
      default_attributes.merge(
         database_directory: 'C:\Test',
         log_directory: 'C:\Test'
      )
    end

    let(:chef_run) do
      ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
        node.automatic['domain'] = 'CONTOSO'
        node.automatic['fqdn'] = 'SUBCA.contoso.com'
        node.automatic['hostname'] = 'SUBCA'
        node.set['certificate_services']['enterprise_subordinate_ca']['database_directory'] = 'C:\Test'
        node.set['certificate_services']['enterprise_subordinate_ca']['log_directory'] = 'C:\Test'
      end.converge(described_recipe)
    end

    describe 'and the Certificate Authority is not installed and is not configured' do
      it_behaves_like 'EnterpriseSubordinateCA is not installed and is not configured'
    end

    describe 'and the Certificate Authority is installed and is not configured' do
      it_behaves_like 'EnterpriseSubordinateCA is installed and is not configured'
    end

    describe 'and the Certificate Authority is installed and is configured' do
      it_behaves_like 'EnterpriseSubordinateCA is installed and is configured'
    end
  end

  describe 'when "ocsp_url" attribute is set to "http://pki.contoso.com/ocsp"' do
    let(:attributes) do
      default_attributes.merge(ocsp_url: 'http://pki.contoso.com/ocsp')
    end

    let(:code_configure_aia) do
      [
        'Get-CAAuthorityInformationAccess | %{ Remove-CAAuthorityInformationAccess $_.uri -Force }',
        'Add-CAAuthorityInformationAccess -Uri http://pki.contoso.com/ocsp -AddToCertificateOcsp -Force'
      ].join('; ')
    end

    let(:chef_run) do
      ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
        node.automatic['domain'] = 'CONTOSO'
        node.automatic['fqdn'] = 'SUBCA.contoso.com'
        node.automatic['hostname'] = 'SUBCA'
        node.set['certificate_services']['enterprise_subordinate_ca']['ocsp_url'] = 'http://pki.contoso.com/ocsp'
      end.converge(described_recipe)
    end

    describe 'and the Certificate Authority is not installed and is not configured' do
      it_behaves_like 'EnterpriseSubordinateCA is not installed and is not configured'
    end

    describe 'and the Certificate Authority is installed and is not configured' do
      it_behaves_like 'EnterpriseSubordinateCA is installed and is not configured'
    end

    describe 'and the Certificate Authority is installed and is configured' do
      it_behaves_like 'EnterpriseSubordinateCA is installed and is configured'
    end
  end

  describe 'when "overwrite" attributes are set to "true"' do
    let(:attributes) do
      default_attributes.merge(
        overwrite_existing_ca_in_ds: true,
        overwrite_existing_database: true,
        overwrite_existing_key: true
      )
    end

    let(:chef_run) do
      ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
        node.automatic['domain'] = 'CONTOSO'
        node.automatic['fqdn'] = 'SUBCA.contoso.com'
        node.automatic['hostname'] = 'SUBCA'
        node.set['certificate_services']['enterprise_subordinate_ca']['overwrite_existing_ca_in_ds'] = true
        node.set['certificate_services']['enterprise_subordinate_ca']['overwrite_existing_database'] = true
        node.set['certificate_services']['enterprise_subordinate_ca']['overwrite_existing_key'] = true
      end.converge(described_recipe)
    end

    describe 'and the Certificate Authority is not installed and is not configured' do
      it_behaves_like 'EnterpriseSubordinateCA is not installed and is not configured'
    end

    describe 'and the Certificate Authority is installed and is not configured' do
      it_behaves_like 'EnterpriseSubordinateCA is installed and is not configured'
    end

    describe 'and the Certificate Authority is installed and is configured' do
      it_behaves_like 'EnterpriseSubordinateCA is installed and is configured'
    end
  end

  describe 'when "policy" attribute contains a single policy' do
    let(:attributes) do
      default_attributes.merge(
        policy: {
          'LegalPolicy' => {
            'notice' => 'Legal Policy Statement',
            'oid'    => '1.2.3.4.1455.67.89.5',
            'url'    => 'http://pki/pki/legal.txt'
          }
        }
      )
    end

    let(:content_capolicy) do <<-EOF.gsub(/^ {8}/, '')
        [Version]
        Signature="$Windows NT$"

        [PolicyStatementExtension]
        Policies=LegalPolicy

        [LegalPolicy]
        OID=1.2.3.4.1455.67.89.5
        Notice="Legal Policy Statement"
        URL=http://pki/pki/legal.txt

        [Certsrv_Server]
        RenewalKeyLength=4096
        RenewalValidityPeriod=Years
        RenewalValidityPeriodUnits=5
        CRLPeriod=Weeks
        CRLPeriodUnits=2
        CRLDeltaPeriod=Days
        CRLDeltaPeriodUnits=1
        ClockSkewMinutes=10
        LoadDefaultTemplates=0
        AlternateSignatureAlgorithm=1
        ForceUTF8=0
        EnableKeyCounting=0
      EOF
    end

    let(:chef_run) do
      ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
        node.automatic['domain'] = 'CONTOSO'
        node.automatic['fqdn'] = 'SUBCA.contoso.com'
        node.automatic['hostname'] = 'SUBCA'
        node.set['certificate_services']['enterprise_subordinate_ca']['policy']['LegalPolicy']['notice'] = 'Legal Policy Statement'
        node.set['certificate_services']['enterprise_subordinate_ca']['policy']['LegalPolicy']['oid'] = '1.2.3.4.1455.67.89.5'
        node.set['certificate_services']['enterprise_subordinate_ca']['policy']['LegalPolicy']['url'] = 'http://pki/pki/legal.txt'
      end.converge(described_recipe)
    end

    describe 'and the Certificate Authority is not installed and is not configured' do
      it_behaves_like 'EnterpriseSubordinateCA is not installed and is not configured'
    end

    describe 'and the Certificate Authority is installed and is not configured' do
      it_behaves_like 'EnterpriseSubordinateCA is installed and is not configured'
    end

    describe 'and the Certificate Authority is installed and is configured' do
      it_behaves_like 'EnterpriseSubordinateCA is installed and is configured'
    end
  end

  describe 'when "policy" attribute contains multiple policies' do
    let(:attributes) do
      default_attributes.merge(
        policy: {
          'InternalPolicy' => {
            'notice' => 'Internal Policy Statement',
            'oid'    => '1.2.3.4.1455.67.89.5',
            'url'    => 'http://pki/pki/internal.txt'
          },
          'LegalPolicy' => {
            'notice' => 'Legal Policy Statement',
            'oid'    => '1.2.3.4.1455.67.89.5',
            'url'    => 'http://pki/pki/legal.txt'
          }
        }
      )
    end

    let(:content_capolicy) do <<-EOF.gsub(/^ {8}/, '')
        [Version]
        Signature="$Windows NT$"

        [PolicyStatementExtension]
        Policies=InternalPolicy,LegalPolicy

        [InternalPolicy]
        OID=1.2.3.4.1455.67.89.5
        Notice="Internal Policy Statement"
        URL=http://pki/pki/internal.txt

        [LegalPolicy]
        OID=1.2.3.4.1455.67.89.5
        Notice="Legal Policy Statement"
        URL=http://pki/pki/legal.txt

        [Certsrv_Server]
        RenewalKeyLength=4096
        RenewalValidityPeriod=Years
        RenewalValidityPeriodUnits=5
        CRLPeriod=Weeks
        CRLPeriodUnits=2
        CRLDeltaPeriod=Days
        CRLDeltaPeriodUnits=1
        ClockSkewMinutes=10
        LoadDefaultTemplates=0
        AlternateSignatureAlgorithm=1
        ForceUTF8=0
        EnableKeyCounting=0
      EOF
    end

    let(:chef_run) do
      ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
        node.automatic['domain'] = 'CONTOSO'
        node.automatic['fqdn'] = 'SUBCA.contoso.com'
        node.automatic['hostname'] = 'SUBCA'
        node.set['certificate_services']['enterprise_subordinate_ca']['policy']['InternalPolicy']['notice'] = 'Internal Policy Statement'
        node.set['certificate_services']['enterprise_subordinate_ca']['policy']['InternalPolicy']['oid'] = '1.2.3.4.1455.67.89.5'
        node.set['certificate_services']['enterprise_subordinate_ca']['policy']['InternalPolicy']['url'] = 'http://pki/pki/internal.txt'
        node.set['certificate_services']['enterprise_subordinate_ca']['policy']['LegalPolicy']['notice'] = 'Legal Policy Statement'
        node.set['certificate_services']['enterprise_subordinate_ca']['policy']['LegalPolicy']['oid'] = '1.2.3.4.1455.67.89.5'
        node.set['certificate_services']['enterprise_subordinate_ca']['policy']['LegalPolicy']['url'] = 'http://pki/pki/legal.txt'
      end.converge(described_recipe)
    end

    describe 'and the Certificate Authority is not installed and is not configured' do
      it_behaves_like 'EnterpriseSubordinateCA is not installed and is not configured'
    end

    describe 'and the Certificate Authority is installed and is not configured' do
      it_behaves_like 'EnterpriseSubordinateCA is installed and is not configured'
    end

    describe 'and the Certificate Authority is installed and is configured' do
      it_behaves_like 'EnterpriseSubordinateCA is installed and is configured'
    end
  end
end
