#
# Cookbook Name:: certificate_services
# Spec:: standalone_root_ca
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

require 'digest'
require 'spec_helper'

describe 'certificate_services::standalone_root_ca' do
  let(:code_configure_aia) do
    [
      'Get-CAAuthorityInformationAccess | %{ Remove-CAAuthorityInformationAccess $_.uri -Force }'
    ].join('; ')
  end

  let(:code_configure_cdp) do
    [
      'Get-CACrlDistributionPoint | %{ Remove-CACrlDistributionPoint $_.uri -Force }',
      'Add-CACrlDistributionPoint -Uri C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%8.crl -PublishToServer -Force',
      'Add-CACrlDistributionPoint -Uri C:\\CAConfig\\%3%8.crl -PublishToServer -Force'
    ].join('; ')
  end

  let(:content_capolicy) do <<-EOF.gsub(/^ {6}/, '')
      [Version]
      Signature="$Windows NT$"

      [Certsrv_Server]
      RenewalKeyLength=4096
      RenewalValidityPeriod=Years
      RenewalValidityPeriodUnits=20
      CRLPeriod=Weeks
      CRLPeriodUnits=26
      CRLDeltaPeriod=Days
      CRLDeltaPeriodUnits=0
      ClockSkewMinutes=10
      LoadDefaultTemplates=0
      AlternateSignatureAlgorithm=1
      ForceUTF8=0
      EnableKeyCounting=0
    EOF
  end

  let(:default_attributes) do
    {
      # aia_url: nil,
      allow_administrator_interaction: false,
      alternate_signature_algorithm: true,
      caconfig_dir: 'C:\CAConfig',
      # cdp_url: nil,
      clock_skew_minutes: 10,
      common_name: nil,
      # crl_delta_overlap_period:,
      # crl_delta_overlap_units:,
      crl_delta_period: 'days',
      crl_delta_period_units: 0,
      crl_overlap_period: 'hours',
      crl_overlap_units: 12,
      crl_period: 'weeks',
      crl_period_units: 26,
      crypto_provider: 'RSA#Microsoft Software Key Storage Provider',
      database_path: 'C:\Windows\system32\CertLog',
      domain_pass: nil,
      domain_user: nil,
      enable_auditing_eventlogs: true,
      enable_key_counting: false,
      # enforce_x500_name_lengths:,
      force_utf8: false,
      hash_algorithm: 'SHA256',
      key_length: 4096,
      load_default_templates: false,
      # log_level:,
      log_path: 'C:\Windows\system32\CertLog',
      # ocsp_url: nil,
      output_cert_request_file: nil,
      overwrite_existing_ca_in_ds: false,
      overwrite_existing_database: false,
      overwrite_existing_key: false,
      policy: nil,
      renewal_key_length: 4096,
      renewal_validity_period: 'years',
      renewal_validity_period_units: 20,
      validity_period: 'years',
      validity_period_units: 10,
      windows_domain: nil,
    }
  end

  let(:powershell_flags) { '-NoLogo -NonInteractive -NoProfile -ExecutionPolicy Unrestricted -InputFormat None' }
  let(:shellout_options) { { environment: { 'LC_ALL' => 'en_US.UTF-8', 'LANGUAGE' => 'en_US.UTF-8', 'LANG' => 'en_US.UTF-8' } } }

  describe 'when all attributes are default' do
    let(:attributes) { default_attributes }

    describe 'and the Certificate Authority is not installed and is not configured' do
      let(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
          node.automatic['hostname'] = 'ROOTCA'
        end.converge(described_recipe)
      end

      it_behaves_like 'StandaloneRootCA not installed and not configured'
    end

    describe 'and the Certificate Authority is installed and is configured' do
      let(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
          node.automatic['hostname'] = 'ROOTCA'
        end.converge(described_recipe)
      end

      it_behaves_like 'StandaloneRootCA installed and configured'
    end
  end

  describe 'when "cdp_url" attribute is set to "http://pki.contoso.com/cdp/%3%8.crl"' do
    let(:attributes) do
      # default_attributes.merge(cdp_url: 'http://pki.contoso.com/cdp/%3%8.crl')
      default_attributes
    end

    let(:code_configure_cdp) do
      [
        'Get-CACrlDistributionPoint | %{ Remove-CACrlDistributionPoint $_.uri -Force }',
        'Add-CACrlDistributionPoint -Uri C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%8.crl -PublishToServer -Force',
        'Add-CACrlDistributionPoint -Uri C:\\CAConfig\\%3%8.crl -PublishToServer -Force',
        'Add-CACrlDistributionPoint -Uri http://pki.contoso.com/cdp/%3%8.crl -AddToCertificateCDP -Force'
      ].join('; ')
    end

    describe 'and the Certificate Authority is not installed and is not configured' do
      let(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
          node.automatic['hostname'] = 'ROOTCA'
          node.set['certificate_services']['standalone_root_ca']['cdp_url'] = 'http://pki.contoso.com/cdp/%3%8.crl'
        end.converge(described_recipe)
      end

      it_behaves_like 'StandaloneRootCA not installed and not configured'
    end

    describe 'and the Certificate Authority is installed and is configured' do
      let(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
          node.automatic['hostname'] = 'ROOTCA'
          node.set['certificate_services']['standalone_root_ca']['cdp_url'] = 'http://pki.contoso.com/cdp/%3%8.crl'
        end.converge(described_recipe)
      end

      it_behaves_like 'StandaloneRootCA installed and configured'
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

    let!(:content_capolicy) do <<-EOF.gsub(/^ {8}/, '')
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
        RenewalValidityPeriodUnits=20
        CRLPeriod=Weeks
        CRLPeriodUnits=26
        CRLDeltaPeriod=Days
        CRLDeltaPeriodUnits=0
        ClockSkewMinutes=10
        LoadDefaultTemplates=0
        AlternateSignatureAlgorithm=1
        ForceUTF8=0
        EnableKeyCounting=0
      EOF
    end

    describe 'and the Certificate Authority is not installed and is not configured' do
      let(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
          node.automatic['hostname'] = 'ROOTCA'
          node.set['certificate_services']['standalone_root_ca']['policy']['LegalPolicy']['notice'] = 'Legal Policy Statement'
          node.set['certificate_services']['standalone_root_ca']['policy']['LegalPolicy']['oid'] = '1.2.3.4.1455.67.89.5'
          node.set['certificate_services']['standalone_root_ca']['policy']['LegalPolicy']['url'] = 'http://pki/pki/legal.txt'
        end.converge(described_recipe)
      end

      it_behaves_like 'StandaloneRootCA not installed and not configured'
    end

    describe 'and the Certificate Authority is installed and is configured' do
      let(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
          node.automatic['hostname'] = 'ROOTCA'
          node.set['certificate_services']['standalone_root_ca']['policy']['LegalPolicy']['notice'] = 'Legal Policy Statement'
          node.set['certificate_services']['standalone_root_ca']['policy']['LegalPolicy']['oid'] = '1.2.3.4.1455.67.89.5'
          node.set['certificate_services']['standalone_root_ca']['policy']['LegalPolicy']['url'] = 'http://pki/pki/legal.txt'
        end.converge(described_recipe)
      end

      it_behaves_like 'StandaloneRootCA installed and configured'
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

    let!(:content_capolicy) do <<-EOF.gsub(/^ {8}/, '')
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
        RenewalValidityPeriodUnits=20
        CRLPeriod=Weeks
        CRLPeriodUnits=26
        CRLDeltaPeriod=Days
        CRLDeltaPeriodUnits=0
        ClockSkewMinutes=10
        LoadDefaultTemplates=0
        AlternateSignatureAlgorithm=1
        ForceUTF8=0
        EnableKeyCounting=0
      EOF
    end

    describe 'and the Certificate Authority is not installed and is not configured' do
      let(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
          node.automatic['hostname'] = 'ROOTCA'
          node.set['certificate_services']['standalone_root_ca']['policy']['InternalPolicy']['notice'] = 'Internal Policy Statement'
          node.set['certificate_services']['standalone_root_ca']['policy']['InternalPolicy']['oid'] = '1.2.3.4.1455.67.89.5'
          node.set['certificate_services']['standalone_root_ca']['policy']['InternalPolicy']['url'] = 'http://pki/pki/internal.txt'
          node.set['certificate_services']['standalone_root_ca']['policy']['LegalPolicy']['notice'] = 'Legal Policy Statement'
          node.set['certificate_services']['standalone_root_ca']['policy']['LegalPolicy']['oid'] = '1.2.3.4.1455.67.89.5'
          node.set['certificate_services']['standalone_root_ca']['policy']['LegalPolicy']['url'] = 'http://pki/pki/legal.txt'
        end.converge(described_recipe)
      end

      it_behaves_like 'StandaloneRootCA not installed and not configured'
    end

    describe 'and the Certificate Authority is installed and is configured' do
      let(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
          node.automatic['hostname'] = 'ROOTCA'
          node.set['certificate_services']['standalone_root_ca']['policy']['InternalPolicy']['notice'] = 'Internal Policy Statement'
          node.set['certificate_services']['standalone_root_ca']['policy']['InternalPolicy']['oid'] = '1.2.3.4.1455.67.89.5'
          node.set['certificate_services']['standalone_root_ca']['policy']['InternalPolicy']['url'] = 'http://pki/pki/internal.txt'
          node.set['certificate_services']['standalone_root_ca']['policy']['LegalPolicy']['notice'] = 'Legal Policy Statement'
          node.set['certificate_services']['standalone_root_ca']['policy']['LegalPolicy']['oid'] = '1.2.3.4.1455.67.89.5'
          node.set['certificate_services']['standalone_root_ca']['policy']['LegalPolicy']['url'] = 'http://pki/pki/legal.txt'
        end.converge(described_recipe)
      end

      it_behaves_like 'StandaloneRootCA installed and configured'
    end
  end

  describe 'when "windows_domain" attribute is set to "contoso.com"' do
    let(:attributes) { default_attributes.merge!(windows_domain: 'contoso.com') }

    describe 'and the Certificate Authority is not installed and is not configured' do
      let(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
          node.automatic['hostname'] = 'ROOTCA'
          node.set['certificate_services']['standalone_root_ca']['windows_domain'] = 'contoso.com'
        end.converge(described_recipe)
      end

      it_behaves_like 'StandaloneRootCA not installed and not configured'
    end

    describe 'and the Certificate Authority is installed and is configured' do
      let(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
          node.automatic['hostname'] = 'ROOTCA'
          node.set['certificate_services']['standalone_root_ca']['windows_domain'] = 'contoso.com'
        end.converge(described_recipe)
      end

      it_behaves_like 'StandaloneRootCA installed and configured'
    end
  end

  describe 'when "windows_domain" attribute is set to "contoso.com"' do
    let(:attributes) { default_attributes.merge(windows_domain: 'contoso.com') }

    describe 'and the Certificate Authority is not installed and is not configured' do
      let(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
          node.automatic['hostname'] = 'ROOTCA'
          node.set['certificate_services']['standalone_root_ca']['windows_domain'] = 'contoso.com'
        end.converge(described_recipe)
      end

      it_behaves_like 'StandaloneRootCA not installed and not configured'
    end

    describe 'and the Certificate Authority is installed and is configured' do
      let(:chef_run) do
        ChefSpec::SoloRunner.new(step_into: [:certificate_services_install, :ruby_block]) do |node|
          node.automatic['hostname'] = 'ROOTCA'
          node.set['certificate_services']['standalone_root_ca']['windows_domain'] = 'contoso.com'
        end.converge(described_recipe)
      end

      it_behaves_like 'StandaloneRootCA installed and configured'
    end
  end
end
