#
# Cookbook Name:: certificate_services
# Resource:: install
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

include CertificateServices::Helper
include Windows::Helper

actions :create, :delete, :install, :uninstall
default_action :create

# CA type to install/configure

property :type, kind_of: String, required: true, regex: /^(EnterpriseSubordinateCA|StandaloneRootCA)$/i, name_property: true

# CAPolicy.inf and Install-AdcsCertificationAuthority attributes

property :allow_administrator_interaction, kind_of: [TrueClass, FalseClass],   required: false, default: false
property :alternate_signature_algorithm,   kind_of: [TrueClass, FalseClass],   required: true, default: false
property :aia_url,                         kind_of: [Array, String, NilClass], required: false, default: nil
property :cdp_url,                         kind_of: [Array, String, NilClass], required: false, default: nil
property :caconfig_dir,                    kind_of: String,                    required: true, default: 'C:\CAConfig'
property :clock_skew_minutes,              kind_of: [Fixnum, String],          required: false
property :common_name,                     kind_of: String,                    required: false
property :crl_delta_period,                kind_of: String,                    required: false, regex: /^(Hours|Days|Weeks|Months|Years)$/i
property :crl_delta_period_units,          kind_of: [Fixnum, String],          required: false
property :crl_overlap_period,              kind_of: String,                    required: false, regex: /^(Hours|Days|Weeks|Months|Years)$/i
property :crl_overlap_units,               kind_of: [Fixnum, String],          required: false
property :crl_period,                      kind_of: String,                    required: false, regex: /^(Hours|Days|Weeks|Months|Years)$/i
property :crl_period_units,                kind_of: [Fixnum, String],          required: false
property :crypto_provider,                 kind_of: String,                    required: true, default: 'RSA#Microsoft Software Key Storage Provider'
property :database_directory,              kind_of: String,                    required: true, default: 'C:\Windows\system32\CertLog'
property :domain,                          kind_of: String,                    required: false, default: node['domain']
property :domain_pass,                     kind_of: String,                    required: false
property :domain_user,                     kind_of: String,                    required: false
property :enable_auditing_eventlogs,       kind_of: [TrueClass, FalseClass],   required: true, default: true
property :enable_key_counting,             kind_of: [TrueClass, FalseClass],   required: true, default: false
property :enhanced_key_usage,              kind_of: [Array, String],           required: false, default: nil
property :force_utf8,                      kind_of: [TrueClass, FalseClass],   required: true, default: false
property :hash_algorithm,                  kind_of: String,                    required: true, default: 'SHA256'
property :install_cert_file,               kind_of: String,                    required: false
property :key_length,                      kind_of: [Fixnum, String],          required: true, default: 4096
property :load_default_templates,          kind_of: [TrueClass, FalseClass],   required: true, default: false
property :log_directory,                   kind_of: String,                    required: true, default: 'C:\Windows\system32\CertLog'
property :ocsp_url,                        kind_of: [String, NilClass],        required: false, default: nil
property :overwrite_existing_ca_in_ds,     kind_of: [TrueClass, FalseClass],   required: false, default: false
property :overwrite_existing_database,     kind_of: [TrueClass, FalseClass],   required: false, default: false
property :overwrite_existing_key,          kind_of: [TrueClass, FalseClass],   required: false, default: false
property :policy,                          kind_of: [Array, Hash, NilClass],   required: false, default: nil
property :renewal_key_length,              kind_of: [Fixnum, String],          required: true
property :renewal_validity_period,         kind_of: String,                    required: true, regex: /^(Hours|Days|Weeks|Months|Years)$/i
property :renewal_validity_period_units,   kind_of: [Fixnum, String],          required: true
property :root_crl_file,                   kind_of: String,                    required: false
property :root_crt_file,                   kind_of: String,                    required: false
property :validity_period,                 kind_of: String,                    required: false, regex: /^(Hours|Days|Weeks|Months|Years)$/i
property :validity_period_units,           kind_of: [Fixnum, String],          required: false
property :windows_domain,                  kind_of: String,                    required: false

action_class do
  def bool_to_int(bool)
    bool == true ? 1 : 0
  end
end

action :create do
  #
  # Set powershell_out options for later
  #
  powershell_out_options = {}
  powershell_out_options = { user: new_resource.domain_user, password: new_resource.domain_pass, domain: node['domain'] } if new_resource.type == 'EnterpriseSubordinateCA'

  #
  # Create CAPolicy.inf template
  #
  enhanced_key_usage = new_resource.enhanced_key_usage
  enhanced_key_usage = Array(enhanced_key_usage) unless enhanced_key_usage.nil?

  policy = new_resource.policy
  policy = [policy] if policy.is_a?(Hash)

  policy_name = []
  policy.each { |p| p.each { |i| policy_name << i.first } } unless policy.nil?

  template 'C:/Windows/CAPolicy.inf' do
    source 'CAPolicy.inf.erb'
    variables(
      alternate_signature_algorithm: bool_to_int(new_resource.alternate_signature_algorithm),
      clock_skew_minutes: new_resource.clock_skew_minutes,
      crl_delta_period: new_resource.crl_delta_period,
      crl_delta_period_units: new_resource.crl_delta_period_units,
      crl_period: new_resource.crl_period,
      crl_period_units: new_resource.crl_period_units,
      enable_key_counting: bool_to_int(new_resource.enable_key_counting),
      enhanced_key_usage: enhanced_key_usage,
      force_utf8: bool_to_int(new_resource.force_utf8),
      load_default_templates: bool_to_int(new_resource.load_default_templates),
      policy: policy,
      policy_name: policy_name,
      renewal_key_length: new_resource.renewal_key_length,
      renewal_validity_period: new_resource.renewal_validity_period,
      renewal_validity_period_units: new_resource.renewal_validity_period_units
    )
  end

  #
  # Install AD CS windows feature
  #
  windows_feature 'ADCS-Cert-Authority' do
    action :install
    provider :windows_feature_powershell
  end

  #
  # Install AD CS RSAT windows feature
  #
  windows_feature 'RSAT-ADCS-Mgmt' do
    action :install
    provider :windows_feature_powershell
  end

  #
  # Configure the CA
  #
  directory new_resource.caconfig_dir

  config_ca_cmd = [
    'Install-AdcsCertificationAuthority -Force',
    "-CAType #{new_resource.type}",
    "-CryptoProviderName '#{new_resource.crypto_provider}'",
    "-DatabaseDirectory '#{new_resource.database_directory}'",
    "-HashAlgorithmName #{new_resource.hash_algorithm}",
    "-KeyLength #{new_resource.key_length}",
    "-LogDirectory '#{new_resource.log_directory}'"
  ]

  config_ca_cmd << "-CACommonName '#{new_resource.common_name}'" if new_resource.common_name
  config_ca_cmd << '-OverwriteExistingCAinDS' if new_resource.overwrite_existing_ca_in_ds
  config_ca_cmd << '-OverwriteExistingDatabase' if new_resource.overwrite_existing_database
  config_ca_cmd << '-OverwriteExistingKey' if new_resource.overwrite_existing_key
  config_ca_cmd << "-ValidityPeriod #{new_resource.renewal_validity_period}" if new_resource.type == 'StandaloneRootCA'
  config_ca_cmd << "-ValidityPeriodUnits #{new_resource.renewal_validity_period_units}" if new_resource.type == 'StandaloneRootCA'

  ruby_block 'Install ADCS Certification Authority' do
    block { powershell_out!(config_ca_cmd.join(' '), powershell_out_options) }
    not_if { ca_installed? }
    action :run
  end

  if new_resource.type == 'EnterpriseSubordinateCA'
    #
    # Import root certificate and revocation list to root store
    #
    root_files = []
    root_files << new_resource.root_crl_file if new_resource.root_crl_file
    root_files << new_resource.root_crt_file if new_resource.root_crt_file

    root_files.each do |root_file|
      win_friendly_root_file = win_friendly_path(::File.join(new_resource.caconfig_dir, root_file))

      file win_friendly_root_file do
        action :nothing
      end

      ruby_block "Install #{win_friendly_root_file}" do
        block { shell_out!("certutil –addstore –f root \"#{win_friendly_root_file}\"") }
        only_if { ::File.exist?(win_friendly_root_file) }
        notifies :delete, "file[#{win_friendly_root_file}]"
      end
    end

    #
    # Install subordinate certificate
    #
    if new_resource.install_cert_file && ::File.exist?(::File.join(new_resource.caconfig_dir, new_resource.install_cert_file))
      win_friendly_install_cert_file = win_friendly_path(::File.join(new_resource.caconfig_dir, new_resource.install_cert_file))

      file win_friendly_install_cert_file do
        action :nothing
      end

      ruby_block "Install #{win_friendly_install_cert_file} certificate" do
        block { shell_out!("certutil -installCert \"#{win_friendly_install_cert_file}\"", powershell_out_options) }
        not_if { ca_configured? }
        notifies :restart, 'windows_service[CertSvc]', :immediately
        notifies :delete, "file[#{win_friendly_install_cert_file}]"
      end
    end
  end

  #
  # Configure AIA and CDP locations
  #
  cdp_code = []
  cdp_code << 'Get-CACrlDistributionPoint | %{ Remove-CACrlDistributionPoint $_.uri -Force }'

  cdp_urls = new_resource.cdp_url
  cdp_urls = Array(cdp_url) unless cdp_urls.nil?

  if new_resource.type == 'StandaloneRootCA'
    cdp_code << 'Add-CACrlDistributionPoint -Uri C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%8.crl -PublishToServer -Force'
    cdp_code << "Add-CACrlDistributionPoint -Uri #{new_resource.caconfig_dir}\\%3%8.crl -PublishToServer -Force"
    cdp_urls.each do |cdp_url|
      cdp_code << "Add-CACrlDistributionPoint -Uri #{cdp_url} -AddToCertificateCDP -Force"
    end unless cdp_urls.nil?
  elsif new_resource.type == 'EnterpriseSubordinateCA'
    cdp_code << 'Add-CACrlDistributionPoint -Uri C:\\Windows\\System32\\CertSrv\CertEnroll\\%3%8%9.crl -PublishToServer -PublishDeltaToServer -Force'
    cdp_code << "Add-CACrlDistributionPoint -Uri #{new_resource.caconfig_dir}\\%3%8%9.crl -PublishToServer -PublishDeltaToServer -Force"

    cdp_urls.each do |cdp_url|
      cdp_code << "Add-CACrlDistributionPoint -Uri #{cdp_url} -AddToCertificateCDP -AddToFreshestCrl -Force"
    end unless cdp_urls.nil?
  end

  aia_urls = new_resource.aia_url
  aia_urls = Array(aia_url) unless aia_urls.nil?

  aia_code = []
  aia_code << 'Get-CAAuthorityInformationAccess | %{ Remove-CAAuthorityInformationAccess $_.uri -Force }'
  aia_urls.each do |aia_url|
    aia_code << "Add-CAAuthorityInformationAccess -Uri #{aia_url} -AddToCertificateAia -Force"
  end unless aia_urls.nil?
  aia_code << "Add-CAAuthorityInformationAccess -Uri #{new_resource.ocsp_url} -AddToCertificateOcsp -Force" unless new_resource.ocsp_url.nil?

  powershell_script 'Configure CDP' do
    code cdp_code.join('; ')
    action :run
    notifies :restart, 'windows_service[CertSvc]'
    only_if { ca_configured? }
  end

  powershell_script 'Configure AIA' do
    code aia_code.join('; ')
    action :run
    notifies :restart, 'windows_service[CertSvc]'
    only_if { ca_configured? }
  end

  #
  # Set certificate and certificate revocation list related registry values
  #
  registry_values = []
  registry_values << { name: 'AuditFilter',         type: :dword,  data: '127' } if new_resource.enable_auditing_eventlogs
  registry_values << { name: 'CRLDeltaPeriod',      type: :string, data: new_resource.crl_delta_period.downcase.capitalize } if new_resource.crl_delta_period
  registry_values << { name: 'CRLDeltaPeriodUnits', type: :dword,  data: new_resource.crl_delta_period_units } if new_resource.crl_delta_period_units
  registry_values << { name: 'CRLOverlapPeriod',    type: :string, data: new_resource.crl_overlap_period.downcase.capitalize } if new_resource.crl_overlap_period
  registry_values << { name: 'CRLOverlapUnits',     type: :dword,  data: new_resource.crl_overlap_units } if new_resource.crl_overlap_units
  registry_values << { name: 'CRLPeriod',           type: :string, data: new_resource.crl_period.downcase.capitalize } if new_resource.crl_period
  registry_values << { name: 'CRLPeriodUnits',      type: :dword,  data: new_resource.crl_period_units } if new_resource.crl_period_units
  registry_values << { name: 'DSConfigDN',          type: :string, data: "CN=Configuration,#{domain_dn(new_resource.windows_domain)}" } if new_resource.windows_domain
  registry_values << { name: 'DSDomainDN',          type: :string, data: domain_dn(new_resource.windows_domain) } if new_resource.windows_domain
  registry_values << { name: 'ValidityPeriod',      type: :string, data: new_resource.validity_period.downcase.capitalize } if new_resource.validity_period
  registry_values << { name: 'ValidityPeriodUnits', type: :dword,  data: new_resource.validity_period_units } if new_resource.validity_period_units

  unless ca_name.nil?
    registry_key "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\#{ca_name.split(/\\/)[1]}" do
      values registry_values
      action :create
      only_if { ca_configured? }
      notifies :restart, 'windows_service[CertSvc]', :immediately
    end
  end

  csp_registry_values = []
  csp_registry_values << { name: 'AlternateSignatureAlgorithm', type: :dword, data: bool_to_int(new_resource.alternate_signature_algorithm) }

  unless ca_name.nil?
    registry_key "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\#{ca_name.split(/\\/)[1]}\\CSP" do
      values csp_registry_values
      action :create
      only_if { ca_configured? }
      notifies :restart, 'windows_service[CertSvc]', :immediately
    end
  end

  #
  # Start the Active Directory Certificate Services service
  #
  windows_service 'CertSvc' do
    action new_resource.type == 'StandaloneRootCA' ? [:enable, :start] : ca_configured? ? [:enable, :start] : :nothing
  end

  #
  # Generate a new CRL each time the service is restarted
  #
  powershell_script 'Generate new CRL' do
    code 'certutil -CRL'
    action :nothing
    retries 3
    only_if { ca_configured? }
    subscribes :run, 'windows_service[CertSvc]'
  end
end

action :delete do
  #
  # Delete CAPolicy.inf template
  #
  file 'C:/Windows/CAPolicy.inf' do
    action :delete
  end
end
