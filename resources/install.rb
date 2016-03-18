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

property :allow_administrator_interaction, kind_of: [TrueClass, FalseClass], required: false, default: false
property :alternate_signature_algorithm,   kind_of: [TrueClass, FalseClass], required: true, default: false
property :caconfig_dir,                    kind_of: String,                  required: true, default: 'C:\CAConfig'
property :clock_skew_minutes,              kind_of: [Fixnum, String],        required: false
property :common_name,                     kind_of: String,                  required: false
property :crl_delta_period,                kind_of: String,                  required: false, regex: /^(Hours|Days|Weeks|Months|Years)$/i
property :crl_delta_period_units,          kind_of: [Fixnum, String],        required: false
property :crl_overlap_period,              kind_of: String,                  required: false, regex: /^(Hours|Days|Weeks|Months|Years)$/i
property :crl_overlap_units,               kind_of: [Fixnum, String],        required: false
property :crl_period,                      kind_of: String,                  required: false, regex: /^(Hours|Days|Weeks|Months|Years)$/i
property :crl_period_units,                kind_of: [Fixnum, String],        required: false
property :crypto_provider,                 kind_of: String,                  required: true, default: 'RSA#Microsoft Software Key Storage Provider'
property :database_path,                   kind_of: String,                  required: true, default: 'C:\Windows\system32\CertLog'
property :domain,                          kind_of: String,                  required: false, default: node['domain']
property :domain_pass,                     kind_of: String,                  required: false
property :domain_user,                     kind_of: String,                  required: false
property :enable_auditing_eventlogs,       kind_of: [TrueClass, FalseClass], required: true, default: true
property :enable_key_counting,             kind_of: [TrueClass, FalseClass], required: true, default: false
property :force_utf8,                      kind_of: [TrueClass, FalseClass], required: true, default: false
property :hash_algorithm,                  kind_of: String,                  required: true, default: 'SHA256'
property :install_cert_file,               kind_of: String,                  required: false
property :key_length,                      kind_of: [Fixnum, String],        required: true, default: 4096
property :load_default_templates,          kind_of: [TrueClass, FalseClass], required: true, default: false
property :log_path,                        kind_of: String,                  required: true, default: 'C:\Windows\system32\CertLog'
property :output_cert_request_file,        kind_of: String,                  required: false
property :overwrite_existing_ca_in_ds,     kind_of: [TrueClass, FalseClass], required: false, default: false
property :overwrite_existing_database,     kind_of: [TrueClass, FalseClass], required: false, default: false
property :overwrite_existing_key,          kind_of: [TrueClass, FalseClass], required: false, default: false
property :policy,                          kind_of: [Array, Hash, NilClass], required: false, default: nil
property :renewal_key_length,              kind_of: [Fixnum, String],        required: true
property :renewal_validity_period,         kind_of: String,                  required: true, regex: /^(Hours|Days|Weeks|Months|Years)$/i
property :renewal_validity_period_units,   kind_of: [Fixnum, String],        required: true
property :root_crl_file,                   kind_of: String,                  required: false
property :root_crt_file,                   kind_of: String,                  required: false
property :validity_period,                 kind_of: String,                  required: false, regex: /^(Hours|Days|Weeks|Months|Years)$/i
property :validity_period_units,           kind_of: [Fixnum, String],        required: false
property :windows_domain,                  kind_of: String,                  required: false

action :create do
  #
  # Create CAPolicy.inf template
  #
  policy = new_resource.policy
  policy = [policy] if policy.is_a?(Hash)

  policy_name = []
  policy.each { |p| p.each { |i| policy_name << i.first } } unless policy.nil?

  template 'C:/Windows/CAPolicy.inf' do
    source 'CAPolicy.inf.erb'
    variables(
      alternate_signature_algorithm: new_resource.alternate_signature_algorithm,
      clock_skew_minutes: new_resource.clock_skew_minutes,
      crl_delta_period: new_resource.crl_delta_period,
      crl_delta_period_units: new_resource.crl_delta_period_units,
      crl_period: new_resource.crl_period,
      crl_period_units: new_resource.crl_period_units,
      enable_key_counting: new_resource.enable_key_counting,
      force_utf8: new_resource.force_utf8,
      load_default_templates: new_resource.load_default_templates,
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
  directory new_resource.caconfig_dir

  windows_feature 'ADCS-Cert-Authority' do
    action :install
    provider :windows_feature_powershell
  end

  if new_resource.type == 'StandaloneRootCA'
    #
    # Cookbook Name:: sbp_certificate_services
    # Recipe:: standalone_root_ca
    #
    # Copyright (C) 2015 Schuberg Philis
    #
    # Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
    #

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
    ruby_block 'Install ADCS Certification Authority' do
      block do
        config_ca_cmd = [
          'Install-AdcsCertificationAuthority -Force -OverwriteExistingKey',
          "-CAType #{new_resource.type}",
          "-CryptoProviderName '#{new_resource.crypto_provider}'",
          "-HashAlgorithmName #{new_resource.hash_algorithm}",
          "-KeyLength #{new_resource.key_length}",
          "-ValidityPeriod #{new_resource.validity_period}",
          "-ValidityPeriodUnits #{new_resource.validity_period_units}"
        ]
        config_ca_cmd << "-CACommonName '#{new_resource.common_name}'" if new_resource.common_name

        powershell_out!(config_ca_cmd.join(' '))
      end
      not_if { ca_installed? }
      action :run
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
    # registry_key "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\#{common_name}" do
    #   values registry_values
    #   action :create
    #   notifies :restart, 'windows_service[CertSvc]', :immediately
    # end

    #
    # Start the Active Directory Certificate Services service
    #
    windows_service 'CertSvc' do
      action [:enable, :start]
    end

    #
    # Generate a CRL for distribution
    #
    powershell_script 'Generate new CRL' do
      code 'certutil -CRL'
      action :nothing
      subscribes :run, 'windows_service[CertSvc]'
    end

    #
    # Copy the root CA certificate and CRL to the PKI directory for easy access
    #

    # batch 'Copy certificate and CRLs to the PKI directory' do
    #   architecture :x86_64
    #   code "robocopy \"C:\\Windows\\System32\\CertSrv\\CertEnroll\" \"#{new_resource.caconfig_dir}\" /MIR /NDL /NJS /NJH"
    #   returns [0, 1]
    #   action :run
    # end
  else
    #
    # Cookbook Name:: sbp_certificate_services
    # Recipe:: enterprise_subordinate_ca
    #
    # Copyright (C) 2015 Schuberg Philis
    #
    # Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
    #

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
    powershell_out_options = {
      user: new_resource.domain_user,
      password: new_resource.domain_pass,
      domain: node['domain']
    }

    ruby_block 'Install ADCS Certification Authority' do
      block do
        config_ca_cmd = [
          'Install-AdcsCertificationAuthority -Force -OverwriteExistingKey',
          "-CAType #{new_resource.type}",
          "-CryptoProviderName '#{new_resource.crypto_provider}'",
          "-HashAlgorithmName #{new_resource.hash_algorithm}",
          "-KeyLength #{new_resource.key_length}"
        ]
        config_ca_cmd << "-CACommonName '#{new_resource.common_name}'" if new_resource.common_name

        powershell_out!(config_ca_cmd.join(' '), powershell_out_options)
      end
      not_if { ca_installed? }
      action :run
    end

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
        block { shell_out!("certutil –addstore –f root #{win_friendly_root_file}") }
        only_if { ::File.exist?(win_friendly_root_file) }
        notifies :delete, "file[#{win_friendly_root_file}]"
      end
    end

    #
    # Install subordinate certificate
    #
    win_friendly_install_cert_file = win_friendly_path(::File.join(new_resource.caconfig_dir, new_resource.install_cert_file)) if new_resource.install_cert_file
    if new_resource.install_cert_file && ::File.exist?(win_friendly_install_cert_file)
      file win_friendly_install_cert_file do
        action :nothing
      end

      ruby_block "Install #{win_friendly_install_cert_file} certificate" do
        block { shell_out!("certutil -installCert #{win_friendly_install_cert_file}", powershell_out_options) }
        not_if { ca_configured? }
        notifies :restart, 'windows_service[CertSvc]', :immediately
        notifies :delete, "file[#{win_friendly_install_cert_file}]"
      end
    end

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

    #
    # Start the Active Directory Certificate Services service
    #
    windows_service 'CertSvc' do
      action ca_configured? ? [:enable, :start] : :nothing
    end

    #
    # Generate a new CRL each time the service is restarted
    #
    powershell_script 'Generate new CRL' do
      code 'certutil -CRL'
      action :nothing
      subscribes :run, 'windows_service[CertSvc]'
    end

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
