require 'chefspec'
require 'chefspec/berkshelf'

RSpec.configure do |config|
  config.extend(ChefSpec::Cacher)

  config.platform = 'windows'       # Set OS type
  config.version = '2012R2'         # Set OS version

  config.color = true               # Use color in STDOUT
  config.formatter = :documentation # Use the specified formatter
  config.log_level = :error         # Avoid deprecation notice SPAM
end

shared_examples_for 'EnterpriseSubordinateCA is not installed and is not configured' do
  let(:registry_key_values_ca) do
    arr = []
    arr << { name: 'CRLDeltaPeriod',      type: :string, data: attributes[:crl_delta_period].downcase.capitalize }
    arr << { name: 'CRLDeltaPeriodUnits', type: :dword,  data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:crl_delta_period_units].to_s)) }
    arr << { name: 'CRLOverlapPeriod',    type: :string, data: attributes[:crl_overlap_period].downcase.capitalize }
    arr << { name: 'CRLOverlapUnits',     type: :dword,  data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:crl_overlap_units].to_s)) }
    arr << { name: 'CRLPeriod',           type: :string, data: attributes[:crl_period].downcase.capitalize }
    arr << { name: 'CRLPeriodUnits',      type: :dword,  data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:crl_period_units].to_s)) }
    arr << { name: 'DSConfigDN',          type: :string, data: 'CN=Configuration,DC=contoso,DC=com' } unless attributes[:windows_domain].nil?
    arr << { name: 'DSDomainDN',          type: :string, data: 'DC=contoso,DC=com' } unless attributes[:windows_domain].nil?
    arr << { name: 'ValidityPeriod',      type: :string, data: attributes[:validity_period].downcase.capitalize }
    arr << { name: 'ValidityPeriodUnits', type: :dword,  data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:validity_period_units].to_s)) }

    arr
  end

  let(:template_vars_capolicy) do
    template_var_enhanced_key_usage = attributes[:enhanced_key_usage]
    template_var_enhanced_key_usage = Array(template_var_enhanced_key_usage) unless template_var_enhanced_key_usage.nil?

    {
      alternate_signature_algorithm: attributes[:alternate_signature_algorithm] == true ? 1 : 0,
      clock_skew_minutes: attributes[:clock_skew_minutes],
      crl_delta_period: attributes[:crl_delta_period],
      crl_delta_period_units: attributes[:crl_delta_period_units],
      crl_period: attributes[:crl_period],
      crl_period_units: attributes[:crl_period_units],
      enable_key_counting: attributes[:enable_key_counting] == true ? 1 : 0,
      enhanced_key_usage: template_var_enhanced_key_usage,
      force_utf8: attributes[:force_utf8] == true ? 1 : 0,
      load_default_templates: attributes[:load_default_templates] == true ? 1 : 0,
      renewal_key_length: attributes[:renewal_key_length],
      renewal_validity_period: attributes[:renewal_validity_period],
      renewal_validity_period_units: attributes[:renewal_validity_period_units],
      policy: attributes[:policy],
    }
  end

  before do
    allow_any_instance_of(Chef::DSL::RegistryHelper).to receive(:registry_get_values).with('HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\SUBCA-Issuing-CA').and_return(
      [
        { name: 'CRLPublicationURLs', type: :multi_string, data: [] },
        { name: 'CACertPublicationURLs', type: :multi_string, data: [] },
      ]
    )

    shellout_certutil_getconfig = double(run_command: nil, error!: nil, stdout: "CertUtil: No local Certification Authority; use -config option\nCertUtil: No more data is available.\n", stderr: double(empty?: true))
    Mixlib::ShellOut.stub(:new).with('certutil -getconfig', shellout_options).and_return(shellout_certutil_getconfig)
    allow(shellout_certutil_getconfig).to receive(:live_stream).and_return(nil)
    allow(shellout_certutil_getconfig).to receive(:live_stream=).and_return(nil)

    shellout_certutil_ping = double(run_command: nil, error!: nil, stdout: "Connecting to SUBCA.contoso.com\\contoso-SUBCA-Issuing-CA ... Server could not be reached: The RPC server is unavailable. 0x800706ba (WIN32: 1722 RPC_S_SERVER_UNAVAILABLE) -- (15ms)\n\nCertUtil: -ping command FAILED: 0x800706ba (WIN32: 1722 RPC_S_SERVER_UNAVAILABLE\nCertUtil: The RPC server is unavailable.\n", stderr: double(empty?: true))
    Mixlib::ShellOut.stub(:new).with('certutil -ping', shellout_options).and_return(shellout_certutil_ping)
    allow(shellout_certutil_ping).to receive(:live_stream).and_return(nil)
    allow(shellout_certutil_ping).to receive(:live_stream=).and_return(nil)

    shellout_install_adcs = double(run_command: nil, error!: nil, stdout: '', stderr: double(empty?: true))
    Mixlib::ShellOut.stub(:new).with("powershell.exe #{powershell_flags} -Command \"#{command_install_adcs}\"", shellout_options_runas).and_return(shellout_install_adcs)
    allow(shellout_install_adcs).to receive(:live_stream).and_return(nil)
    allow(shellout_install_adcs).to receive(:live_stream=).and_return(nil)

    stub_command('Get-SmbShare -Name PKI').and_return(false)
  end

  it 'should converge successfully' do
    expect { chef_run }.to_not raise_error
  end

  it 'should create a certificate_services_install[EnterpriseSubordinateCA] resource with expected parameters' do
    expect(chef_run).to create_certificate_services_install('EnterpriseSubordinateCA').with(attributes)
  end

  describe 'steps into certificate_services_install and' do
    it 'should create a CAPolicy.inf with expected content' do
      policy = [attributes[:policy]] unless attributes[:policy].nil?
      policy_name = []
      attributes[:policy].each { |p| policy_name << p.first } unless attributes[:policy].nil?

      expect(chef_run).to create_template('C:/Windows/CAPolicy.inf').with_variables(template_vars_capolicy.merge(policy: policy, policy_name: policy_name))
      expect(chef_run).to render_file('C:/Windows/CAPolicy.inf').with_content(content_capolicy)
    end

    it 'should create ca_config_dir' do
      expect(chef_run).to create_directory(attributes[:caconfig_dir])
    end

    it 'should create "CertificateServicesFunctions.ps1"' do
      expect(chef_run).to create_cookbook_file("#{attributes[:caconfig_dir]}\\CertificateServicesFunctions.ps1")
    end

    it 'should install Certificate Authority Windows features' do
      %w(ADCS-Cert-Authority RSAT-ADCS-Mgmt).each do |feature|
        expect(chef_run).to install_windows_feature(feature)
      end
    end

    it 'should install Certificate Authority' do
      expect(chef_run).to run_ruby_block('Install ADCS Certification Authority')
      # expect(Mixlib::ShellOut).to receive(:new).with("powershell.exe #{powershell_flags} -Command \"#{command_install_adcs}\"", shellout_options)
    end

    it 'should not configure AIA' do
      expect(chef_run).to_not run_powershell_script('Configure AIA').with_code(code_configure_aia)
    end

    it 'should not configure CDP' do
      expect(chef_run).to_not run_powershell_script('Configure CDP').with_code(code_configure_cdp)
    end

    it 'should not set registry keys in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\contoso-SUBCA-Issuing-CA' do
      expect(chef_run).to_not create_registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\contoso-SUBCA-Issuing-CA')
    end

    it 'should not set registry keys in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\contoso-SUBCA-Issuing-CA\CSP' do
      expect(chef_run).to_not create_registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\contoso-SUBCA-Issuing-CA\CSP')
    end

    it 'should not enable and not start the CertSvc service' do
      expect(chef_run.windows_service('CertSvc')).to do_nothing
    end

    it 'should generate a new CRL when the service is restarted' do
      expect(chef_run.powershell_script('Generate new CRL')).to do_nothing
      expect(chef_run.powershell_script('Generate new CRL')).to subscribe_to('windows_service[CertSvc]')
    end
  end
end

shared_examples_for 'EnterpriseSubordinateCA is installed and is not configured' do
  let(:registry_key_values_ca) do
    arr = []
    arr << { name: 'CRLDeltaPeriod',      type: :string, data: attributes[:crl_delta_period].downcase.capitalize }
    arr << { name: 'CRLDeltaPeriodUnits', type: :dword,  data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:crl_delta_period_units].to_s)) }
    arr << { name: 'CRLOverlapPeriod',    type: :string, data: attributes[:crl_overlap_period].downcase.capitalize }
    arr << { name: 'CRLOverlapUnits',     type: :dword,  data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:crl_overlap_units].to_s)) }
    arr << { name: 'CRLPeriod',           type: :string, data: attributes[:crl_period].downcase.capitalize }
    arr << { name: 'CRLPeriodUnits',      type: :dword,  data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:crl_period_units].to_s)) }
    arr << { name: 'DSConfigDN',          type: :string, data: 'CN=Configuration,DC=contoso,DC=com' } unless attributes[:windows_domain].nil?
    arr << { name: 'DSDomainDN',          type: :string, data: 'DC=contoso,DC=com' } unless attributes[:windows_domain].nil?
    arr << { name: 'ValidityPeriod',      type: :string, data: attributes[:validity_period].downcase.capitalize }
    arr << { name: 'ValidityPeriodUnits', type: :dword,  data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:validity_period_units].to_s)) }

    arr
  end

  let(:template_vars_capolicy) do
    template_var_enhanced_key_usage = attributes[:enhanced_key_usage]
    template_var_enhanced_key_usage = Array(template_var_enhanced_key_usage) unless template_var_enhanced_key_usage.nil?

    {
      alternate_signature_algorithm: attributes[:alternate_signature_algorithm] == true ? 1 : 0,
      clock_skew_minutes: attributes[:clock_skew_minutes],
      crl_delta_period: attributes[:crl_delta_period],
      crl_delta_period_units: attributes[:crl_delta_period_units],
      crl_period: attributes[:crl_period],
      crl_period_units: attributes[:crl_period_units],
      enable_key_counting: attributes[:enable_key_counting] == true ? 1 : 0,
      enhanced_key_usage: template_var_enhanced_key_usage,
      force_utf8: attributes[:force_utf8] == true ? 1 : 0,
      load_default_templates: attributes[:load_default_templates] == true ? 1 : 0,
      renewal_key_length: attributes[:renewal_key_length],
      renewal_validity_period: attributes[:renewal_validity_period],
      renewal_validity_period_units: attributes[:renewal_validity_period_units],
      policy: attributes[:policy],
    }
  end

  before do
    allow_any_instance_of(Chef::DSL::RegistryHelper).to receive(:registry_get_values).with('HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\SUBCA-Issuing-CA').and_return(
      [
        { name: 'CRLPublicationURLs', type: :multi_string, data: [] },
        { name: 'CACertPublicationURLs', type: :multi_string, data: [] },
      ]
    )

    shellout_certutil_getconfig = double(run_command: nil, error!: nil, stdout: "Config String: \"SUBCA.contoso.com\\contoso-SUBCA-Issuing-CA\"\nCertUtil: -getconfig command completed successfully.\n", stderr: double(empty?: true))
    Mixlib::ShellOut.stub(:new).with('certutil -getconfig', shellout_options).and_return(shellout_certutil_getconfig)
    allow(shellout_certutil_getconfig).to receive(:live_stream).and_return(nil)
    allow(shellout_certutil_getconfig).to receive(:live_stream=).and_return(nil)

    shellout_certutil_ping = double(run_command: nil, error!: nil, stdout: "Connecting to SUBCA.contoso.com\\contoso-SUBCA-Issuing-CA ... Server could not be reached: The RPC server is unavailable. 0x800706ba (WIN32: 1722 RPC_S_SERVER_UNAVAILABLE) -- (15ms)\n\nCertUtil: -ping command FAILED: 0x800706ba (WIN32: 1722 RPC_S_SERVER_UNAVAILABLE\nCertUtil: The RPC server is unavailable.\n", stderr: double(empty?: true))
    Mixlib::ShellOut.stub(:new).with('certutil -ping', shellout_options).and_return(shellout_certutil_ping)
    allow(shellout_certutil_ping).to receive(:live_stream).and_return(nil)
    allow(shellout_certutil_ping).to receive(:live_stream=).and_return(nil)

    shellout_install_adcs = double(run_command: nil, error!: nil, stdout: '', stderr: double(empty?: true))
    Mixlib::ShellOut.stub(:new).with("powershell.exe #{powershell_flags} -Command \"#{command_install_adcs}\"", shellout_options_runas).and_return(shellout_install_adcs)
    allow(shellout_install_adcs).to receive(:live_stream).and_return(nil)
    allow(shellout_install_adcs).to receive(:live_stream=).and_return(nil)

    stub_command('Get-SmbShare -Name PKI').and_return(true)
  end

  it 'should converge successfully' do
    expect { chef_run }.to_not raise_error
  end

  it 'should create a certificate_services_install[EnterpriseSubordinateCA] resource with expected parameters' do
    expect(chef_run).to create_certificate_services_install('EnterpriseSubordinateCA').with(attributes)
  end

  describe 'steps into certificate_services_install and' do
    it 'should create a CAPolicy.inf with expected content' do
      policy = [attributes[:policy]] unless attributes[:policy].nil?
      policy_name = []
      attributes[:policy].each { |p| policy_name << p.first } unless attributes[:policy].nil?

      expect(chef_run).to create_template('C:/Windows/CAPolicy.inf').with_variables(template_vars_capolicy.merge(policy: policy, policy_name: policy_name))
      expect(chef_run).to render_file('C:/Windows/CAPolicy.inf').with_content(content_capolicy)
    end

    it 'should create ca_config_dir' do
      expect(chef_run).to create_directory(attributes[:caconfig_dir])
    end

    it 'should create "CertificateServicesFunctions.ps1"' do
      expect(chef_run).to create_cookbook_file("#{attributes[:caconfig_dir]}\\CertificateServicesFunctions.ps1")
    end

    it 'should install Certificate Authority Windows features' do
      %w(ADCS-Cert-Authority RSAT-ADCS-Mgmt).each do |feature|
        expect(chef_run).to install_windows_feature(feature)
      end
    end

    it 'should not install Certificate Authority' do
      expect(chef_run).to_not run_ruby_block('Install ADCS Certification Authority')
      # expect(Mixlib::ShellOut).to receive(:new).with("powershell.exe #{powershell_flags} -Command \"#{command_install_adcs}\"", shellout_options)
    end

    it 'should not configure AIA' do
      expect(chef_run).to_not run_powershell_script('Configure AIA').with_code(code_configure_aia)
    end

    it 'should not configure CDP' do
      expect(chef_run).to_not run_powershell_script('Configure CDP').with_code(code_configure_cdp)
    end

    it 'should not set registry keys in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\contoso-SUBCA-Issuing-CA' do
      expect(chef_run).to_not create_registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\contoso-SUBCA-Issuing-CA')
    end

    it 'should not set registry keys in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\contoso-SUBCA-Issuing-CA\CSP' do
      expect(chef_run).to_not create_registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\contoso-SUBCA-Issuing-CA\CSP')
    end

    it 'should not enable and not start the CertSvc service' do
      expect(chef_run.windows_service('CertSvc')).to do_nothing
    end

    it 'should generate a new CRL when the service is restarted' do
      expect(chef_run.powershell_script('Generate new CRL')).to do_nothing
      expect(chef_run.powershell_script('Generate new CRL')).to subscribe_to('windows_service[CertSvc]')
    end
  end
end

shared_examples_for 'EnterpriseSubordinateCA is installed and is configured' do
  let(:registry_key_values_ca) do
    arr = []

    arr << { name: 'CRLDeltaPeriod',      type: :string, data: attributes[:crl_delta_period].downcase.capitalize }
    arr << { name: 'CRLDeltaPeriodUnits', type: :dword,  data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:crl_delta_period_units].to_s)) }
    arr << { name: 'CRLPeriod',           type: :string, data: attributes[:crl_period].downcase.capitalize }
    arr << { name: 'CRLPeriodUnits',      type: :dword,  data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:crl_period_units].to_s)) }
    arr << { name: 'ValidityPeriod',      type: :string, data: attributes[:validity_period].downcase.capitalize }
    arr << { name: 'ValidityPeriodUnits', type: :dword,  data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:validity_period_units].to_s)) }

    arr
  end

  let(:template_vars_capolicy) do
    template_var_enhanced_key_usage = attributes[:enhanced_key_usage]
    template_var_enhanced_key_usage = Array(template_var_enhanced_key_usage) unless template_var_enhanced_key_usage.nil?

    {
      alternate_signature_algorithm: attributes[:alternate_signature_algorithm] == true ? 1 : 0,
      clock_skew_minutes: attributes[:clock_skew_minutes],
      crl_delta_period: attributes[:crl_delta_period],
      crl_delta_period_units: attributes[:crl_delta_period_units],
      crl_period: attributes[:crl_period],
      crl_period_units: attributes[:crl_period_units],
      enable_key_counting: attributes[:enable_key_counting] == true ? 1 : 0,
      enhanced_key_usage: template_var_enhanced_key_usage,
      force_utf8: attributes[:force_utf8] == true ? 1 : 0,
      load_default_templates: attributes[:load_default_templates] == true ? 1 : 0,
      renewal_key_length: attributes[:renewal_key_length],
      renewal_validity_period: attributes[:renewal_validity_period],
      renewal_validity_period_units: attributes[:renewal_validity_period_units],
      policy: attributes[:policy],
    }
  end

  before do
    allow_any_instance_of(Chef::DSL::RegistryHelper).to receive(:registry_get_values).with('HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\SUBCA-Issuing-CA').and_return(
      [
        { name: 'CRLPublicationURLs', type: :multi_string, data: [] },
        { name: 'CACertPublicationURLs', type: :multi_string, data: [] },
      ]
    )

    shellout_certutil_getconfig = double(run_command: nil, error!: nil, stdout: "Config String: \"SUBCA.contoso.com\\contoso-SUBCA-Issuing-CA\"\nCertUtil: -getconfig command completed successfully.\n", stderr: double(empty?: true))
    Mixlib::ShellOut.stub(:new).with('certutil -getconfig', shellout_options).and_return(shellout_certutil_getconfig)
    allow(shellout_certutil_getconfig).to receive(:live_stream).and_return(nil)
    allow(shellout_certutil_getconfig).to receive(:live_stream=).and_return(nil)

    shellout_certutil_ping = double(run_command: nil, error!: nil, stdout: "Connecting to SUBCA.contoso.com\\contoso-SUBCA-Issuing-CA ...\nServer \"contoso-SUBCA-Issuing-CA\" ICertRequest2 interface is alive (0ms)\nCertUtil: -ping command completed successfully.\n", stderr: double(empty?: true))
    Mixlib::ShellOut.stub(:new).with('certutil -ping', shellout_options).and_return(shellout_certutil_ping)
    allow(shellout_certutil_ping).to receive(:live_stream).and_return(nil)
    allow(shellout_certutil_ping).to receive(:live_stream=).and_return(nil)

    shellout_install_adcs = double(run_command: nil, error!: nil, stdout: '', stderr: double(empty?: true))
    Mixlib::ShellOut.stub(:new).with("powershell.exe #{powershell_flags} -Command \"#{command_install_adcs}\"", shellout_options_runas).and_return(shellout_install_adcs)
    allow(shellout_install_adcs).to receive(:live_stream).and_return(nil)
    allow(shellout_install_adcs).to receive(:live_stream=).and_return(nil)

    stub_command('Get-SmbShare -Name PKI').and_return(true)
  end

  it 'should converge successfully' do
    expect { chef_run }.to_not raise_error
  end

  it 'should create a certificate_services_install[EnterpriseSubordinateCA] resource with expected parameters' do
    expect(chef_run).to create_certificate_services_install('EnterpriseSubordinateCA').with(attributes)
  end

  describe 'steps into certificate_services_install and' do
    it 'should create a CAPolicy.inf with expected content' do
      policy = [attributes[:policy]] unless attributes[:policy].nil?
      policy_name = []
      attributes[:policy].each { |p| policy_name << p.first } unless attributes[:policy].nil?

      expect(chef_run).to create_template('C:/Windows/CAPolicy.inf').with_variables(template_vars_capolicy.merge(policy: policy, policy_name: policy_name))
      expect(chef_run).to render_file('C:/Windows/CAPolicy.inf').with_content(content_capolicy)
    end

    it 'should create ca_config_dir' do
      expect(chef_run).to create_directory(attributes[:caconfig_dir])
    end

    it 'should create "CertificateServicesFunctions.ps1"' do
      expect(chef_run).to create_cookbook_file("#{attributes[:caconfig_dir]}\\CertificateServicesFunctions.ps1")
    end

    it 'should install Certificate Authority Windows features' do
      %w(ADCS-Cert-Authority RSAT-ADCS-Mgmt).each do |feature|
        expect(chef_run).to install_windows_feature(feature)
      end
    end

    it 'should not install Certificate Authority' do
      expect(chef_run).to_not run_ruby_block('Install ADCS Certification Authority')
      # expect(Mixlib::ShellOut).to receive(:new).with("powershell.exe #{powershell_flags} -Command \"#{command_install_adcs}\"", shellout_options)
    end

    describe 'should configure AIA if aia_url attribute is set' do
      it 'unless aia_url config is up to date' do
        if attributes[:aia_url]
          allow_any_instance_of(Chef::DSL::RegistryHelper).to receive(:registry_get_values).with('HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\SUBCA-Issuing-CA').and_return(
            [
              { name: 'CACertPublicationURLs', type: :multi_string, data: ['http://pki.contoso.com/cdp/%3%4.crt', 'http://pki2.contoso.com/cdp/%3%4.crt'] },
            ]
          )
        end

        expect(chef_run).to_not run_powershell_script('Configure AIA').with_code(code_configure_aia)
      end

      it 'if aia_url config is not up to date' do
        expect(chef_run).to run_powershell_script('Configure AIA').with_code(code_configure_aia) if attributes[:aia_url]
      end
    end

    describe 'should configure CDP if cdp_url attribute is set' do
      it 'unless cdp_url config is up to date' do
        if attributes[:cdp_url]
          allow_any_instance_of(Chef::DSL::RegistryHelper).to receive(:registry_get_values).with('HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\SUBCA-Issuing-CA').and_return(
            [
              { name: 'CRLPublicationURLs', type: :multi_string, data: ['65:C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%8%9.crl', '65:C:\\CAConfig\\%3%8%9.crl', 'http://pki.contoso.com/cdp/%3%8%9.crl', 'http://pki2.contoso.com/cdp/%3%8%9.crl'] },
            ]
          )
        end

        expect(chef_run).to_not run_powershell_script('Configure CDP').with_code(code_configure_cdp)
      end

      it 'if cdp_url config is not up to date' do
        expect(chef_run).to run_powershell_script('Configure CDP').with_code(code_configure_cdp) if attributes[:cdp_url]
      end
    end

    it 'should set registry keys in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\contoso-SUBCA-Issuing-CA' do
      expect(chef_run).to create_registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\contoso-SUBCA-Issuing-CA')
    end

    it 'should set registry keys in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\contoso-SUBCA-Issuing-CA\CSP' do
      expect(chef_run).to create_registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\contoso-SUBCA-Issuing-CA\CSP').with_values(
        [
          name: 'AlternateSignatureAlgorithm', type: :dword, data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:alternate_signature_algorithm] == true ? '1' : '0')),
        ]
      )
    end

    # it 'should enable and start the CertSvc service' do
    #   if attributes[:failover_clustering]
    #     expect(chef_run).to start_windows_service('CertSvc').with_startup_type(:manual)
    #   else
    #     expect(chef_run).to start_windows_service('CertSvc').with_startup_type(:automatic)
    #   end
    # end

    it 'should generate a new CRL when the service is restarted' do
      expect(chef_run.powershell_script('Generate new CRL')).to do_nothing
      expect(chef_run.powershell_script('Generate new CRL')).to subscribe_to('windows_service[CertSvc]')
    end
  end
end

shared_examples_for 'StandaloneRootCA is not installed and is not configured' do
  let(:code_copy_crt_crl) { "robocopy \"C:\\Windows\\System32\\CertSrv\\CertEnroll\" \"#{attributes[:caconfig_dir]}\" /MIR /NDL /NJS /NJH" }

  let(:registry_key_values_ca) do
    arr = []
    arr << { name: 'CRLDeltaPeriod',      type: :string, data: attributes[:crl_delta_period].downcase.capitalize }
    arr << { name: 'CRLDeltaPeriodUnits', type: :dword,  data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:crl_delta_period_units].to_s)) }
    arr << { name: 'CRLOverlapPeriod',    type: :string, data: attributes[:crl_overlap_period].downcase.capitalize }
    arr << { name: 'CRLOverlapUnits',     type: :dword,  data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:crl_overlap_units].to_s)) }
    arr << { name: 'CRLPeriod',           type: :string, data: attributes[:crl_period].downcase.capitalize }
    arr << { name: 'CRLPeriodUnits',      type: :dword,  data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:crl_period_units].to_s)) }
    arr << { name: 'DSConfigDN',          type: :string, data: 'CN=Configuration,DC=contoso,DC=com' } unless attributes[:windows_domain].nil?
    arr << { name: 'DSDomainDN',          type: :string, data: 'DC=contoso,DC=com' } unless attributes[:windows_domain].nil?
    arr << { name: 'ValidityPeriod',      type: :string, data: attributes[:validity_period].downcase.capitalize }
    arr << { name: 'ValidityPeriodUnits', type: :dword,  data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:validity_period_units].to_s)) }

    arr
  end

  let(:template_vars_capolicy) do
    template_var_enhanced_key_usage = attributes[:enhanced_key_usage]
    template_var_enhanced_key_usage = Array(template_var_enhanced_key_usage) unless template_var_enhanced_key_usage.nil?

    {
      alternate_signature_algorithm: attributes[:alternate_signature_algorithm] == true ? 1 : 0,
      clock_skew_minutes: attributes[:clock_skew_minutes],
      crl_delta_period: attributes[:crl_delta_period],
      crl_delta_period_units: attributes[:crl_delta_period_units],
      crl_period: attributes[:crl_period],
      crl_period_units: attributes[:crl_period_units],
      enable_key_counting: attributes[:enable_key_counting] == true ? 1 : 0,
      enhanced_key_usage: template_var_enhanced_key_usage,
      force_utf8: attributes[:force_utf8] == true ? 1 : 0,
      load_default_templates: attributes[:load_default_templates] == true ? 1 : 0,
      renewal_key_length: attributes[:renewal_key_length],
      renewal_validity_period: attributes[:renewal_validity_period],
      renewal_validity_period_units: attributes[:renewal_validity_period_units],
      policy: attributes[:policy],
    }
  end

  before do
    allow_any_instance_of(Chef::DSL::RegistryHelper).to receive(:registry_get_values).with('HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\ROOTCA-CA').and_return(
      [
        { name: 'CRLPublicationURLs', type: :multi_string, data: [] },
        { name: 'CACertPublicationURLs', type: :multi_string, data: [] },
      ]
    )

    shellout_certutil_getconfig = double(run_command: nil, error!: nil, stdout: "CertUtil: No local Certification Authority; use -config option\nCertUtil: No more data is available.\n", stderr: double(empty?: true))
    Mixlib::ShellOut.stub(:new).with('certutil -getconfig', shellout_options).and_return(shellout_certutil_getconfig)
    allow(shellout_certutil_getconfig).to receive(:live_stream).and_return(nil)
    allow(shellout_certutil_getconfig).to receive(:live_stream=).and_return(nil)

    shellout_certutil_ping = double(run_command: nil, error!: nil, stdout: "Connecting to ROOTCA\\ROOTCA-CA ... Server could not be reached: The RPC server is unavailable. 0x800706ba (WIN32: 1722 RPC_S_SERVER_UNAVAILABLE) -- (15ms)\n\nCertUtil: -ping command FAILED: 0x800706ba (WIN32: 1722 RPC_S_SERVER_UNAVAILABLE\nCertUtil: The RPC server is unavailable.\n", stderr: double(empty?: true))
    Mixlib::ShellOut.stub(:new).with('certutil -ping', shellout_options).and_return(shellout_certutil_ping)
    allow(shellout_certutil_ping).to receive(:live_stream).and_return(nil)
    allow(shellout_certutil_ping).to receive(:live_stream=).and_return(nil)

    shellout_install_adcs = double(run_command: nil, error!: nil, stdout: '', stderr: double(empty?: true))
    Mixlib::ShellOut.stub(:new).with("powershell.exe #{powershell_flags} -Command \"#{command_install_adcs}\"", shellout_options).and_return(shellout_install_adcs)
    allow(shellout_install_adcs).to receive(:live_stream).and_return(nil)
    allow(shellout_install_adcs).to receive(:live_stream=).and_return(nil)
  end

  it 'should converge successfully' do
    expect { chef_run }.to_not raise_error
  end

  it 'should create a certificate_services_install[StandaloneRootCA] resource with expected parameters' do
    expect(chef_run).to create_certificate_services_install('StandaloneRootCA').with(attributes)
  end

  it 'should copy the certificate and CRL to the CAConfig directory' do
    shellout_certutil_getconfig = double(run_command: nil, error!: nil, stdout: "Config String: \"ROOTCA\\ROOTCA-CA\"\nCertUtil: -getconfig command completed successfully.\n", stderr: double(empty?: true))
    Mixlib::ShellOut.stub(:new).with('certutil -getconfig', shellout_options).and_return(shellout_certutil_getconfig)
    allow(shellout_certutil_getconfig).to receive(:live_stream).and_return(nil)
    allow(shellout_certutil_getconfig).to receive(:live_stream=).and_return(nil)

    shellout_certutil_ping = double(run_command: nil, error!: nil, stdout: "Connecting to ROOTCA\\ROOTCA-CA ...\nServer \"ROOTCA-CA\" ICertRequest2 interface is alive (0ms)\nCertUtil: -ping command completed successfully.\n", stderr: double(empty?: true))
    Mixlib::ShellOut.stub(:new).with('certutil -ping', shellout_options).and_return(shellout_certutil_ping)
    allow(shellout_certutil_ping).to receive(:live_stream).and_return(nil)
    allow(shellout_certutil_ping).to receive(:live_stream=).and_return(nil)

    expect(chef_run).to run_batch('Copy certificate and CRLs to the CAConfig directory').with(
      architecture: :x86_64,
      code: code_copy_crt_crl,
      returns: [0, 1]
    )
  end

  it 'create a certificate_services_sign_request[C:/*.req] resource' do
    expect(chef_run).to create_certificate_services_sign_request('C:/*.req')
  end

  describe 'steps into certificate_services_install and' do
    it 'should create a CAPolicy.inf with expected content' do
      policy = [attributes[:policy]] unless attributes[:policy].nil?
      policy_name = []
      attributes[:policy].each { |p| policy_name << p.first } unless attributes[:policy].nil?

      expect(chef_run).to create_template('C:/Windows/CAPolicy.inf').with_variables(template_vars_capolicy.merge(policy: policy, policy_name: policy_name))
      expect(chef_run).to render_file('C:/Windows/CAPolicy.inf').with_content(content_capolicy)
    end

    it 'should create ca_config_dir' do
      expect(chef_run).to create_directory(attributes[:caconfig_dir])
    end

    it 'should create "CertificateServicesFunctions.ps1"' do
      expect(chef_run).to create_cookbook_file("#{attributes[:caconfig_dir]}\\CertificateServicesFunctions.ps1")
    end

    it 'should install Certificate Authority Windows features' do
      %w(ADCS-Cert-Authority RSAT-ADCS-Mgmt).each do |feature|
        expect(chef_run).to install_windows_feature(feature)
      end
    end

    it 'should install Certificate Authority' do
      expect(chef_run).to run_ruby_block('Install ADCS Certification Authority')
      # expect(Mixlib::ShellOut).to receive(:new).with("powershell.exe #{powershell_flags} -Command \"#{command_install_adcs}\"", shellout_options)
    end

    it 'should not configure AIA' do
      expect(chef_run).to_not run_powershell_script('Configure AIA').with_code(code_configure_aia)
    end

    it 'should not configure CDP' do
      expect(chef_run).to_not run_powershell_script('Configure CDP').with_code(code_configure_cdp)
    end

    it 'should set registry keys in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\ROOTCA-CA' do
      shellout_certutil_getconfig = double(run_command: nil, error!: nil, stdout: "Config String: \"ROOTCA\\ROOTCA-CA\"\nCertUtil: -getconfig command completed successfully.\n", stderr: double(empty?: true))
      Mixlib::ShellOut.stub(:new).with('certutil -getconfig', shellout_options).and_return(shellout_certutil_getconfig)
      allow(shellout_certutil_getconfig).to receive(:live_stream).and_return(nil)
      allow(shellout_certutil_getconfig).to receive(:live_stream=).and_return(nil)

      shellout_certutil_ping = double(run_command: nil, error!: nil, stdout: "Connecting to ROOTCA\\ROOTCA-CA ...\nServer \"ROOTCA-CA\" ICertRequest2 interface is alive (0ms)\nCertUtil: -ping command completed successfully.\n", stderr: double(empty?: true))
      Mixlib::ShellOut.stub(:new).with('certutil -ping', shellout_options).and_return(shellout_certutil_ping)
      allow(shellout_certutil_ping).to receive(:live_stream).and_return(nil)
      allow(shellout_certutil_ping).to receive(:live_stream=).and_return(nil)

      registry_key_values_ca.unshift(name: 'AuditFilter', type: :dword, data: Chef::Digester.instance.generate_checksum(StringIO.new(127.to_s))) if attributes[:enable_auditing_eventlogs]
      expect(chef_run).to create_registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\ROOTCA-CA').with_values(registry_key_values_ca)
    end

    it 'should set registry keys in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\ROOTCA-CA\CSP' do
      shellout_certutil_getconfig = double(run_command: nil, error!: nil, stdout: "Config String: \"ROOTCA\\ROOTCA-CA\"\nCertUtil: -getconfig command completed successfully.\n", stderr: double(empty?: true))
      Mixlib::ShellOut.stub(:new).with('certutil -getconfig', shellout_options).and_return(shellout_certutil_getconfig)
      allow(shellout_certutil_getconfig).to receive(:live_stream).and_return(nil)
      allow(shellout_certutil_getconfig).to receive(:live_stream=).and_return(nil)

      shellout_certutil_ping = double(run_command: nil, error!: nil, stdout: "Connecting to ROOTCA\\ROOTCA-CA ...\nServer \"ROOTCA-CA\" ICertRequest2 interface is alive (0ms)\nCertUtil: -ping command completed successfully.\n", stderr: double(empty?: true))
      Mixlib::ShellOut.stub(:new).with('certutil -ping', shellout_options).and_return(shellout_certutil_ping)
      allow(shellout_certutil_ping).to receive(:live_stream).and_return(nil)
      allow(shellout_certutil_ping).to receive(:live_stream=).and_return(nil)

      expect(chef_run).to create_registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\ROOTCA-CA\CSP').with_values(
        [
          name: 'AlternateSignatureAlgorithm', type: :dword, data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:alternate_signature_algorithm] == true ? '1' : '0')),
        ]
      )
    end

    it 'should enable and start the CertSvc service' do
      expect(chef_run).to enable_windows_service('CertSvc')
      expect(chef_run).to start_windows_service('CertSvc')
    end

    it 'should generate a new CRL when the service is restarted' do
      expect(chef_run.powershell_script('Generate new CRL')).to do_nothing
      expect(chef_run.powershell_script('Generate new CRL')).to subscribe_to('windows_service[CertSvc]')
    end
  end
end

shared_examples_for 'StandaloneRootCA is installed and is configured' do
  let(:code_copy_crt_crl) { "robocopy \"C:\\Windows\\System32\\CertSrv\\CertEnroll\" \"#{attributes[:caconfig_dir]}\" /MIR /NDL /NJS /NJH" }

  let(:registry_key_values_ca) do
    arr = []
    arr << { name: 'CRLDeltaPeriod',      type: :string, data: attributes[:crl_delta_period].downcase.capitalize }
    arr << { name: 'CRLDeltaPeriodUnits', type: :dword,  data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:crl_delta_period_units].to_s)) }
    arr << { name: 'CRLOverlapPeriod',    type: :string, data: attributes[:crl_overlap_period].downcase.capitalize }
    arr << { name: 'CRLOverlapUnits',     type: :dword,  data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:crl_overlap_units].to_s)) }
    arr << { name: 'CRLPeriod',           type: :string, data: attributes[:crl_period].downcase.capitalize }
    arr << { name: 'CRLPeriodUnits',      type: :dword,  data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:crl_period_units].to_s)) }
    arr << { name: 'DSConfigDN',          type: :string, data: 'CN=Configuration,DC=contoso,DC=com' } unless attributes[:windows_domain].nil?
    arr << { name: 'DSDomainDN',          type: :string, data: 'DC=contoso,DC=com' } unless attributes[:windows_domain].nil?
    arr << { name: 'ValidityPeriod',      type: :string, data: attributes[:validity_period].downcase.capitalize }
    arr << { name: 'ValidityPeriodUnits', type: :dword,  data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:validity_period_units].to_s)) }

    arr
  end

  let(:template_vars_capolicy) do
    template_var_enhanced_key_usage = attributes[:enhanced_key_usage]
    template_var_enhanced_key_usage = Array(template_var_enhanced_key_usage) unless template_var_enhanced_key_usage.nil?

    {
      alternate_signature_algorithm: attributes[:alternate_signature_algorithm] == true ? 1 : 0,
      clock_skew_minutes: attributes[:clock_skew_minutes],
      crl_delta_period: attributes[:crl_delta_period],
      crl_delta_period_units: attributes[:crl_delta_period_units],
      crl_period: attributes[:crl_period],
      crl_period_units: attributes[:crl_period_units],
      enable_key_counting: attributes[:enable_key_counting] == true ? 1 : 0,
      enhanced_key_usage: template_var_enhanced_key_usage,
      force_utf8: attributes[:force_utf8] == true ? 1 : 0,
      load_default_templates: attributes[:load_default_templates] == true ? 1 : 0,
      renewal_key_length: attributes[:renewal_key_length],
      renewal_validity_period: attributes[:renewal_validity_period],
      renewal_validity_period_units: attributes[:renewal_validity_period_units],
      policy: attributes[:policy],
    }
  end

  before do
    allow_any_instance_of(Chef::DSL::RegistryHelper).to receive(:registry_get_values).with('HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\ROOTCA-CA').and_return(
      [
        { name: 'CRLPublicationURLs', type: :multi_string, data: [] },
        { name: 'CACertPublicationURLs', type: :multi_string, data: [] },
      ]
    )

    shellout_certutil_getconfig = double(run_command: nil, error!: nil, stdout: "Config String: \"ROOTCA\\ROOTCA-CA\"\nCertUtil: -getconfig command completed successfully.\n", stderr: double(empty?: true))
    Mixlib::ShellOut.stub(:new).with('certutil -getconfig', shellout_options).and_return(shellout_certutil_getconfig)
    allow(shellout_certutil_getconfig).to receive(:live_stream).and_return(nil)
    allow(shellout_certutil_getconfig).to receive(:live_stream=).and_return(nil)

    shellout_certutil_ping = double(run_command: nil, error!: nil, stdout: "Connecting to ROOTCA\\ROOTCA-CA ...\nServer \"ROOTCA-CA\" ICertRequest2 interface is alive (0ms)\nCertUtil: -ping command completed successfully.\n", stderr: double(empty?: true))
    Mixlib::ShellOut.stub(:new).with('certutil -ping', shellout_options).and_return(shellout_certutil_ping)
    allow(shellout_certutil_ping).to receive(:live_stream).and_return(nil)
    allow(shellout_certutil_ping).to receive(:live_stream=).and_return(nil)

    shellout_install_adcs = double(run_command: nil, error!: nil, stdout: '', stderr: double(empty?: true))
    Mixlib::ShellOut.stub(:new).with("powershell.exe #{powershell_flags} -Command \"#{command_install_adcs}\"", shellout_options).and_return(shellout_install_adcs)
    allow(shellout_install_adcs).to receive(:live_stream).and_return(nil)
    allow(shellout_install_adcs).to receive(:live_stream=).and_return(nil)
  end

  it 'should converge successfully' do
    expect { chef_run }.to_not raise_error
  end

  it 'should create a certificate_services_install[StandaloneRootCA] resource with expected parameters' do
    expect(chef_run).to create_certificate_services_install('StandaloneRootCA').with(attributes)
  end

  it 'should copy the certificate and CRL to the CAConfig directory' do
    expect(chef_run).to run_batch('Copy certificate and CRLs to the CAConfig directory').with(
      architecture: :x86_64,
      code: code_copy_crt_crl,
      returns: [0, 1]
    )
  end

  it 'create a certificate_services_sign_request[C:/*.req] resource' do
    expect(chef_run).to create_certificate_services_sign_request('C:/*.req')
  end

  describe 'steps into certificate_services_install and' do
    it 'should create a CAPolicy.inf with expected content' do
      policy = [attributes[:policy]] unless attributes[:policy].nil?
      policy_name = []
      attributes[:policy].each { |p| policy_name << p.first } unless attributes[:policy].nil?

      expect(chef_run).to create_template('C:/Windows/CAPolicy.inf').with_variables(template_vars_capolicy.merge(policy: policy, policy_name: policy_name))
      expect(chef_run).to render_file('C:/Windows/CAPolicy.inf').with_content(content_capolicy)
    end

    it 'should create ca_config_dir' do
      expect(chef_run).to create_directory(attributes[:caconfig_dir])
    end

    it 'should create "CertificateServicesFunctions.ps1"' do
      expect(chef_run).to create_cookbook_file("#{attributes[:caconfig_dir]}\\CertificateServicesFunctions.ps1")
    end

    it 'should install Certificate Authority Windows features' do
      %w(ADCS-Cert-Authority RSAT-ADCS-Mgmt).each do |feature|
        expect(chef_run).to install_windows_feature(feature)
      end
    end

    it 'should not install Certificate Authority' do
      expect(chef_run).to_not run_ruby_block('Install ADCS Certification Authority')
      # expect(Mixlib::ShellOut).to receive(:new).with("powershell.exe #{powershell_flags} -Command \"#{command_install_adcs}\"", shellout_options)
    end

    describe 'should configure AIA if aia_url attribute is set' do
      it 'unless aia_url config is up to date' do
        if attributes[:aia_url]
          allow_any_instance_of(Chef::DSL::RegistryHelper).to receive(:registry_get_values).with('HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\ROOTCA-CA').and_return(
            [
              { name: 'CACertPublicationURLs', type: :multi_string, data: ['http://pki.contoso.com/cdp/%3.crt', 'http://pki2.contoso.com/cdp/%3.crt'] },
            ]
          )
        end

        expect(chef_run).to_not run_powershell_script('Configure AIA').with_code(code_configure_aia)
      end

      it 'if aia_url config is not up to date' do
        expect(chef_run).to run_powershell_script('Configure AIA').with_code(code_configure_aia) if attributes[:aia_url]
      end
    end

    describe 'should configure CDP if cdp_url attribute is set' do
      it 'unless cdp_url config is up to date' do
        if attributes[:cdp_url]
          allow_any_instance_of(Chef::DSL::RegistryHelper).to receive(:registry_get_values).with('HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\ROOTCA-CA').and_return(
            [
              { name: 'CRLPublicationURLs', type: :multi_string, data: ['65:C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%8%9.crl', '65:C:\\CAConfig\\%3%8%9.crl', 'http://pki.contoso.com/cdp/%3%8.crl', 'http://pki2.contoso.com/cdp/%3%8.crl'] },
            ]
          )
        end

        expect(chef_run).to_not run_powershell_script('Configure CDP').with_code(code_configure_cdp)
      end

      it 'if cdp_url config is not up to date' do
        expect(chef_run).to run_powershell_script('Configure CDP').with_code(code_configure_cdp) if attributes[:cdp_url]
      end
    end

    it 'should set registry keys in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\ROOTCA-CA' do
      registry_key_values_ca.unshift(name: 'AuditFilter', type: :dword, data: Chef::Digester.instance.generate_checksum(StringIO.new(127.to_s))) if attributes[:enable_auditing_eventlogs]
      expect(chef_run).to create_registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\ROOTCA-CA').with_values(registry_key_values_ca)
    end

    it 'should set registry keys in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\ROOTCA-CA\CSP' do
      expect(chef_run).to create_registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\ROOTCA-CA\CSP').with_values(
        [
          name: 'AlternateSignatureAlgorithm', type: :dword, data: Chef::Digester.instance.generate_checksum(StringIO.new(attributes[:alternate_signature_algorithm] == true ? '1' : '0')),
        ]
      )
    end

    it 'should enable and start the CertSvc service' do
      expect(chef_run).to enable_windows_service('CertSvc')
      expect(chef_run).to start_windows_service('CertSvc')
    end

    it 'should generate a new CRL when the service is restarted' do
      expect(chef_run.powershell_script('Generate new CRL')).to do_nothing
      expect(chef_run.powershell_script('Generate new CRL')).to subscribe_to('windows_service[CertSvc]')
    end
  end
end

at_exit { ChefSpec::Coverage.report! }
