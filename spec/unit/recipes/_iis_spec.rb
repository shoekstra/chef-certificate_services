require 'spec_helper'

shared_examples_for 'IIS should be installed/configured' do
  it 'should install IIS' do
    %w(Web-Basic-Auth Web-Mgmt-Console Web-Mgmt-Service Web-Mgmt-Tools Web-WebServer).each do |feature_name|
      expect(chef_run).to install_windows_feature(feature_name)
    end

    %w(W3SVC WMSvc).each do |service_name|
      expect(chef_run).to enable_windows_service(service_name)
      expect(chef_run).to start_windows_service(service_name)
    end
  end

  it 'should enable remote management' do
    expect(chef_run).to create_registry_key('HKLM\SOFTWARE\Microsoft\WebManagement\Server').with_values(
      [{ name: 'EnableRemoteManagement', type: :dword, data: '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b' }]
    )
  end

  it 'should schedule a restart of windows_service[WMSvc]' do
    expect(chef_run.registry_key('HKLM\SOFTWARE\Microsoft\WebManagement\Server')).to notify('windows_service[WMSvc]').to(:restart).delayed
  end

  it 'should enable anonymous authentication' do
    expect(chef_run).to run_powershell_script('Set anonymous authentication (WebConfiguration)').with_code(
      'Set-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost -Metadata overrideMode -Value Allow'
    )
    expect(chef_run.powershell_script('Set anonymous authentication (WebConfiguration)')).to notify('windows_service[W3SVC]').to(:restart).delayed
  end

  it 'should run iis_config with /section:windowsAuthentication /authPersistNonNTLM:true' do
    expect(chef_run).to set_iis_config('/section:windowsAuthentication /authPersistNonNTLM:true')
  end
end

shared_examples_for 'IIS is already installed/configured' do
  it 'should install IIS' do
    %w(Web-Basic-Auth Web-Mgmt-Console Web-Mgmt-Service Web-Mgmt-Tools Web-WebServer).each do |feature_name|
      expect(chef_run).to install_windows_feature(feature_name)
    end

    %w(W3SVC WMSvc).each do |service_name|
      expect(chef_run).to enable_windows_service(service_name)
      expect(chef_run).to start_windows_service(service_name)
    end
  end

  it 'should enable remote management' do
    expect(chef_run).to create_registry_key('HKLM\SOFTWARE\Microsoft\WebManagement\Server').with_values(
      [{ name: 'EnableRemoteManagement', type: :dword, data: '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b' }]
    )
  end

  it 'should schedule a restart of windows_service[WMSvc]' do
    expect(chef_run.registry_key('HKLM\SOFTWARE\Microsoft\WebManagement\Server')).to notify('windows_service[WMSvc]').to(:restart).delayed
  end

  it 'should not enable anonymous authentication' do
    expect(chef_run).to_not run_powershell_script('Set anonymous authentication (WebConfiguration)').with_code(
      'Set-WebConfiguration -Filter /system.WebServer/security/authentication/AnonymousAuthentication -PSPath machine/webroot/apphost -Metadata overrideMode -Value Allow'
    )
    expect(chef_run.powershell_script('Set anonymous authentication (WebConfiguration)')).to notify('windows_service[W3SVC]').to(:restart).delayed
  end

  it 'should run iis_config with /section:windowsAuthentication /authPersistNonNTLM:true' do
    expect(chef_run).to set_iis_config('/section:windowsAuthentication /authPersistNonNTLM:true')
  end
end
