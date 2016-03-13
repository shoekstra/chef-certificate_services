#
# Cookbook Name:: certificate_services
# Spec:: pspki
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

require 'spec_helper'

describe 'certificate_services::pspki' do
  context 'when all attributes are default' do
    let(:chef_run) do
      ChefSpec::SoloRunner.new(file_cache_path: '/Chef/cache').converge(described_recipe)
    end

    it 'converge successfully' do
      expect { chef_run }.to_not raise_error
    end

    it 'installs the PSCX PowerShell module'do
      expect(chef_run).to create_remote_file('/Chef/cache/pscx.msi').with(
        source: 'http://download-codeplex.sec.s-msft.com/Download/Release?ProjectName=pscx&DownloadId=923562&FileTime=130585918034470000&Build=21031'
      )

      expect(chef_run).to install_package('PowerShell Community Extensions 3.2.0').with(
        source: '/Chef/cache/pscx.msi',
        installer_type: :msi
      )
    end

    it 'installs the PSPKI PowerShell module' do
      expect(chef_run).to create_remote_file('/Chef/cache/pspki.exe').with(
        source: 'http://download-codeplex.sec.s-msft.com/Download/Release?ProjectName=pspki&DownloadId=1440723&FileTime=130716062844400000&Build=21031'
      )

      expect(chef_run).to install_package('PowerShell PKI Module').with(
        source: '/Chef/cache/pspki.exe',
        installer_type: :custom,
        options: '/quiet'
      )
    end
  end

  context 'when custom values are specified' do
    let(:chef_run) do
      ChefSpec::SoloRunner.new(file_cache_path: '/Chef/cache') do |node|
        node.set['certificate_services']['pscx']['package_name']  = 'pscx package name'
        node.set['certificate_services']['pscx']['source_url']    = 'http://test'
        node.set['certificate_services']['pspki']['package_name'] = 'pspki package name'
        node.set['certificate_services']['pspki']['source_name']  = 'http://test'
      end.converge(described_recipe)
    end

    it 'converge successfully' do
      expect { chef_run }.to_not raise_error
    end

    it 'installs the PSCX PowerShell module'do
      expect(chef_run).to create_remote_file('/Chef/cache/pscx.msi').with(
        source: 'http://test'
      )

      expect(chef_run).to install_package('pscx package name').with(
        source: '/Chef/cache/pscx.msi',
        installer_type: :msi
      )
    end

    it 'installs the PSPKI PowerShell module' do
      expect(chef_run).to create_remote_file('/Chef/cache/pspki.exe').with(
        source: 'http://test'
      )

      expect(chef_run).to install_package('pspki package name').with(
        source: '/Chef/cache/pspki.exe',
        installer_type: :custom,
        options: '/quiet'
      )
    end
  end
end
