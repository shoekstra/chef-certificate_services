#
# Cookbook Name:: certificate_services
# Spec:: helper
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

require 'spec_helper'
require_relative '../../../libraries/certificate_services_helper.rb'

describe CertificateServices::Helper do
  let(:shellout_options) { { environment: { 'LC_ALL' => 'en_US.UTF-8', 'LANGUAGE' => 'en_US.UTF-8', 'LANG' => 'en_US.UTF-8' } } }
  let(:helper_class) { Class.new { include CertificateServices::Helper } }

  describe '#ca_configured?' do
    let(:shellout) { double(run_command: nil, error!: nil, stdout: '', stderr: double(empty?: true)) }
    before { Mixlib::ShellOut.stub(:new).and_return(shellout) }

    it 'builds the correct command' do
      expect(Mixlib::ShellOut).to receive(:new).with('certutil -ping', shellout_options)
      expect(shellout).to receive(:live_stream).and_return(nil)
      expect(shellout).to receive(:live_stream=).and_return(nil)
      expect(helper_class.new.ca_configured?).to be false
    end

    context 'when CA not configured' do
      stdout = "Connecting to SUBCA.contoso.com\\contoso-SUBCA-CA ... Server could not be reached: The RPC server is unavailable. 0x800706ba (WIN32: 1722 RPC_S_SERVER_UNAVAILABLE) -- (15ms)\n\nCertUtil: -ping command FAILED: 0x800706ba (WIN32: 1722 RPC_S_SERVER_UNAVAILABLE\nCertUtil: The RPC server is unavailable.\n"
      let(:shellout) { double(run_command: nil, error!: nil, stdout: stdout, stderr: double(empty?: true)) }
      before { Mixlib::ShellOut.stub(:new).and_return(shellout) }

      it 'says CA is not configured' do
        expect(shellout).to receive(:live_stream).and_return(nil)
        expect(shellout).to receive(:live_stream=).and_return(nil)
        expect(helper_class.new.ca_configured?).to be false
      end
    end

    context 'when CA configured' do
      stdout = "Connecting to SUBCA.contoso.com\\contoso-SUBCA-CA ...\nServer \"contoso-SUBCA-CA\" ICertRequest2 interface is alive (0ms)\nCertUtil: -ping command completed successfully.\n"
      let(:shellout) { double(run_command: nil, error!: nil, stdout: stdout, stderr: double(empty?: true)) }
      before { Mixlib::ShellOut.stub(:new).and_return(shellout) }

      it 'says CA is configured' do
        expect(shellout).to receive(:live_stream).and_return(nil)
        expect(shellout).to receive(:live_stream=).and_return(nil)
        expect(helper_class.new.ca_configured?).to be true
      end
    end
  end

  describe '#ca_installed?' do
    let(:shellout) { double(run_command: nil, error!: nil, stdout: '', stderr: double(empty?: true)) }
    before { Mixlib::ShellOut.stub(:new).and_return(shellout) }

    it 'builds the correct command' do
      expect(Mixlib::ShellOut).to receive(:new).with('certutil -getconfig', shellout_options)
      expect(shellout).to receive(:live_stream).and_return(nil)
      expect(shellout).to receive(:live_stream=).and_return(nil)
      expect(helper_class.new.ca_installed?).to be false
    end

    context 'when CA not installed' do
      stdout = "CertUtil: No local Certification Authority; use -config option\nCertUtil: No more data is available.\n"
      let(:shellout) { double(run_command: nil, error!: nil, stdout: stdout, stderr: double(empty?: true)) }
      before { Mixlib::ShellOut.stub(:new).and_return(shellout) }

      it 'says CA is not installed' do
        expect(shellout).to receive(:live_stream).and_return(nil)
        expect(shellout).to receive(:live_stream=).and_return(nil)
        expect(helper_class.new.ca_installed?).to be false
      end
    end

    context 'when CA installed' do
      stdout = "Config String: \"ROOTCA\\ROOTCA-CA\"\nCertUtil: -getconfig command completed successfully.\n"
      let(:shellout) { double(run_command: nil, error!: nil, stdout: stdout, stderr: double(empty?: true)) }
      before { Mixlib::ShellOut.stub(:new).and_return(shellout) }

      it 'says CA is installed' do
        expect(shellout).to receive(:live_stream).and_return(nil)
        expect(shellout).to receive(:live_stream=).and_return(nil)
        expect(helper_class.new.ca_installed?).to be true
      end
    end
  end

  describe '#ca_name' do
    let(:shellout) { double(run_command: nil, error!: nil, stdout: '', stderr: double(empty?: true)) }
    before { Mixlib::ShellOut.stub(:new).and_return(shellout) }

    it 'builds the correct command' do
      expect(Mixlib::ShellOut).to receive(:new).with('certutil -getconfig', shellout_options)
      expect(shellout).to receive(:live_stream).and_return(nil)
      expect(shellout).to receive(:live_stream=).and_return(nil)
      expect(helper_class.new.ca_name).to be nil
    end

    context 'when CA not name' do
      stdout = "CertUtil: No local Certification Authority; use -config option\nCertUtil: No more data is available.\n"
      let(:shellout) { double(run_command: nil, error!: nil, stdout: stdout, stderr: double(empty?: true)) }
      before { Mixlib::ShellOut.stub(:new).and_return(shellout) }

      it 'says CA is not name' do
        expect(shellout).to receive(:live_stream).and_return(nil)
        expect(shellout).to receive(:live_stream=).and_return(nil)
        expect(helper_class.new.ca_name).to be nil
      end
    end

    context 'when CA name' do
      stdout = "Config String: \"ROOTCA\\ROOTCA-CA\"\nCertUtil: -getconfig command completed successfully.\n"
      let(:shellout) { double(run_command: nil, error!: nil, stdout: stdout, stderr: double(empty?: true)) }
      before { Mixlib::ShellOut.stub(:new).and_return(shellout) }

      it 'says CA is name' do
        expect(shellout).to receive(:live_stream).and_return(nil)
        expect(shellout).to receive(:live_stream=).and_return(nil)
        expect(helper_class.new.ca_name).to eq 'ROOTCA\\ROOTCA-CA'
      end
    end
  end

  describe '#domain_dn' do
    include CertificateServices::Helper

    context 'when argument is not given' do
      it 'raise an error' do
        expect { domain_dn }.to raise_error(ArgumentError)
      end
    end

    context 'when lowercase argument "contoso.com" is given' do
      it 'returns domain DN "DC=contoso,DC=com"' do
        expect(domain_dn('contoso.com')).to eq('DC=contoso,DC=com')
      end
    end

    context 'when uppercase argument "CONTOSO.COM" is given' do
      it 'returns domain DN "DC=contoso,DC=com"' do
        expect(domain_dn('CONTOSO.COM')).to eq('DC=contoso,DC=com')
      end
    end
  end
end
