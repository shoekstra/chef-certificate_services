#
# Cookbook Name:: certificate_services
# Library:: helper
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

# require 'wmi-lite'

module CertificateServices
  module Helper
    include Chef::Mixin::ShellOut
    #
    # Return CA configured status
    #
    def ca_configured?
      shell_out('certutil -ping').stdout.include?('is alive')
    end

    #
    # Return CA installed status
    #
    def ca_installed?
      shell_out('certutil -getconfig').stdout.include?('Config String:')
    end

    #
    # Return name of CA
    #
    def ca_name
      result = shell_out('certutil -getconfig').stdout
      return nil unless result.include?('command completed successfully')
      result.split(/\n/)[0].split(': ')[1].delete('"').chomp
    end

    #
    # Return domain distinguished name
    #
    def domain_dn(domain)
      domain.split('.').map! { |k| "DC=#{k.downcase}" }.join(',')
    end

    #
    # Return an array (empty array if passed nil)
    #
    def to_array(var)
      var = var.is_a?(Array) ? var : [var]
      var = var.reject(&:nil?)
      var
    end

    #
    # Return true if computer is running Windows
    #
    def windows?
      RUBY_PLATFORM =~ /mswin|mingw|windows/
    end

    #
    # Return true if computer is domain joined
    #
    def windows_domain_joined?
      return false unless windows?

      wmi = WmiLite::Wmi.new
      computer_system = wmi.first_of('Win32_ComputerSystem')
      computer_system['partofdomain']
    end
  end
end unless defined?(CertificateServices::Helper)
