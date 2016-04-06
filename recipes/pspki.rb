#
# Cookbook Name:: certificate_services
# Recipe:: pspki
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

raise(RuntimeError, "Cannot use certificate_services::pspki recipe with this version of Chef client; please use 12.8.1 or later.") unless Gem::Version.new(node['chef_packages']['chef']['version']) >= Gem::Version.new('12.8.1')

remote_file "#{Chef::Config['file_cache_path']}/pscx.msi" do
  source node['certificate_services']['pscx']['source_url']
end

package node['certificate_services']['pscx']['package_name'] do
  source "#{Chef::Config['file_cache_path']}/pscx.msi"
  installer_type :msi
end

remote_file "#{Chef::Config['file_cache_path']}/pspki.exe" do
  source node['certificate_services']['pspki']['source_name']
end

package node['certificate_services']['pspki']['package_name'] do
  source "#{Chef::Config['file_cache_path']}/pspki.exe"
  installer_type :custom
  options 'addlocal=all /qn'
end
