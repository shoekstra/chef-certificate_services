#
# Cookbook Name:: testcookbook
# Recipe:: vagrant
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

# Fix problem with Centos 7 networking
#
execute 'nmcli connection reload && systemctl restart network.service' do
  only_if { node['platform_family'] == 'rhel' && node['platform_version'].to_i == 7 }
end

# Keep packages on the guest, for use with vagrant-cachier
#
node.default['yum']['main']['keepcache'] = true if node['platform_family'] == 'rhel'

node['yum']['repos'].each do |repo|
  node.default['yum']['repos'][repo.first]['make_cache'] = false
end

chef_gem 'chef-rewind'
require 'chef/rewind'

# Include default recipe
#
include_recipe "#{cookbook_name}::default"

# Ensure vim is installed
#
package 'vim'

# Unwind resources that prevent caching
#
unwind 'zap_yum_repos[/etc/yum.repos.d]'
unwind 'execute[yum_clean_all]'
zap_yum_repos 'remove repos'
