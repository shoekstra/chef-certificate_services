#
# Cookbook Name:: certificate_services
# Recipe:: default
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

# Include this cookbook's SELinux config if SELinux is enabled
#
extend Chef::Util::Selinux
include_recipe "#{cookbook_name}::_selinux" if selinux_enabled?

# Include this cookbook's Nagios config/checks if 'nrpe' is in the run_list
#
include_recipe "#{cokbook_name}::_nrpe" if node.recipe?('nrpe')

# Install/configure something here
#
