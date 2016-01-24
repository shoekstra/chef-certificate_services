#
# Cookbook Name:: testcookbook
# Recipe:: default
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

# Enable selinux before doing anything further
#
node.default['selinux']['state'] = 'enforcing'

include_recipe 'selinux'

# Install SBP NRPE checks
#
include_recipe 'sbp_nrpe_wrapper::default'

# Install SBP repos
#
include_recipe 'sbp_yum_wrapper::default'
