#
# Cookbook Name:: certificate_services
# Recipe:: online_responder
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

include_recipe "#{cookbook_name}::_iis" unless node.recipe?("#{cookbook_name}::_iis")
include_recipe 'pspki::default'

config = node['certificate_services']['online_responder']

certificate_services_online_responder config['ca_name'] do
  array_controller config['array_controller'] if config['array_controller']
  array_members config['array_members'] if config['array_members']
  cdp_url_base config['cdp_url_base'] if config['cdp_url_base']
  domain_pass config['domain_pass'] if config['domain_pass']
  domain_user config['domain_user'] if config['domain_user']
end
