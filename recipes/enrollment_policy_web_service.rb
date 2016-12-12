#
# Cookbook Name:: certificate_services
# Recipe:: enrollment_policy_web_service
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

config = node[cookbook_name][recipe_name]

if config['kerberos'].empty? && config['username'].empty?
  raise("To use #{cookbook_name}::#{recipe_name} you must configure node['#{cookbook_name}']['#{recipe_name}'] attributes")
end

config.each do |auth_type, auth_config|
  next if auth_config.empty?

  certificate_services_enrollment_policy_web_service auth_type do
    auth_type auth_config['auth_type'] if auth_config['auth_type']
    domain_pass auth_config['domain_pass'] if auth_config['domain_pass']
    domain_user auth_config['domain_user'] if auth_config['domain_user']
    friendly_name auth_config['friendly_name'] if auth_config['friendly_name']
    key_based_renewal auth_config['key_based_renewal'] if auth_config['key_based_renewal']
  end
end
