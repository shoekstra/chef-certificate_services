#
# Cookbook Name:: certificate_services
# Recipe:: web_enrollment
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

config = node['certificate_services']['web_enrollment']

certificate_services_web_enrollment config['ca_config'] do
  domain_pass config['domain_pass'] if config['domain_pass']
  domain_user config['domain_user'] if config['domain_user']
end
