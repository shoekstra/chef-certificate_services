#
# Cookbook Name:: certificate_services
# Recipe:: network_device_enrollment_service
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

config = node['certificate_services']['network_device_enrollment_service']

certificate_services_network_device_enrollment_service config['ca_config'] do
  app_pool_identity config['app_pool_identity'] if config['app_pool_identity']
  domain_pass config['domain_pass'] if config['domain_pass']
  domain_user config['domain_user'] if config['domain_user']
  encryption_key_length config['encryption_key_length'] if config['encryption_key_length']
  encryption_provider_name config['encryption_provider_name'] if config['encryption_provider_name']
  encryption_template config['encryption_template'] if config['encryption_template']
  general_purpose_template config['general_purpose_template'] if config['general_purpose_template']
  ra_city config['ra_city'] if config['ra_city']
  ra_company config['ra_company'] if config['ra_company']
  ra_country config['ra_country'] if config['ra_country']
  ra_department config['ra_department'] if config['ra_department']
  ra_email config['ra_email'] if config['ra_email']
  ra_name config['ra_name'] if config['ra_name']
  ra_state config['ra_state'] if config['ra_state']
  service_password config['service_password'] if config['service_password']
  service_user config['service_user'] if config['service_user']
  signature_template config['signature_template'] if config['signature_template']
  signing_key_length config['signing_key_length'] if config['signing_key_length']
  signing_provider_name config['signing_provider_name'] if config['signing_provider_name']
  use_single_password config['use_single_password'] if config['use_single_password']
end
