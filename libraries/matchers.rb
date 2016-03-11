#
# Cookbook Name:: certificate_services
# Library:: matchers
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

if defined?(ChefSpec)
  #
  # certificate_services_install
  #
  def create_certificate_services_install(resource_name)
    ChefSpec::Matchers::ResourceMatcher.new(:certificate_services_install, :create, resource_name)
  end

  def delete_certificate_services_install(resource_name)
    ChefSpec::Matchers::ResourceMatcher.new(:certificate_services_install, :delete, resource_name)
  end

  #
  # certificate_services_sign_request
  #
  def create_certificate_services_sign_request(resource_name)
    ChefSpec::Matchers::ResourceMatcher.new(:certificate_services_sign_request, :create, resource_name)
  end

  def delete_certificate_services_sign_request(resource_name)
    ChefSpec::Matchers::ResourceMatcher.new(:certificate_services_sign_request, :delete, resource_name)
  end
end
