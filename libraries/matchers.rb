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
  # certificate_services_aia
  #
  def create_certificate_services_aia(resource_name)
    ChefSpec::Matchers::ResourceMatcher.new(:certificate_services_aia, :create, resource_name)
  end

  def delete_certificate_services_aia(resource_name)
    ChefSpec::Matchers::ResourceMatcher.new(:certificate_services_aia, :delete, resource_name)
  end

  #
  # certificate_services_capolicy
  #
  def create_certificate_services_capolicy(resource_name)
    ChefSpec::Matchers::ResourceMatcher.new(:certificate_services_capolicy, :create, resource_name)
  end

  def delete_certificate_services_capolicy(resource_name)
    ChefSpec::Matchers::ResourceMatcher.new(:certificate_services_capolicy, :delete, resource_name)
  end

  #
  # certificate_services_cdp
  #
  def create_certificate_services_cdp(resource_name)
    ChefSpec::Matchers::ResourceMatcher.new(:certificate_services_cdp, :create, resource_name)
  end

  def delete_certificate_services_cdp(resource_name)
    ChefSpec::Matchers::ResourceMatcher.new(:certificate_services_cdp, :delete, resource_name)
  end

  #
  # certificate_services_cdp_endpoint
  #
  def create_certificate_services_cdp_endpoint(resource_name)
    ChefSpec::Matchers::ResourceMatcher.new(:certificate_services_cdp_endpoint, :create, resource_name)
  end

  def delete_certificate_services_cdp_endpoint(resource_name)
    ChefSpec::Matchers::ResourceMatcher.new(:certificate_services_cdp_endpoint, :delete, resource_name)
  end

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
  # certificate_services_import
  #
  def install_certificate_services_import(resource_name)
    ChefSpec::Matchers::ResourceMatcher.new(:certificate_services_import, :install, resource_name)
  end

  def delete_certificate_services_import(resource_name)
    ChefSpec::Matchers::ResourceMatcher.new(:certificate_services_import, :delete, resource_name)
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
