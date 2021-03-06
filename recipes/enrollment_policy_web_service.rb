#
# Cookbook Name:: certificate_services
# Recipe:: enrollment_policy_web_service
#
# Copyright 2019, Stephen Hoekstra
# Copyright 2019, Schuberg Philis
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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
