#
# Cookbook Name:: certificate_services
# Recipe:: online_responder
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
