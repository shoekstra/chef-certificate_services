#
# Cookbook Name:: certificate_services
# Recipe:: web_enrollment
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

config = node['certificate_services']['web_enrollment']

certificate_services_web_enrollment config['ca_config'] do
  domain_pass config['domain_pass'] if config['domain_pass']
  domain_user config['domain_user'] if config['domain_user']
end
