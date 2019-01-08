#
# Cookbook Name:: certificate_services
# Resource:: sign_request
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

include CertificateServices::Helper

default_action :create

property :path, String, name_property: true

action :create do
  #
  # Look for any .req files in C:\ from subordinate CAs and sign them
  #
  Dir.glob(new_resource.path).each do |request|
    request_id = submit_request(request)
    resubmit_request(request_id)
    retrieve_request(request_id, request)
    delete_request_file(request)
  end
end

def delete_request_file(request)
  Chef::Log.debug("Deleted signing request \"#{request}\".") if ::File.delete(request)
end

def submit_request(file)
  Chef::Log.debug("RUNNING: certreq -Submit -Config \"#{ca_name}\" \"#{file}\"")
  cmd = Mixlib::ShellOut.new("certreq -Submit -Config \"#{ca_name}\" \"#{file}\"").run_command
  cmd.error!

  cmd.stdout.split(/\r\n/).grep(/RequestId/).first.gsub('RequestId: ', '')
end

def resubmit_request(request_id)
  Chef::Log.debug("RUNNING: certutil -Resubmit #{request_id}")
  cmd = Mixlib::ShellOut.new("certutil -Resubmit #{request_id}").run_command
  cmd.error!
end

def retrieve_request(request_id, request)
  Chef::Log.debug("RUNNING: certreq -Retrieve -Config \"#{ca_name}\" #{request_id} \"#{request.gsub('req', 'crt')}\"")
  cmd = Mixlib::ShellOut.new("certreq -Retrieve -f -Config \"#{ca_name}\" #{request_id} \"#{request.gsub('req', 'crt')}\"").run_command
  cmd.error!

  Chef::Log.debug("Signed awaiting request \"#{request}\".")
end
