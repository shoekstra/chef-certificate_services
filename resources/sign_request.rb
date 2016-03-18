#
# Cookbook Name:: certificate_services
# Resource:: sign_request
#
# Copyright (C) 2016 Schuberg Philis
#
# Created by: Stephen Hoekstra <shoekstra@schubergphilis.com>
#

include CertificateServices::Helper

actions :create
default_action :create

property :path, kind_of: String, required: true, name_property: true

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
