# Define default CentOS/Redhat repositories
#
if node['platform_family'] == 'rhel'
  default['yum']['repos']['artifacts-epel']['description']  = 'Fedora EPEL packages'
  default['yum']['repos']['artifacts-epel']['baseurl']      = "http://artifacts.schubergphilis.com/mrepo/epel-#{node['platform_version'][0]}-x86_64-weekly/#{node['yum']['snapshot']}/RPMS.epel/"
  default['yum']['repos']['artifacts-epel']['gpgcheck']     = false
  default['yum']['repos']['artifacts-epel']['enabled']      = true

  default['yum']['repos']['sbp']['description']             = 'SBP'
  default['yum']['repos']['sbp']['baseurl']                 = "http://artifacts.schubergphilis.com/mrepo/sbp-#{node['platform_version'][0]}-x86_64-weekly/#{node['yum']['snapshot']}/RPMS.sbp/"
  default['yum']['repos']['sbp']['gpgcheck']                = false
  default['yum']['repos']['sbp']['enabled']                 = true
end

# Define specific CentOS repositories
#
if node['platform'] == 'centos'
  default['yum']['repos']['os']['description']             = 'CentOS-$releasever - Base'
  default['yum']['repos']['os']['baseurl']                 = "http://artifacts.schubergphilis.com/mrepo/centos-#{node['platform_version'][0]}-x86_64-weekly/#{node['yum']['snapshot']}/RPMS.os/"
  default['yum']['repos']['os']['gpgcheck']                = false
  default['yum']['repos']['os']['enabled']                 = true

  default['yum']['repos']['centos_updates']['description'] = 'CentOS-$releasever - Updates'
  default['yum']['repos']['centos_updates']['baseurl']     = "http://artifacts.schubergphilis.com/mrepo/centos-#{node['platform_version'][0]}-x86_64-weekly/#{node['yum']['snapshot']}/RPMS.updates/"
  default['yum']['repos']['centos_updates']['gpgcheck']    = false
  default['yum']['repos']['centos_updates']['enabled']     = true
end

# Define specific Redhat repositories
#
if node['platform'] == 'redhat'
  default['yum']['repos']['os']['description']             = 'RHEL-$releasever - Base'
  default['yum']['repos']['os']['baseurl']                 = "http://artifacts.schubergphilis.com/mrepo/redhat-#{node['platform_version'][0]}-x86_64-weekly/#{node['yum']['snapshot']}/RPMS.os/"
  default['yum']['repos']['os']['gpgcheck']                = false
  default['yum']['repos']['os']['enabled']                 = true

  default['yum']['repos']['rhel_updates']['description']   = 'RHEL-$releasever - Updates'
  default['yum']['repos']['rhel_updates']['baseurl']       = "http://artifacts.schubergphilis.com/mrepo/redhat-#{node['platform_version'][0]}-x86_64-weekly/#{node['yum']['snapshot']}/RPMS.updates/"
  default['yum']['repos']['rhel_updates']['gpgcheck']      = false
  default['yum']['repos']['rhel_updates']['enabled']       = true

  default['yum']['repos']['optional']['description']       = 'RHEL-$releasever - Optional'
  default['yum']['repos']['optional']['baseurl']           = "http://artifacts.schubergphilis.com/mrepo/redhat-#{node['platform_version'][0]}-x86_64-weekly/#{node['yum']['snapshot']}/RPMS.optional/"
  default['yum']['repos']['optional']['gpgcheck']          = false
  default['yum']['repos']['optional']['enabled']           = true
end
