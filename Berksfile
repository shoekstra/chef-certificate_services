source 'https://supermarket.getchef.com'
source 'https://supermarket.schubergphilis.com'

metadata

cookbook 'windows', git: 'https://github.com/shoekstra/chef-windows.git', branch: 'windows_certificate_matchers'

group :integration do
  cookbook 'certificate_services_test', path: './test/fixtures/cookbooks/certificate_services_test'
end
