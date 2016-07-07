source 'https://supermarket.getchef.com'

cookbook 'pspki', git: 'https://github.schubergphilis.com/shoekstra/chef-pspki.git', branch: 'develop'

metadata

group :integration do
  cookbook 'certificate_services_test', path: './test/fixtures/cookbooks/certificate_services_test'
end
