guard :rspec, cmd: 'chef exec rspec', all_on_start: false do
  watch(%r{^spec/unit/*/(.+)_spec\.rb$})

  watch(%r{^recipes/(.+)\.rb$}) do |m|
    "spec/unit/recipes/#{m[1]}_spec.rb"
  end

  watch(%r{^resources/install.rb$}) do |_m|
    'spec/unit/recipes/standalone_root_ca_spec.rb'
    'spec/unit/recipes/enterprise_subordinate_ca_spec.rb'
  end

  watch(%r{^templates/default/CAPolicy.inf.erb$}) do |_m|
    'spec/unit/recipes/standalone_root_ca_spec.rb'
    'spec/unit/recipes/enterprise_subordinate_ca_spec.rb'
  end
end
