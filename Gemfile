source 'https://rubygems.org'

gem 'berkshelf'
gem 'chef', '~> 12.4.0'
gem 'rake'
gem 'vagrant-wrapper'

group :development do
  gem 'guard'
  gem 'guard-kitchen'
  gem 'guard-foodcritic', '>= 1.0'
end

group :integration do
  gem 'test-kitchen', '~> 1.0'
  gem 'kitchen-vagrant'
end

group :unit_tests do
  gem 'rubocop'
  gem 'chefspec'
  gem 'foodcritic'
end
