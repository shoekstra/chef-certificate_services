require 'foodcritic'
require 'highline/import'
require 'rspec/core/rake_task'
require 'rubocop/rake_task'

desc 'Run RuboCop style and lint checks'
RuboCop::RakeTask.new(:rubocop) do |t|
  t.options = ['-D']
end

desc 'Run Foodcritic lint checks'
FoodCritic::Rake::LintTask.new(:foodcritic) do |t|
  t.options = { fail_tags: ['any'] }
end

desc 'Run ChefSpec examples'
RSpec::Core::RakeTask.new(:spec)

desc 'Run all tests'
task test: [:rubocop, :foodcritic, :spec]
task default: [:test]

namespace 'readme' do
  desc 'Generate all sections'
  task all: [:requirements, :attributes, :recipes, :testing, :authors, :toc]

  desc 'Generate attributes section'
  task :attributes do
    confirm = ask('Generating the attributes section will overwrite currently described attributes; continue? [Y/N] ') { |yn| yn.limit = 1, yn.validate = /[yn]/i }
    readme_attributes if confirm.downcase == 'y'
  end

  desc 'Generate authors section'
  task :authors do
    readme_authors
  end

  desc 'Generate dependencies section'
  task :depends do
    readme_depends
  end

  desc 'Generate supported platforms section'
  task :platforms do
    readme_platforms
  end

  desc 'Generate testing section'
  task :testing do
    readme_testing
  end

  desc 'Generate requirements section (alias for readme::platforms and readme::depends)'
  task requirements: [:depends, :platforms]

  desc 'Generate table of contents'
  task :toc do
    readme_toc
  end

  desc 'Generate recipes section'
  task :recipes do
    confirm = ask('Generating the recipes section will overwrite currently described recipes; continue? [Y/N] ') { |yn| yn.limit = 1, yn.validate = /[yn]/i }
    readme_recipes if confirm.downcase == 'y'
  end
end

begin
  require 'kitchen/rake_tasks'
  Kitchen::RakeTasks.new

  desc 'Alias for kitchen:all'
  task integration: 'kitchen:all'

  task test: [:integration]
rescue LoadError
  puts '>>>>> Kitchen gem not loaded, omitting tasks' unless ENV['CI']
end

private

class String
  def integer?
    self.gsub!(/\_/, '')
    self.to_i.to_s == self
  end
end

def metadata_cookbook_name
  metadata = File.read('metadata.rb').split(/\n/)

  cookbook = metadata.grep(/name/).first
  cookbook = cookbook.gsub(/name\s+/, '').delete("'")

  cookbook
end

def metadata_recipe_description(recipe)
  metadata = File.read('metadata.rb').split(/\n/)
  recipes = metadata.grep(/recipe/)

  if recipes.grep(/#{recipe}/).empty?
    description = 'TODO: *Explain what the recipe does here*'
  else
    description = recipes.grep(/#{recipe}/).first.split(',')[-1]
    description = description.delete('\"\'').strip!
  end

  description
end

def readme_replace(start, finish, replace)
  readme = File.read('README.md')

  new = readme.gsub(/#{start}(.*)#{finish}/m, replace.join("\n"))

  File.open('README.md', 'w') { |file| file.write(new) }
end

def readme_attributes
  attributes = []

  Dir.glob('attributes/*.rb').each do |attribute_file|
    File.read(attribute_file).split("\n").each do |line|
      next if line.match(/#/)
      next if line.empty?
      attributes << line
    end
  end

  attributes.sort!

  cookbook_attributes = []
  attributes.each { |attribute| cookbook_attributes << attribute[/['"](.*?)['"]/].delete("'") }
  cookbook_attributes = cookbook_attributes.uniq.sort

  replace = []
  replace << '## Attributes'
  replace << ''
  replace << 'Attributes in this cookbook:'
  replace << ''
  replace << '<table>'
  replace << '  <tr>'
  replace << '    <th>Key</th>'
  replace << '    <th>Type</th>'
  replace << '    <th>Description</th>'
  replace << '    <th>Default</th>'
  replace << '  </tr>'

  attributes.grep(/#{metadata_cookbook_name}/).each do |attribute|
    attribute.sub!(/^\w+/, '')
    key, value = attribute.split(/\s+=\s+/)
    replace << '  <tr>'
    replace << "    <td><tt>#{key}</tt></td>"

    case value
    when String
      if value.integer?
        replace << '    <td>Int</td>'
      else
        replace << '    <td>String</td>'
      end
    when TrueClass
      replace << '    <td>Bool</td>'
    when FalseClass
      replace << '    <td>Bool</td>'
    when Array
      replace << '    <td>Array</td>'
    when Fixnum
      replace << '    <td>Int</td>'
    else
      replace << '    <td>String / Bool / Array / Int</td>'
    end

    case key
    when /terraform/i
      replace << '    <td>This attribute is populated via Terraform</td>'
    else
      replace << '    <td>Some info about the attribute</td>'
    end
    replace << "    <td><tt>#{value.delete("'")}</tt></td>"
    replace << '  </tr>'
  end

  replace << '</table>'
  replace << ''

  cookbook_attributes.delete(metadata_cookbook_name)

  cookbook_attributes.each do |cookbook_attribute|
    replace << "Attributes set for the `#{cookbook_attribute}` cookbook:"
    replace << ''
    replace << '<table>'
    replace << '  <tr>'
    replace << '    <th>Key</th>'
    replace << '    <th>Type</th>'
    replace << '    <th>Description</th>'
    replace << '    <th>Default</th>'
    replace << '  </tr>'

    attributes.grep(/#{cookbook_attribute}/).each do |attribute|
      attribute.sub!(/^\w+/, '')
      key, value = attribute.split(/\s+=\s+/)
      replace << '  <tr>'
      replace << "    <td><tt>#{key}</tt></td>"
      case value
      when String
        if value.integer?
          replace << '    <td>Int</td>'
        else
          replace << '    <td>String</td>'
        end
      when TrueClass
        replace << '    <td>Bool</td>'
      when FalseClass
        replace << '    <td>Bool</td>'
      when Array
        replace << '    <td>Array</td>'
      when Fixnum
        replace << '    <td>Int</td>'
      else
        replace << '    <td>String / Bool / Array / Int</td>'
      end
      replace << '    <td>Some info about the attribute</td>'
      replace << "    <td><tt>#{value.delete("'")}</tt></td>"
      replace << '  </tr>'
    end

    replace << '</table>'
    replace << ''
  end

  replace << '## Recipes'
  replace << ''

  readme_replace('## Attributes', 'Recipes', replace)
end

def readme_authors
  replace = []
  replace << '## License and Author'
  replace << ''
  replace << 'Authors and contributors:'
  replace << ''

  `git log --format='%aN <%aE>' | sort -u`.split(/\n/).each do |author|
    replace << "* #{author}"
  end

  replace << ''
  replace << 'Copyright (c) 2015, Schuberg Philis, All Rights Reserved.'
  replace << ''
  replace << '## Contributing'

  replace_start = '## License and Author'
  replace_end = 'Contributing'

  readme_replace(replace_start, replace_end, replace)
end

def readme_depends
  depends = []
  File.read('metadata.rb').split(/\n/).grep(/depends/i).each do |dependency|
    next if dependency[/^\#/]
    depends << dependency
  end

  replace = []
  if depends.empty?
    replace << '### Cookbooks'
    replace << ''
    replace << 'This cookbook does not depend on any other cookbooks.'
    replace << ''
    replace << '## Usage'
  else
    replace << '### Cookbooks'
    replace << ''
    replace << 'This cookbook depends upon:'
    replace << ''

    cookbooks = []
    depends.each do |depend|
      depend = depend.delete("'").gsub(/depends/, '').split(',')

      cookbook = depend[0].strip
      version = depend[1].split(' ')[-1].strip

      if cookbook.match(/^sbp_/)
        cookbook = "[#{cookbook}](https://supermarket.schubergphilis.com/cookbooks/#{cookbook})"
      else
        cookbook = "[#{cookbook}](https://supermarket.chef.io/cookbooks/#{cookbook})"
      end

      cookbooks << "\* #{cookbook} (#{version})"
    end

    cookbooks.sort.each do |cookbook|
      replace << cookbook
    end

    replace << ''
    replace << '## Usage'
  end

  replace_start = '### Cookbooks'
  replace_end = 'Usage'

  readme_replace(replace_start, replace_end, replace)
end

def readme_recipe(recipes, type)
  recipes = [recipes] unless recipes.is_a?(Array)

  arr = []
  arr << "### #{type.capitalize} Recipes"
  arr << ''

  recipes.each do |recipe|
    arr << "#### `#{recipe}`"
    arr << ''
    arr << metadata_recipe_description(recipe)
    arr << ''
  end

  arr
end

def readme_recipes
  cookbook = metadata_cookbook_name

  recipes = Dir.glob('recipes/*')
  recipes.map! { |r| r.gsub('recipes/', '').gsub('.rb', '') }

  public_recipes = []
  private_recipes = []

  recipes.each do |recipe|
    if recipe.match(/^_/)
      private_recipes << "#{cookbook}::#{recipe}"
    else
      public_recipes << "#{cookbook}::#{recipe}"
    end
  end

  replace = []
  replace << '## Recipes'
  replace << ''
  replace.concat(readme_recipe(public_recipes, 'public')) unless public_recipes.empty?
  replace.concat(readme_recipe(private_recipes, 'private')) unless private_recipes.empty?
  replace << '## Versioning'

  replace_start = File.readlines('README.md').grep(/^\#*\s+(.*)Recipes$/).first.chomp
  replace_end = 'Versioning$'

  readme_replace(replace_start, replace_end, replace)
end

def readme_platforms
  metadata = File.read('metadata.rb').split(/\n/)

  replace = []
  replace << '### Platforms'
  replace << ''
  replace << 'This cookbook supports:'
  replace << ''

  supports = []
  metadata.grep(/supports/i).each do |line|
    platform = case line.split(/\s+/)[-1].delete("'")
               when /centos/i
                 'CentOS'
               when /redhat/i
                 'RedHat'
               else
                 line.split(/\s+/)[-1].delete("'").capitalize
               end

    supports << "\* #{platform}"
  end

  supports.sort.each do |platform|
    replace << platform
  end

  replace << ''
  replace << '### Cookbooks'

  replace_start = '### Platforms'
  replace_end = 'Cookbooks'

  readme_replace(replace_start, replace_end, replace)
end

def readme_toc
  readme = File.read('README.md').split(/\n/)
  topics = readme.grep(/^(##\s|###\s)/)

  count = 1
  replace = []

  replace << '## Table of contents'
  replace << ''

  topics.each do |topic|
    next if topic.match(/Table of contents/)

    if topic.match(/^##\s/)
      entry = topic.gsub(/^##\s/, '')
      link = entry.downcase.gsub(/\s/, '-')

      replace << "#{count}. [#{entry}](\##{link})"
      count += 1
    else
      entry = topic.gsub(/^###\s/, '')
      link = entry.downcase.gsub(/\s/, '-')

      replace << "    * [#{entry}](\##{link})"
    end
  end

  replace << ''
  replace << '## Requirements'

  replace_start = '## Table of contents'
  replace_end = 'Requirements'

  readme_replace(replace_start, replace_end, replace)
end

def readme_testing
  replace = []
  replace << '## Testing'
  replace << ''

  `rake -T`.split(/\n/).each do |rake_task|
    replace << "    #{rake_task}" unless rake_task[/readme/]
  end

  replace << ''
  replace << '## License and Author'

  replace_start = '## Testing'
  replace_end = 'License and Author'

  readme_replace(replace_start, replace_end, replace)
end
