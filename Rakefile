require 'rake/extensiontask'
Rake::ExtensionTask.new('keychain')

task :default => :compile

task :test => :compile do
  ruby 'test/test_keychain.rb'
end
