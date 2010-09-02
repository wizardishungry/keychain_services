require 'rake/extensiontask'
spec = Gem::Specification.new do |s|
  s.name = 'keychain_services'
  s.version = '0.1.0'
  s.summary = 'Ruby bindings for OS X Keychain Services API'
  s.platform = Gem::Platform::RUBY
  s.extensions = FileList["ext/keychain/extconf.rb"]
end

Rake::GemPackageTask.new(spec) do |pkg|
end

Rake::ExtensionTask.new('keychain', spec)

task :default => :compile

task :test => :compile do
  ruby 'test/test_keychain.rb'
end
