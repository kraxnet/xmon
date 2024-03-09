# frozen_string_literal: true

require_relative "lib/xmon/version"

Gem::Specification.new do |spec|
  spec.name = "xmon"
  spec.version = Xmon::VERSION
  spec.authors = ["Jiří Kubíček"]
  spec.email = ["jiri.kubicek@kraxnet.cz"]

  spec.summary = "Yet another network monitoring tool"
  spec.description = "Use DSL to describe your network and services, run periodic checks and get notified when something changes."
  spec.homepage = "https://github.com/kraxnet/xmon"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.6.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/kraxnet/xmon.git"
  spec.metadata["changelog_uri"] = "https://github.com/kraxnet/xmon/commits"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (File.expand_path(f) == __FILE__) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "slop"
  spec.add_dependency "whois-parser"
  spec.add_dependency "httparty"
  spec.add_dependency "dnsruby"
  spec.add_dependency "ruby-nmap"
  spec.add_dependency "activesupport", "~> 7.0.8"
  spec.add_dependency "colorize"
  spec.add_dependency "net-ssh"
  spec.add_development_dependency "pry"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
