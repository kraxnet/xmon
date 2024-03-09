# frozen_string_literal: true

require "pry"
require "colorize"
# require 'net/protocol'

require_relative "xmon/version"
require_relative "xmon/descriptions"

require_relative "xmon/tcp"
require_relative "xmon/ssl"
require_relative "xmon/dns"
require_relative "xmon/rdap"

module Xmon
  class Error < StandardError; end

  def self.compare(a, b)
    if a == b
      [:ok, a]
    else
      [:fail, a, b]
    end
  end

  def self.print_results(results)
    # puts "Results: #{results.inspect}".colorize(:blue)
    results.each do |res|
      res.each do |r|
        if r.is_a?(Array)
          if r[0] == :ok
            puts "OK: #{r[1]}".colorize(:green)
          else
            puts "FAIL: #{r[1]} != #{r[2]}".colorize(:red)
          end
        end
      end
    end
  end

  def self.load(file)
    d = Description.new
    d.instance_eval(File.read(file))
    d
  end
end
