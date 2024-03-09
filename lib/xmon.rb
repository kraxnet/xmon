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

  def self.compare(a, b, info = "UNK")
    if a == b
      [:ok, info, a].compact
    else
      [:fail, info, a, b].compact
    end
  end

  def self.print_results(results)
    # puts "Results: #{results.inspect}".colorize(:blue)
    results.each do |res|
      res.each do |r|
        if r.is_a?(Array)
          friendly_name = if r[1].respond_to?(:parent)
            [r[1].class.to_s.split("::").last, r[1].parent.friendly_name].join("/")
          else
            r[1].class.to_s
          end
          if r[0] == :ok
            puts "OK [#{friendly_name}]: #{r[2]}".colorize(:green)
          else
            puts "FAIL: [#{friendly_name}]: #{r[2]} != #{r[3]}".colorize(:red)
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
