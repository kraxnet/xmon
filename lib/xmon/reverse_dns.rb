require "dnsruby"

module Xmon
  class ReverseDNS < Description
    def initialize(parent, value = nil)
      if parent
        puts "NEW REVERSE DNS #{value} #{parent.address}"
        @parent = parent
        @address = parent.address
        @hostname = value
      else
        puts "NEW REVERSE DNS #{value}"
      end
    end

    def fetch(record, type = "A")
      puts "fetching #{record} #{type}"
      Dnsruby::Resolver.new.query(record, type).answer.map { |a| a.rdata.to_s }.join
    end

    def check
      [compare(:hostname, @hostname, fetch(@address, "PTR"))]
    end
  end
end
