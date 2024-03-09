require "dnsruby"

module Xmon
  class ReverseDNS < Description
    def initialize(parent, value = nil)
      @parent = parent
      @address = parent.address
      @hostname = value
    end

    def fetch(record, type = "A")
      Dnsruby::Resolver.new.query(record, type).answer.map { |a| a.rdata.to_s }.join
    end

    def check
      [compare(:hostname, @hostname, fetch(@address, "PTR"))]
    end
  end
end
