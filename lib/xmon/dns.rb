require "dnsruby"

module Xmon
  class DNS < Description
    def initialize(parent)
      @parent = parent
      @domain = parent.name
      define_attributes([:nameservers, :records, :dnssec])
    end

    def record(name, type, value)
      @records ||= []
      @records << {name: name, type: type, value: value}
    end

    def fetch(record, type = "A")
      Dnsruby::Resolver.new.query(record, type).answer.map { |a| a.respond_to?(:address) ? a.address : a.rdata }.flatten.map(&:to_s).sort
    end

    def check
      r = [Xmon.compare(@nameservers, fetch(@domain, "NS"), self)]

      @records.each do |record|
        r << Xmon.compare(record[:value], fetch(record[:name] + "." + @domain, record[:type].to_s.upcase).sort.join(","), self)
      end
      r
    end
  end
end
