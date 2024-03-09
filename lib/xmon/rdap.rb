require "httparty"

module Xmon
  class RDAP < Description
    def initialize(parent, **opts)
      @parent = parent
      @domain = parent.name
      define_attributes([:registrant, :registrar, :expires])
    end

    def fetch(record)
      response = HTTParty.get("https://rdap.nic.cz/domain/#{record}")
      response = JSON.parse(response.body, symbolize_names: true)
      {
        registrant: response[:entities].detect { |a| a[:roles] == ["registrant"] }[:handle],
        registrar: response[:entities].detect { |a| a[:roles] == ["registrar"] }[:handle],
        nameservers: response[:nameservers].map { |a| a[:ldhName] }.sort,
        expiration: response[:events].detect { |a| a[:eventAction] == "expiration" }[:eventDate],
        status: response[:status].map { |s| s.split(" ").join("_") }.sort.join("_").to_sym
      }
    end

    def check
      checker = fetch(@domain)
      [Xmon.compare(@status, checker[:status], self),
        Xmon.compare(@registrant, checker[:registrant], self),
        Xmon.compare(@registrar, checker[:registrar], self),
        Xmon.compare(@expires, checker[:expiration][0, 10], self)]
    end
  end
end
