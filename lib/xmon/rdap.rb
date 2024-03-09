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
        expires: response[:events].detect { |a| a[:eventAction] == "expiration" }[:eventDate][0, 10],
        status: response[:status].map { |s| s.split(" ").join("_") }.sort.join("_").to_sym
      }
    end

    def check
      checker = fetch(@domain)
      [compare(:status, @status, checker[:status]),
        compare(:registrant, @registrant, checker[:registrant]),
        compare(:registrar, @registrar, checker[:registrar]),
        compare(:expires, @expires, checker[:expires])]
    end
  end
end
