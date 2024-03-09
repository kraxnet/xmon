require "whois-parser"

module Xmon
  class Whois < Description
    def initialize(parent, **opts)
      @parent = parent
      @domain = parent.name
      define_attributes([:registrant, :registrar, :expires])
    end

    def fetch(record)
      response = ::Whois.whois(record)
      # only joker.com compatible
      {
        registrar: response.match(/Registrar URL: https:\/\/(.*)/)[1].strip,
        registrant: response.match(/Registrant Organization: (.*)/)[1].strip,
        expiration: response.match(/Registrar Registration Expiration Date: (.*)/)[1].strip,
        status: response.match(/Domain Status: (.*)/)[1].strip
      }
    end

    def check
      checker = fetch(@domain)
      [compare(:status, @status, checker[:status].split(" ").first),
        compare(:registrant, @registrant, checker[:registrant]),
        compare(:registrar, @registrar, checker[:registrar]),
        compare(:expires, @expires, checker[:expiration][0, 10])]
    end
  end
end
