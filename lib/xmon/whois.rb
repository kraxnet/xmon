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
      [Xmon.compare(@status, checker[:status].split(" ").first, self),
        Xmon.compare(@registrant, checker[:registrant], self),
        Xmon.compare(@registrar, checker[:registrar], self),
        Xmon.compare(@expires, checker[:expiration][0, 10], self)]
    end
  end
end
