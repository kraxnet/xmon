require "whois-parser"

module Xmon
  class Whois < Description
    def fetch(record)
      ::Whois.whois(record)
    end
  end
end
