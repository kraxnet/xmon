module Xmon
  module Inventory
    class Validator
      def self.run
        puts "HOSTNAMES"

        dupes = Page["hostname"].map { |a| a["hostname"] }.tally.select { |_k, v| v > 1 }
        puts "  Duplicate hostnames: #{dupes}" if dupes.any?

        Page["hostname"].each do |page|
          domain = page["hostname"].split(".").last(2).join(".")
          puts "  Domain #{domain} not found for #{page["hostname"]}" unless Page["domain"].find { |p| p["name"] == domain }

          [page["address"]].flatten.compact.each do |ip|
            puts "  IP #{ip} not found for #{page["hostname"]}" unless Page["ipv4"].find { |p| p["ip"] == ip }
          end
        end

        puts "DOMAINS"
        dupes = Page["domain"].map { |a| a["name"] }.tally.select { |_k, v| v > 1 }
        puts "  Duplicate domains: #{dupes}" if dupes.any?
      end
    end
  end
end
