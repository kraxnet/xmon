module Xmon
  module Inventory
    class Stats
      def self.run
        print_header("domain registrants")
        Page["domain"].group_by { |p| p["registrant"] }.sort_by { |_k, v| v.size }.reverse.each do |registrant, pages|
          print_results(registrant, pages)
        end

        print_header("domain registrars")
        Page["domain"].group_by { |p| p["registrar"] }.sort_by { |_k, v| v.size }.reverse.each do |registrar, pages|
          print_results(registrar, pages)
        end

        print_header("nameservers")
        Page["domain"].group_by { |p| p["nameservers"] }.sort_by { |_k, v| v.size }.reverse.each do |nameservers, pages|
          print_results(nameservers, pages)
        end

        print_header("ASNs")
        Page["ip_range"].group_by { |p| p["asn"] }.sort_by { |_k, v| v.size }.reverse.each do |asn, pages|
          print_results(asn, pages)
        end

        print_header("IP ranges")
        Page["ipv4"].group_by { |p| p["ip_range"] }.sort_by { |_k, v| v.size }.reverse.each do |range, pages|
          ups = pages.select { |p| p["status"] == :up }.size
          puts "#{range || ":unknown"} #{pages.size} (#{ups} up)"
        end

        print_header("IP addresses")
        Page["hostname"].map { |p| p["address"] }.flatten.group_by { |p| p }.sort_by { |_k, v| v.size }.reverse.each do |ip, pages|
          print_results(ip, pages) if pages.size > 1
        end

        print_header("TLS certificates")
        Page["portscan"].group_by { |p| p["cert_sn"] }.sort_by { |_k, v| v.size }.reverse.each do |certificate, pages|
          print_results(certificate, pages)
        end

        print_header("TLS servers")
        Page["portscan"].group_by { |p| p["server"] }.sort_by { |_k, v| v.size }.reverse.each do |server, pages|
          print_results(server, pages)
        end
      end

      def self.print_header(text)
        puts
        puts
        puts text.upcase.chars.join(" ").center(80)
        puts "*" * 80
      end

      def self.print_results(key, values)
        key = [key].flatten.join(", ")
        puts "#{(key || ":unknown").ljust(69)} #{values.size.to_s.rjust(10)}"
      end
    end
  end
end
