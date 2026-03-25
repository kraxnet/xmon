require "fileutils"
require "cuid2"
require "httparty"
require "dnsruby"
require "openssl"
require "timeout"

module Xmon
  module Inventory
    class Scanner
      def fetch_ssl(host, name = nil, port = 443)
        ctx = OpenSSL::SSL::SSLContext.new
        begin
          sock = Timeout.timeout(10) { TCPSocket.new(host, port) }
        rescue Timeout::Error
          return { status: :socket_timeout }
        rescue Errno::ENETUNREACH, Errno::EHOSTUNREACH
          return { status: :unreachable }
        rescue IO::TimeoutError
          return { status: :timeout }
        rescue Errno::ECONNREFUSED
          return { status: :refused }
        end

        ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
        ssl.hostname = name if name
        ssl.sync_close = true
        begin
          Timeout.timeout(15) { ssl.connect }
        rescue Timeout::Error
          return { status: :connect_timeout }
        rescue OpenSSL::SSL::SSLError
          return { status: :ssl_error }
        rescue Errno::ECONNRESET
          return { status: :reset }
        end

        cert = ssl.peer_cert
        request = "GET / HTTP/1.1\r\nHost: #{name || host}\r\nConnection: close\r\n\r\n"
        ssl.write request

        begin
          header = ssl.gets("\r\n\r\n")
          body = Timeout.timeout(30) { ssl.read }
        rescue Timeout::Error
          return { status: :read_timeout }
        rescue OpenSSL::SSL::SSLError
          body = ""
        end

        return { status: :no_header } unless header

        status_line, header_rest = header.split("\r\n", 2)
        _protocol, status_code, _status_text = status_line.split(" ", 3)
        cn = cert.subject.to_s.split("/CN=")[1]
        altnames = cert.extensions
          .select { |a| a.oid == "subjectAltName" }
          .flat_map { |a| a.value.split(", ") }
          .map { |a| a.split("DNS:")[1] } - [cn]
        issuer_cn = cert.issuer.to_s.split("/CN=")[1]
        issuer_o  = cert.issuer.to_a.find { |a| a[0] == "O" }&.dig(1)

        {
          cert_sn: cert.serial.to_s(16),
          cert_not_after: cert.not_after.utc.iso8601,
          cert_not_before: cert.not_before.utc.iso8601,
          issuer: issuer_o || issuer_cn,
          status_code: status_code.to_i,
          name: cn,
          altnames: altnames,
          headers: header_rest.split("\r\n").map { |a| a.split(": ", 2) }.to_h,
          body: body
        }
      end

      def ptr_records
        resolver = Dnsruby::Resolver.new
        Page["ipv4"].each do |page|
          puts "PTR #{page["ip"]}"
          begin
            names = resolver.query(page["ip"], "PTR").answer.map { |a| a.rdata.to_s }
            names = names.first if names.size == 1
            page.update(ptr: names).save unless names.empty?
          rescue Dnsruby::NXDomain, Dnsruby::ServFail, Dnsruby::Refused
            puts "  no PTR"
          end
        end
      end

      def asns
        Page["ip_range"].each do |page|
          print "ASN #{page["cidr"]}"
          begin
            response = HTTParty.get("https://rdap.db.ripe.net/ip/#{page["cidr"].split("/").first}")
            data = JSON.parse(response.body, symbolize_names: true)
            asn_str = data.dig(:name) || "unknown"
            page.update("netname" => asn_str).save
            puts " => #{asn_str}"
          rescue => e
            puts " error: #{e.message}"
          end
        end

        Page["ip_range"].group_by { |page| page.frontmatter["asn"] }.each do |asn, pages|
          next unless asn
          FileUtils.mkdir_p("#{Page.output_dir}/asns")
          Page.new(asn, "#{Page.output_dir}/asns").update("asn" => asn, "ranges" => pages.map { |page| page["cidr"] }).save
        end
      end

      def hostnames
        resolver = Dnsruby::Resolver.new
        Page["hostname"].each do |page|
          puts "DNS #{page["hostname"]}"
          previous_addresses = [page["address"]].flatten.compact
          begin
            addresses = resolver.query(page["hostname"], "A").answer
              .select { |a| a.respond_to?(:address) }
              .map { |a| a.address.to_s }.sort
            addresses = addresses.first if addresses.size == 1
            page.update(address: addresses).save unless addresses.empty?

            # Forward to Umrath
            @umrath&.hostname_resolved(page, previous_addresses)
          rescue Dnsruby::NXDomain
            puts "  NXDOMAIN"
            page.update(address: nil, status: :nxdomain).save
          rescue Dnsruby::ServFail, Dnsruby::Refused => e
            puts "  #{e.class}"
          end
        end
      end

      def domains
        Page["domain"].each do |domain|
          puts "NS #{domain["name"]}"
          begin
            resolver = Dnsruby::Resolver.new
            nameservers = resolver.query(domain["name"], "NS").answer
              .map { |a| a.rdata.to_s.chomp(".") }.uniq.sort
            domain.update(nameservers: nameservers).save unless nameservers.empty?
          rescue Dnsruby::NXDomain, Dnsruby::ServFail, Dnsruby::Refused => e
            puts "  #{e.class}"
          end
        end

        Page["domain"].select { |p| p["name"].end_with?(".cz") }.shuffle.each do |domain|
          puts "RDAP #{domain["name"]}"
          begin
            response = HTTParty.get("https://rdap.nic.cz/domain/#{domain["name"]}")
            data = JSON.parse(response.body, symbolize_names: true)
            domain.update(
              registrant: data[:entities].detect { |a| a[:roles] == ["registrant"] }&.dig(:handle),
              registrar: data[:entities].detect { |a| a[:roles] == ["registrar"] }&.dig(:handle),
              nameservers: data[:nameservers]&.map { |a| a[:ldhName] }&.sort,
              expires: data[:events]&.detect { |a| a[:eventAction] == "expiration" }&.dig(:eventDate)&.slice(0, 10),
              status: data[:status]&.map { |s| s.split(" ").join("_") }&.sort&.join("_")&.to_sym
            ).save

            # Forward to Umrath
            @umrath&.domain_scanned(domain)
          rescue JSON::ParserError
            puts "  JSON parse error, skipping"
          rescue => e
            puts "  error: #{e.message}"
          end
        end
      end

      def update_page_ssl(page, ssl, prefix = "")
        if ssl[:status]
          page.update("#{prefix}status" => ssl[:status])
        else
          page.update("#{prefix}status" => :ok)
          page.update("#{prefix}cert_sn" => ssl[:cert_sn])
          page.update("#{prefix}cert_not_after" => ssl[:cert_not_after])
          page.update("#{prefix}cert_not_before" => ssl[:cert_not_before])
          page.update("#{prefix}issuer" => ssl[:issuer])
          page.update("#{prefix}name" => ssl[:name])
          page.update("#{prefix}status_code" => ssl[:status_code])
          page.update("#{prefix}server" => ssl.dig(:headers, "Server"))
          page.update("#{prefix}altnames" => ssl[:altnames]) if ssl[:altnames]&.any?
          page.update("#{prefix}location" => ssl[:headers]["Location"]) if ssl.dig(:headers, "Location")
        end
      end

      def ipv4_certificates
        Page["ipv4"].select { |a| a["status"] == :up }.shuffle.each do |page|
          puts "SSL #{page["ip"]}"
          ssl = fetch_ssl(page["ip"])
          update_page_ssl(page, ssl, "p443_")
          page.save

          # Forward to Umrath
          @umrath&.address_scanned(page, nil)
        end
      end

      def hostname_certificates
        FileUtils.mkdir_p("#{Page.output_dir}/portscans")
        Page["hostname"].shuffle.each do |page|
          puts "SSL #{page["hostname"]} #{[page["address"]].flatten.join(",")}"
          [page["address"]].flatten.compact.each do |ip|
            ps = Page.find { |p| p["_type"] == "portscan" && p["ip"] == ip && p["port"] == 443 && p["hostname"] == page["hostname"] }
            ps ||= Page.new(Cuid2.generate, "#{Page.output_dir}/portscans").update("_type" => "portscan", "ip" => ip, "port" => 443, "hostname" => page["hostname"])
            ssl = fetch_ssl(ip, page["hostname"])
            update_page_ssl(ps, ssl)
            ps.save

            # Forward to Umrath
            @umrath&.certificate_discovered(ps)
          end
        end
      end

      def self.run
        scanner = new

        # Initialize Umrath adapter if configured
        if ENV["UMRATH_URL"]
          require_relative "../umrath_adapter"
          scanner.instance_variable_set(:@umrath, XmonUmrath::Adapter.new(
            base_url: ENV["UMRATH_URL"],
            project_id: ENV.fetch("UMRATH_PROJECT_ID", "ezop")
          ))
          puts "  ✓ Umrath adapter (#{ENV["UMRATH_URL"]})"
        end

        scanner.domains
        scanner.asns
        scanner.hostnames
        scanner.ptr_records
        scanner.ipv4_certificates
        scanner.hostname_certificates

        if scanner.instance_variable_get(:@umrath)
          stats = scanner.instance_variable_get(:@umrath).stats
          puts "\nUmrath: #{stats[:forwarded]} events forwarded, #{stats[:errors]} errors"
        end
      end
    end
  end
end
