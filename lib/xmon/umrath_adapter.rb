# frozen_string_literal: true

require "net/http"
require "json"
require "uri"
require "securerandom"

# Umrath Event Store Adapter pro xmon/ezrecon
#
# Tento adaptér se připojuje do xmon scanneru a generuje eventy
# při skenování (místo tichého přepisování frontmatter souborů).
#
# Použití v xmon scanner.rb:
#   require_relative "umrath_adapter"
#   @umrath = XmonUmrath::Adapter.new(
#     base_url: ENV.fetch("UMRATH_URL", "http://localhost:9292"),
#     project_id: ENV.fetch("UMRATH_PROJECT_ID", "ezop")
#   )
#
#   # Po domain skenu:
#   @umrath.domain_scanned(page)
#
#   # Po hostname resolution:
#   @umrath.hostname_resolved(page, previous_addresses)
#
#   # Po IPv4 skenu:
#   @umrath.address_scanned(page, previous_ptr)
#
#   # Po TLS skenu:
#   @umrath.certificate_discovered(page)
#
module XmonUmrath
  class Adapter
    CERT_EXPIRY_WARN_DAYS = 30
    DOMAIN_EXPIRY_WARN_DAYS = 30

    def initialize(base_url:, project_id:, caller_id: "ezrecon", timeout: 5, enabled: true)
      @base_url = base_url
      @project_id = project_id
      @caller_id = caller_id
      @timeout = timeout
      @enabled = enabled
      @stats = { forwarded: 0, errors: 0 }
    end

    attr_reader :stats

    def disable!
      @enabled = false
    end

    def enable!
      @enabled = true
    end

    # ── Domain ─────────────────────────────────────────

    # Voláno po DNS + RDAP skenu domény
    # page = Xmon::Inventory::Page s frontmatter
    def domain_scanned(page)
      fm = page_frontmatter(page)
      domain_id = fm["id"] || page_id(page)
      domain_name = fm["name"]

      append(
        bucket: "recon",
        aggregate_type: "Domain",
        aggregate_id: domain_id,
        event_type: "DomainScanned",
        payload: {
          "domain_id" => domain_id,
          "domain_name" => domain_name,
          "nameservers" => Array(fm["nameservers"]),
          "registrant" => fm["registrant"],
          "registrar" => fm["registrar"],
          "expires" => fm["expires"]&.to_s,
          "status" => fm["status"]&.to_s,
          "scanned_at" => now
        }
      )

      # Zkontrolovat expiraci
      if fm["expires"]
        check_domain_expiry(domain_id, domain_name, fm["expires"].to_s)
      end
    end

    # ── Hostname ───────────────────────────────────────

    # Voláno po DNS A lookup
    def hostname_resolved(page, previous_addresses: nil)
      fm = page_frontmatter(page)
      hostname_id = fm["id"] || page_id(page)

      addresses = case fm["address"]
      when Array then fm["address"]
      when String then [fm["address"]]
      else []
      end

      prev = case previous_addresses
      when Array then previous_addresses
      when String then [previous_addresses]
      else nil
      end

      status = fm["status"]&.to_s || (addresses.empty? ? "nxdomain" : "up")

      append(
        bucket: "recon",
        aggregate_type: "NetworkHost",
        aggregate_id: hostname_id,
        event_type: "HostnameResolved",
        payload: {
          "hostname_id" => hostname_id,
          "hostname" => fm["hostname"],
          "addresses" => addresses,
          "status" => status,
          "previous_addresses" => prev,
          "resolved_at" => now
        }.compact
      )
    end

    # ── IPv4 ───────────────────────────────────────────

    # Voláno po PTR lookup + port 443 probe
    def address_scanned(page, previous_ptr: nil)
      fm = page_frontmatter(page)
      ipv4_id = fm["id"] || page_id(page)

      append(
        bucket: "recon",
        aggregate_type: "NetworkAddress",
        aggregate_id: ipv4_id,
        event_type: "AddressScanned",
        payload: {
          "ipv4_id" => ipv4_id,
          "ip" => fm["ip"],
          "ptr" => fm["ptr"],
          "port_443_status" => fm["p443_status"]&.to_s || "unknown",
          "previous_ptr" => previous_ptr,
          "scanned_at" => now
        }.compact
      )
    end

    # ── PortScan / Certificate ─────────────────────────

    # Voláno po TLS skenu (hostname_certificates / ipv4_certificates)
    def certificate_discovered(page, previous_cert_serial: nil)
      fm = page_frontmatter(page)
      scan_id = fm["id"] || page_id(page)

      payload = {
        "scan_id" => scan_id,
        "ip" => fm["ip"],
        "port" => fm["port"] || 443,
        "hostname" => fm["hostname"],
        "cert_serial" => fm["cert_sn"],
        "cert_subject" => fm["name"],
        "cert_issuer" => fm["issuer"],
        "cert_not_after" => fm["cert_not_after"]&.to_s,
        "altnames" => Array(fm["altnames"]),
        "server" => fm["server"],
        "status_code" => fm["status_code"],
        "discovered_at" => now
      }.compact

      append(
        bucket: "recon",
        aggregate_type: "PortScan",
        aggregate_id: scan_id,
        event_type: "CertificateDiscovered",
        payload: payload
      )

      # Cert changed?
      if previous_cert_serial && previous_cert_serial != fm["cert_sn"]
        append(
          bucket: "recon",
          aggregate_type: "PortScan",
          aggregate_id: scan_id,
          event_type: "CertificateChanged",
          payload: {
            "scan_id" => scan_id,
            "ip" => fm["ip"],
            "port" => fm["port"] || 443,
            "hostname" => fm["hostname"],
            "old_cert_serial" => previous_cert_serial,
            "new_cert_serial" => fm["cert_sn"],
            "new_cert_not_after" => fm["cert_not_after"]&.to_s,
            "changed_at" => now
          }.compact
        )
      end

      # Cert expiring?
      if fm["cert_not_after"]
        check_cert_expiry(scan_id, fm)
      end
    end

    private

    def page_frontmatter(page)
      case page
      when Hash then page
      else
        page.respond_to?(:frontmatter) ? page.frontmatter : page.instance_variable_get(:@frontmatter) || {}
      end
    end

    def page_id(page)
      page.respond_to?(:id) ? page.id : SecureRandom.uuid
    end

    def check_domain_expiry(domain_id, domain_name, expires_str)
      expires = Date.parse(expires_str) rescue return
      days = (expires - Date.today).to_i
      return unless days <= DOMAIN_EXPIRY_WARN_DAYS

      append(
        bucket: "recon",
        aggregate_type: "Domain",
        aggregate_id: domain_id,
        event_type: "DomainExpiring",
        payload: {
          "domain_id" => domain_id,
          "domain_name" => domain_name,
          "expires" => expires_str,
          "days_remaining" => days,
          "detected_at" => now
        }
      )
    end

    def check_cert_expiry(scan_id, fm)
      not_after = Date.parse(fm["cert_not_after"].to_s) rescue return
      days = (not_after - Date.today).to_i
      return unless days <= CERT_EXPIRY_WARN_DAYS

      append(
        bucket: "recon",
        aggregate_type: "PortScan",
        aggregate_id: scan_id,
        event_type: "CertificateExpiring",
        payload: {
          "scan_id" => scan_id,
          "ip" => fm["ip"],
          "hostname" => fm["hostname"],
          "cert_serial" => fm["cert_sn"],
          "cert_not_after" => fm["cert_not_after"].to_s,
          "days_remaining" => days,
          "detected_at" => now
        }.compact
      )
    end

    def now
      Time.now.utc.iso8601(3)
    end

    def append(bucket:, aggregate_type:, aggregate_id:, event_type:, payload:)
      return unless @enabled

      uri = URI("#{@base_url}/v1/projects/#{@project_id}/streams/#{bucket}/#{aggregate_type}/#{aggregate_id}/events:append")

      body = {
        events: [{
          event_id: SecureRandom.uuid,
          event_type: event_type,
          payload: payload,
          metadata: { source: "ezrecon", adapter_version: "1.0" }
        }]
      }

      req = Net::HTTP::Post.new(uri)
      req["Content-Type"] = "application/json"
      req["X-Caller"] = @caller_id
      req.body = JSON.generate(body)

      http = Net::HTTP.new(uri.host, uri.port)
      http.open_timeout = @timeout
      http.read_timeout = @timeout
      http.use_ssl = uri.scheme == "https"

      response = http.request(req)

      unless response.is_a?(Net::HTTPSuccess)
        raise "Umrath append failed: HTTP #{response.code} — #{response.body}"
      end

      @stats[:forwarded] += 1
    rescue => e
      @stats[:errors] += 1
      warn "[XmonUmrath] Error appending #{event_type}: #{e.message}" if $VERBOSE
    end
  end
end
