# frozen_string_literal: true

require "net/http"
require "json"
require "securerandom"
require "time"
require "uri"

# Umrath Worker Handlers for ezrecon
#
# Two-layer architecture:
#
#   Layer 1 (Scan) — this file
#     Commands run network scans and emit raw observation events
#     ("what we measured") to the `recon-scan` bucket.
#     No analysis, no comparison with previous state, just facts.
#
#   Layer 2 (Evaluate) — see umrath_evaluator.rb
#     Command reads raw scan events, compares with previous observations,
#     and emits derived analytical events to the `recon-eval` bucket.
#     This layer is fully replayable — delete eval streams and re-run.
#
# Raw events (Layer 1):
#   DomainScanResult    → recon-scan/DomainScan/{domain_id}
#   HostnameScanResult  → recon-scan/HostnameScan/{hostname_id}
#   TlsScanResult       → recon-scan/TlsScan/{endpoint_id}
#
# Derived events (Layer 2):
#   HostnameAddressChanged, HostnameBecameUnreachable, HostnameRecovered,
#   CertificateChanged, CertificateExpiringSoon, EndpointBecameReachable,
#   EndpointBecameUnreachable, DomainNameserversChanged, DomainExpiringSoon,
#   SharedCertificateDetected
#
# Commands:
#   ezrecon.scan_domains       — DNS NS + RDAP for all inventory domains
#   ezrecon.scan_hostnames     — DNS A-record resolve for all hostnames
#   ezrecon.scan_certificates  — TLS scan for hostnames and IPv4 addresses
#   ezrecon.scan_all           — Generate inventory + all scans in sequence
#   ezrecon.evaluate           — Read raw scans, detect changes, emit derived events
#
module EzreconWorkerHandlers
  SCAN_BUCKET = "recon-scan"

  class << self
    def register(handlers)
      @base_url   = ENV.fetch("UMRATH_URL", "http://127.0.0.1:8080")
      @project_id = ENV.fetch("UMRATH_PROJECT_ID", "ezop")

      handlers.register("ezrecon.scan_domains",      method(:handle_scan_domains))
      handlers.register("ezrecon.scan_hostnames",     method(:handle_scan_hostnames))
      handlers.register("ezrecon.scan_certificates",  method(:handle_scan_certificates))
      handlers.register("ezrecon.scan_all",           method(:handle_scan_all))
      handlers.register("ezrecon.evaluate",           method(:handle_evaluate))
    end

    private

    # ─── Layer 1: Raw Scan Handlers ──────────────────────────────────

    def handle_scan_domains(_command)
      scanner = init_scanner
      scanner.domains

      count = emit_domain_results
      { success: true, result: { "domains_scanned" => count } }
    rescue StandardError => e
      failure_result("scan_domains_failed", e)
    end

    def handle_scan_hostnames(_command)
      scanner = init_scanner
      scanner.hostnames

      count = emit_hostname_results
      { success: true, result: { "hostnames_scanned" => count } }
    rescue StandardError => e
      failure_result("scan_hostnames_failed", e)
    end

    def handle_scan_certificates(_command)
      scanner = init_scanner
      scanner.ipv4_certificates
      scanner.hostname_certificates

      count = emit_tls_results
      { success: true, result: { "endpoints_scanned" => count } }
    rescue StandardError => e
      failure_result("scan_certificates_failed", e)
    end

    def handle_scan_all(_command)
      inventory_dir = ENV.fetch("EZRECON_INVENTORY_DIR") { Dir.pwd }
      output_dir    = ENV.fetch("EZRECON_OUTPUT_DIR") { File.join(inventory_dir, "output") }

      require "xmon"
      Xmon::Inventory::Page.output_dir = output_dir
      Xmon::Inventory::Generator.run(inventory_dir: inventory_dir)

      scanner = Xmon::Inventory::Scanner.new
      scanner.domains
      scanner.asns
      scanner.hostnames
      scanner.ptr_records
      scanner.ipv4_certificates
      scanner.hostname_certificates

      Xmon::Inventory::Page.reload

      domain_count   = emit_domain_results
      hostname_count = emit_hostname_results
      tls_count      = emit_tls_results

      {
        success: true,
        result: {
          "domains_scanned"   => domain_count,
          "hostnames_scanned" => hostname_count,
          "endpoints_scanned" => tls_count,
        },
      }
    rescue StandardError => e
      failure_result("scan_all_failed", e)
    end

    # ─── Layer 2: Evaluate Handler ───────────────────────────────────

    def handle_evaluate(command)
      payload = command.dig("request", "payload") || {}

      require_relative "umrath_evaluator"
      evaluator = EzreconEvaluator.new(
        base_url:        @base_url,
        project_id:      @project_id,
        checkpoint_path: ENV.fetch("EZRECON_EVAL_CHECKPOINT") { ".eval_checkpoint.json" },
        replay:          !!payload["replay"],
      )

      init_scanner # ensure Page.output_dir is set + pages loaded
      stats = evaluator.run

      { success: true, result: stats }
    rescue StandardError => e
      failure_result("evaluate_failed", e)
    end

    # ─── Raw Event Emitters ──────────────────────────────────────────

    def emit_domain_results
      count = 0
      Xmon::Inventory::Page["domain"].each do |page|
        next unless page["nameservers"] # skip unscanned
        append_event(SCAN_BUCKET, "DomainScan", page.id, "DomainScanResult", {
          "domain_name" => page["name"],
          "nameservers" => page["nameservers"],
          "registrant"  => page["registrant"],
          "registrar"   => page["registrar"],
          "expires"     => page["expires"]&.to_s,
          "rdap_status" => page["status"]&.to_s,
          "scanned_at"  => now,
        }.compact)
        count += 1
      end
      count
    end

    def emit_hostname_results
      count = 0
      Xmon::Inventory::Page["hostname"].each do |page|
        addresses = Array(page["address"])
        dns_status = page["status"]&.to_s
        dns_status ||= addresses.any? ? "ok" : "unknown"
        append_event(SCAN_BUCKET, "HostnameScan", page.id, "HostnameScanResult", {
          "hostname"   => page["hostname"],
          "addresses"  => addresses,
          "dns_status" => dns_status,
          "scanned_at" => now,
        }.compact)
        count += 1
      end
      count
    end

    def emit_tls_results
      count = 0

      # Portscan pages (hostname-based TLS scans)
      Xmon::Inventory::Page["portscan"].each do |page|
        append_event(SCAN_BUCKET, "TlsScan", page.id, "TlsScanResult", {
          "ip"             => page["ip"],
          "port"           => page["port"] || 443,
          "hostname"       => page["hostname"],
          "cert_serial"    => page["cert_sn"],
          "cert_subject"   => page["name"],
          "cert_issuer"    => page["issuer"],
          "cert_not_after" => page["cert_not_after"]&.to_s,
          "altnames"       => Array(page["altnames"]),
          "server"         => page["server"],
          "status_code"    => page["status_code"],
          "tls_status"     => page["status"]&.to_s || "unknown",
          "scanned_at"     => now,
        }.compact)
        count += 1
      end

      # IPv4 direct TLS scans (p443_ prefixed fields)
      Xmon::Inventory::Page["ipv4"].each do |page|
        next unless page["p443_status"]
        append_event(SCAN_BUCKET, "TlsScan", "ipv4-#{page.id}-443", "TlsScanResult", {
          "ip"             => page["ip"],
          "port"           => 443,
          "cert_serial"    => page["p443_cert_sn"],
          "cert_subject"   => page["p443_name"],
          "cert_issuer"    => page["p443_issuer"],
          "cert_not_after" => page["p443_cert_not_after"]&.to_s,
          "tls_status"     => page["p443_status"]&.to_s || "unknown",
          "scanned_at"     => now,
        }.compact)
        count += 1
      end

      count
    end

    # ─── Scanner Setup ───────────────────────────────────────────────

    def init_scanner
      require "xmon"

      output_dir = ENV.fetch("EZRECON_OUTPUT_DIR") {
        File.join(ENV.fetch("EZRECON_INVENTORY_DIR") { Dir.pwd }, "output")
      }
      Xmon::Inventory::Page.output_dir = output_dir

      Xmon::Inventory::Scanner.new
    end

    # ─── HTTP Helpers ────────────────────────────────────────────────

    def append_event(bucket, aggregate_type, aggregate_id, event_type, payload)
      uri = URI("#{@base_url}/v1/projects/#{@project_id}/streams/#{bucket}/#{aggregate_type}/#{aggregate_id}/events:append")

      body = {
        events: [{
          event_id:   SecureRandom.uuid,
          event_type: event_type,
          payload:    payload,
          metadata:   { source: "ezrecon", layer: "scan", version: "1.0" },
        }],
      }

      req             = Net::HTTP::Post.new(uri)
      req["Content-Type"] = "application/json"
      req["X-Caller"]     = "ezrecon"
      req.body            = JSON.generate(body)

      http = Net::HTTP.new(uri.host, uri.port)
      http.open_timeout = 5
      http.read_timeout = 10
      http.use_ssl      = uri.scheme == "https"

      response = http.request(req)
      unless response.is_a?(Net::HTTPSuccess)
        raise "Umrath append failed (#{event_type}): HTTP #{response.code} — #{response.body}"
      end
    end

    def failure_result(code, error)
      {
        success: false,
        failure: {
          "code"    => code,
          "message" => error.message,
          "details" => { "error_class" => error.class.name },
        },
      }
    end

    def now
      Time.now.utc.iso8601(3)
    end
  end
end

UMRATH_CUSTOM_HANDLERS = lambda { |handlers|
  EzreconWorkerHandlers.register(handlers)
}
