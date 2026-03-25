# frozen_string_literal: true

require "net/http"
require "json"
require "securerandom"
require "time"
require "uri"
require "date"
require "set"

# Replayable evaluator for ezrecon raw scan events.
#
# Reads raw observation events from `recon-scan` bucket,
# replays them chronologically, tracks entity state, and emits
# derived analytical events to `recon-eval` bucket whenever
# a meaningful change is detected.
#
# The evaluator is a pure function over the raw scan stream:
#
#   f(raw_scan_events[0..N]) → derived_events[0..M]
#
# Replay procedure:
#   1. Delete the .eval_checkpoint.json file (or pass replay: true)
#   2. Run ezrecon.evaluate
#   3. Evaluator reads ALL raw events from the beginning
#   4. Rebuilds state, re-emits all derived events
#
# This allows adding new detection rules and applying them
# retroactively to the entire scan history.
#
# Derived events:
#
#   Domain:
#     DomainNameserversChanged  — NS set differs from previous scan
#     DomainExpiringSoon        — domain expires within threshold
#
#   Hostname:
#     HostnameAddressChanged    — IP address set differs (added/removed)
#     HostnameBecameUnreachable — was resolvable, now NXDOMAIN
#     HostnameRecovered         — was NXDOMAIN, now resolvable
#
#   Endpoint (TLS):
#     CertificateChanged        — different cert serial on same endpoint
#     CertificateExpiringSoon   — cert expires within threshold
#     EndpointBecameReachable   — was refused/timeout, now accessible
#     EndpointBecameUnreachable — was accessible, now refused/timeout
#
#   Certificate (cross-entity):
#     SharedCertificateDetected — same cert serial seen on multiple endpoints
#
class EzreconEvaluator
  SCAN_BUCKET = "recon-scan"
  EVAL_BUCKET = "recon-eval"

  CERT_EXPIRY_WARN_DAYS   = 30
  DOMAIN_EXPIRY_WARN_DAYS = 30

  REACHABLE_STATUSES   = %w[ok].freeze
  UNREACHABLE_STATUSES = %w[refused timeout socket_timeout unreachable
                            connect_timeout ssl_error reset read_timeout
                            no_header].freeze

  def initialize(base_url:, project_id:, checkpoint_path: ".eval_checkpoint.json", replay: false)
    @base_url        = base_url
    @project_id      = project_id
    @checkpoint_path = checkpoint_path
    @replay          = replay
    @checkpoint      = replay ? {} : load_checkpoint
    @stats           = Hash.new(0)
    @cert_endpoints  = Hash.new { |h, k| h[k] = Set.new }
  end

  attr_reader :stats

  def run
    evaluate_domains
    evaluate_hostnames
    evaluate_tls_endpoints
    detect_shared_certificates
    save_checkpoint

    @stats.transform_keys(&:to_s).merge(
      "checkpoint_path" => @checkpoint_path,
      "replay"          => @replay,
    )
  end

  private

  # ─── Domain Evaluation ───────────────────────────────────────────

  def evaluate_domains
    Xmon::Inventory::Page["domain"].each do |page|
      stream_key = "DomainScan/#{page.id}"
      events = read_stream(SCAN_BUCKET, "DomainScan", page.id)
      next if events.empty?

      already_processed = @checkpoint[stream_key] || 0
      state = {}

      events.each_with_index do |event, i|
        p = event["payload"]
        old_ns = state[:nameservers]

        state[:nameservers] = p["nameservers"]
        state[:registrar]   = p["registrar"]
        state[:expires]     = p["expires"]

        next if i < already_processed

        # Nameservers changed
        if old_ns && p["nameservers"] && old_ns.sort != Array(p["nameservers"]).sort
          emit_eval("Domain", page.id, "DomainNameserversChanged", {
            "domain_name"     => p["domain_name"],
            "old_nameservers" => old_ns,
            "new_nameservers" => p["nameservers"],
            "source_event_id" => event["event_id"],
            "detected_at"     => now,
          })
        end

        # Domain expiring
        if p["expires"]
          days = safe_days_until(p["expires"])
          if days && days <= DOMAIN_EXPIRY_WARN_DAYS
            emit_eval("Domain", page.id, "DomainExpiringSoon", {
              "domain_name"     => p["domain_name"],
              "expires"         => p["expires"],
              "days_remaining"  => days,
              "source_event_id" => event["event_id"],
              "detected_at"     => now,
            })
          end
        end
      end

      @checkpoint[stream_key] = events.length
    end
  end

  # ─── Hostname Evaluation ─────────────────────────────────────────

  def evaluate_hostnames
    Xmon::Inventory::Page["hostname"].each do |page|
      stream_key = "HostnameScan/#{page.id}"
      events = read_stream(SCAN_BUCKET, "HostnameScan", page.id)
      next if events.empty?

      already_processed = @checkpoint[stream_key] || 0
      state = { addresses: Set.new, dns_status: nil }

      events.each_with_index do |event, i|
        p = event["payload"]
        old_addresses = state[:addresses].dup
        old_status    = state[:dns_status]

        new_addresses = Set.new(Array(p["addresses"]))
        new_status    = p["dns_status"]

        state[:addresses]  = new_addresses
        state[:dns_status] = new_status

        next if i < already_processed

        # Address changed
        if old_addresses.any? && new_addresses != old_addresses
          added   = (new_addresses - old_addresses).to_a.sort
          removed = (old_addresses - new_addresses).to_a.sort
          emit_eval("Hostname", page.id, "HostnameAddressChanged", {
            "hostname"          => p["hostname"],
            "added_addresses"   => added,
            "removed_addresses" => removed,
            "current_addresses" => new_addresses.to_a.sort,
            "source_event_id"   => event["event_id"],
            "detected_at"       => now,
          })
        end

        # Became unreachable (had addresses, now NXDOMAIN)
        if old_status && old_status != "nxdomain" && new_status == "nxdomain"
          emit_eval("Hostname", page.id, "HostnameBecameUnreachable", {
            "hostname"           => p["hostname"],
            "previous_addresses" => old_addresses.to_a.sort,
            "source_event_id"    => event["event_id"],
            "detected_at"        => now,
          })
        end

        # Recovered (was NXDOMAIN, now has addresses)
        if old_status == "nxdomain" && new_status != "nxdomain" && new_addresses.any?
          emit_eval("Hostname", page.id, "HostnameRecovered", {
            "hostname"        => p["hostname"],
            "addresses"       => new_addresses.to_a.sort,
            "source_event_id" => event["event_id"],
            "detected_at"     => now,
          })
        end
      end

      @checkpoint[stream_key] = events.length
    end
  end

  # ─── TLS Endpoint Evaluation ─────────────────────────────────────

  def evaluate_tls_endpoints
    endpoint_ids = collect_tls_endpoint_ids

    endpoint_ids.each do |endpoint_id|
      stream_key = "TlsScan/#{endpoint_id}"
      events = read_stream(SCAN_BUCKET, "TlsScan", endpoint_id)
      next if events.empty?

      already_processed = @checkpoint[stream_key] || 0
      state = { cert_serial: nil, tls_status: nil }

      events.each_with_index do |event, i|
        p = event["payload"]
        old_serial = state[:cert_serial]
        old_status = state[:tls_status]

        new_serial = p["cert_serial"]
        new_status = p["tls_status"]

        state[:cert_serial] = new_serial if new_serial
        state[:tls_status]  = new_status

        # Track cert → endpoint mapping (always, for shared cert detection)
        @cert_endpoints[new_serial] << endpoint_id if new_serial

        next if i < already_processed

        # Certificate changed
        if old_serial && new_serial && old_serial != new_serial
          emit_eval("Endpoint", endpoint_id, "CertificateChanged", {
            "ip"              => p["ip"],
            "port"            => p["port"],
            "hostname"        => p["hostname"],
            "old_cert_serial" => old_serial,
            "new_cert_serial" => new_serial,
            "source_event_id" => event["event_id"],
            "detected_at"     => now,
          }.compact)
        end

        # Endpoint reachability change
        was_reachable   = REACHABLE_STATUSES.include?(old_status)
        is_reachable    = REACHABLE_STATUSES.include?(new_status)
        was_unreachable = UNREACHABLE_STATUSES.include?(old_status)
        is_unreachable  = UNREACHABLE_STATUSES.include?(new_status)

        if was_reachable && is_unreachable
          emit_eval("Endpoint", endpoint_id, "EndpointBecameUnreachable", {
            "ip"              => p["ip"],
            "port"            => p["port"],
            "hostname"        => p["hostname"],
            "tls_status"      => new_status,
            "source_event_id" => event["event_id"],
            "detected_at"     => now,
          }.compact)
        elsif was_unreachable && is_reachable
          emit_eval("Endpoint", endpoint_id, "EndpointBecameReachable", {
            "ip"              => p["ip"],
            "port"            => p["port"],
            "hostname"        => p["hostname"],
            "source_event_id" => event["event_id"],
            "detected_at"     => now,
          }.compact)
        end

        # Certificate expiring
        if p["cert_not_after"]
          days = safe_days_until(p["cert_not_after"])
          if days && days <= CERT_EXPIRY_WARN_DAYS
            emit_eval("Endpoint", endpoint_id, "CertificateExpiringSoon", {
              "ip"              => p["ip"],
              "port"            => p["port"],
              "hostname"        => p["hostname"],
              "cert_serial"     => new_serial,
              "cert_not_after"  => p["cert_not_after"],
              "days_remaining"  => days,
              "source_event_id" => event["event_id"],
              "detected_at"     => now,
            }.compact)
          end
        end
      end

      @checkpoint[stream_key] = events.length
    end
  end

  # ─── Cross-entity: Shared Certificates ───────────────────────────

  def detect_shared_certificates
    @cert_endpoints.each do |serial, endpoints|
      next unless serial
      next if endpoints.size < 2

      emit_eval("Certificate", serial, "SharedCertificateDetected", {
        "cert_serial"    => serial,
        "endpoint_count" => endpoints.size,
        "endpoints"      => endpoints.to_a.sort,
        "detected_at"    => now,
      })
    end
  end

  # ─── Entity Discovery ─────────────────────────────────────────────

  def collect_tls_endpoint_ids
    ids = []

    # Portscan pages (hostname-based TLS)
    Xmon::Inventory::Page["portscan"].each { |p| ids << p.id }

    # IPv4 direct scans (synthetic IDs matching worker handler convention)
    Xmon::Inventory::Page["ipv4"].each do |p|
      ids << "ipv4-#{p.id}-443" if p["p443_status"]
    end

    ids
  end

  # ─── HTTP Helpers ──────────────────────────────────────────────────

  def read_stream(bucket, aggregate_type, aggregate_id)
    events   = []
    position = 0

    loop do
      uri = URI("#{@base_url}/v1/projects/#{@project_id}/streams/#{bucket}/#{aggregate_type}/#{aggregate_id}/events?after_position=#{position}&limit=500")

      response = http_get(uri)
      return events if response.code == "404"

      unless response.is_a?(Net::HTTPSuccess)
        raise "Read stream failed (#{bucket}/#{aggregate_type}/#{aggregate_id}): HTTP #{response.code}"
      end

      data  = JSON.parse(response.body)
      batch = data["events"] || []
      break if batch.empty?

      events.concat(batch)
      position = data["next_position"] || (position + batch.length)
      break if batch.length < 500
    end

    events
  end

  def emit_eval(aggregate_type, aggregate_id, event_type, payload)
    uri = URI("#{@base_url}/v1/projects/#{@project_id}/streams/#{EVAL_BUCKET}/#{aggregate_type}/#{aggregate_id}/events:append")

    body = {
      events: [{
        event_id:   SecureRandom.uuid,
        event_type: event_type,
        payload:    payload,
        metadata:   { source: "ezrecon-evaluator", layer: "eval", version: "1.0" },
      }],
    }

    response = http_post(uri, body)
    unless response.is_a?(Net::HTTPSuccess)
      raise "Eval append failed (#{event_type}): HTTP #{response.code} — #{response.body}"
    end

    @stats[event_type] = (@stats[event_type] || 0) + 1
  end

  def http_get(uri)
    req = Net::HTTP::Get.new(uri)
    req["X-Caller"] = "ezrecon-evaluator"

    http = Net::HTTP.new(uri.host, uri.port)
    http.open_timeout = 10
    http.read_timeout = 30
    http.use_ssl      = uri.scheme == "https"
    http.request(req)
  end

  def http_post(uri, body)
    req = Net::HTTP::Post.new(uri)
    req["Content-Type"] = "application/json"
    req["X-Caller"]     = "ezrecon-evaluator"
    req.body            = JSON.generate(body)

    http = Net::HTTP.new(uri.host, uri.port)
    http.open_timeout = 5
    http.read_timeout = 10
    http.use_ssl      = uri.scheme == "https"
    http.request(req)
  end

  # ─── Checkpoint Management ─────────────────────────────────────────

  def load_checkpoint
    return {} unless File.exist?(@checkpoint_path)
    JSON.parse(File.read(@checkpoint_path))
  rescue JSON::ParserError
    {}
  end

  def save_checkpoint
    File.write(@checkpoint_path, JSON.pretty_generate(@checkpoint))
  end

  # ─── Utilities ─────────────────────────────────────────────────────

  def safe_days_until(date_str)
    (Date.parse(date_str.to_s) - Date.today).to_i
  rescue ArgumentError, TypeError
    nil
  end

  def now
    Time.now.utc.iso8601(3)
  end
end
