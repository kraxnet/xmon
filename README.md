# Xmon

Network reconnaissance and monitoring tool for ezrecon.

Use DSL to describe your network and services, run periodic checks, and get notified when something changes.

## Architecture

Xmon follows a **two-layer architecture** for Umrath integration:

### Layer 1 — Raw Scan (facts)

Scan commands run network probes and emit raw observation events
("at time T, entity X had state Y") to the `recon-scan` bucket.
No analysis, no comparison — just measured facts.

```
ezrecon.scan_domains  →  DomainScanResult   →  recon-scan/DomainScan/{id}
ezrecon.scan_hostnames → HostnameScanResult  →  recon-scan/HostnameScan/{id}
ezrecon.scan_certificates → TlsScanResult   →  recon-scan/TlsScan/{id}
ezrecon.scan_all      →  all of the above   →  (includes generate + all scans)
```

### Layer 2 — Evaluate (derived, replayable)

The evaluate command reads raw scan streams, replays them chronologically,
compares consecutive observations, and emits derived analytical events
to the `recon-eval` bucket.

```
ezrecon.evaluate  →  reads recon-scan/*  →  emits to recon-eval/*
```

This layer is **fully replayable**: delete the checkpoint file and re-run
to regenerate all derived events. This allows adding new detection rules
and applying them retroactively to the entire scan history.

### Data Flow

```
┌─────────────┐     ┌──────────────────┐     ┌──────────────────────┐
│  ezrecon    │     │  Layer 1: Scan   │     │  recon-scan bucket   │
│  *.yml      │────▶│  (worker cmds)   │────▶│  raw observations    │
│  inventory  │     │                  │     │  (append-only)       │
└─────────────┘     └──────────────────┘     └──────────┬───────────┘
                                                        │
                                             ┌──────────▼───────────┐
                                             │  Layer 2: Evaluate   │
                                             │  (replayable)        │
                                             └──────────┬───────────┘
                                                        │
                                             ┌──────────▼───────────┐
                                             │  recon-eval bucket   │
                                             │  derived insights    │
                                             │  (deletable/replay)  │
                                             └──────────────────────┘
```

## Commands

| Command | Description |
|---------|-------------|
| `ezrecon.scan_domains` | DNS NS + RDAP lookup for all inventory domains |
| `ezrecon.scan_hostnames` | DNS A-record resolution for all hostnames |
| `ezrecon.scan_certificates` | TLS scan for hostnames and IPv4 addresses |
| `ezrecon.scan_all` | Generate pages from inventory + run all scans |
| `ezrecon.evaluate` | Read raw scans → detect changes → emit derived events |

### Evaluate payload options

```json
{ "replay": true }
```

When `replay` is true, the evaluator ignores the checkpoint and
reprocesses all raw events from the beginning.

## Raw Events (Layer 1)

| Event Type | Aggregate | Key Fields |
|------------|-----------|------------|
| `DomainScanResult` | `DomainScan/{id}` | domain_name, nameservers, registrant, registrar, expires |
| `HostnameScanResult` | `HostnameScan/{id}` | hostname, addresses[], dns_status |
| `TlsScanResult` | `TlsScan/{id}` | ip, port, hostname, cert_serial, cert_not_after, tls_status |

## Derived Events (Layer 2)

| Event Type | Aggregate | When |
|------------|-----------|------|
| `DomainNameserversChanged` | `Domain/{id}` | NS set differs from previous scan |
| `DomainExpiringSoon` | `Domain/{id}` | Domain expires within 30 days |
| `HostnameAddressChanged` | `Hostname/{id}` | IP set differs (includes added/removed) |
| `HostnameBecameUnreachable` | `Hostname/{id}` | Was resolvable → NXDOMAIN |
| `HostnameRecovered` | `Hostname/{id}` | Was NXDOMAIN → resolvable |
| `CertificateChanged` | `Endpoint/{id}` | Different cert serial on same endpoint |
| `CertificateExpiringSoon` | `Endpoint/{id}` | Certificate expires within 30 days |
| `EndpointBecameReachable` | `Endpoint/{id}` | Was refused/timeout → TLS reachable |
| `EndpointBecameUnreachable` | `Endpoint/{id}` | Was reachable → refused/timeout |
| `SharedCertificateDetected` | `Certificate/{serial}` | Same cert seen on 2+ endpoints |

## Buckets

| Bucket | Content | Deletable? |
|--------|---------|------------|
| `recon-scan` | Raw scan observations | **No** (source of truth) |
| `recon-eval` | Derived analytical events | **Yes** (replayable from recon-scan) |

## CLI Usage

### Inventory

```bash
# Generate pages from YAML inventory:
bin/xmon generate -i /path/to/ezrecon -o output

# Run scans (updates pages + optionally forwards to Umrath):
UMRATH_URL=http://localhost:8080 bin/xmon scan

# Other CLI commands:
bin/xmon check -d examples/nic.rb
bin/xmon stats
bin/xmon validate
```

### Worker Mode

Set environment variables and let the Umrath worker claim commands:

```bash
export UMRATH_URL=http://127.0.0.1:8080
export UMRATH_PROJECT_ID=ezop
export EZRECON_INVENTORY_DIR=/path/to/ezrecon
export EZRECON_OUTPUT_DIR=/path/to/ezrecon/output
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `UMRATH_URL` | `http://127.0.0.1:8080` | Umrath server URL |
| `UMRATH_PROJECT_ID` | `ezop` | Umrath project ID |
| `EZRECON_INVENTORY_DIR` | `$PWD` | Path to ezrecon YAML files |
| `EZRECON_OUTPUT_DIR` | `$EZRECON_INVENTORY_DIR/output` | Path to generated pages |
| `EZRECON_EVAL_CHECKPOINT` | `.eval_checkpoint.json` | Evaluator checkpoint file |

## Development

After checking out the repo, run `bin/setup` to install dependencies. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
