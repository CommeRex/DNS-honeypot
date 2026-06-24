# DNS Honeypot

A DNS amplification honeypot for CSE3000. Listens on UDP port 53, forwards
queries to a real resolver, and logs every request as newline-delimited JSON.

## Setup

```bash
# 1. Install the DNS library
go get github.com/miekg/dns

# 2. Build
go build -o honeypot .

# 3. Run (port 53 requires root on Linux)
sudo ./honeypot
```

For local testing without root, change `Port: 53` to `Port: 5353` in main.go
and query it with:
```bash
dig @127.0.0.1 -p 5353 isc.org ANY
```

## Log format

Each line of `honeypot.jsonl` is one JSON object:

```json
{
  "timestamp":      "2026-05-01T12:34:56.789Z",
  "source_ip":      "1.2.3.4",
  "source_port":    54321,
  "queried_domain": "isc.org.",
  "query_type":     "ANY",
  "edns_payload":   4096,
  "request_size":   44,
  "response_size":  1432
}
```

During a real DDoS attack, `source_ip` is the **victim's spoofed IP**, not
the attacker's IP. This is how we track who is being attacked.

## Dataset

The dataset that was collected during the research project is located at ./analysis/honeypot.jsonl


Link to the project: https://repository.tudelft.nl/record/uuid:9f75a430-1e74-457a-ac3f-67d7f4ba8ddb
