# Changelog

All notable changes to this project are recorded here. The format follows
Keep a Changelog, and the project uses semantic versioning.

## [0.1.0] - 2025

### Added

* First public release.
* A pcap and pcapng reader written on the standard library, including support
  for snaplen truncated captures.
* Decoders for Ethernet, Linux cooked capture, raw IP, IPv4 and IPv6, and for
  TCP, UDP, and ICMP.
* Application parsing for DNS queries and answers, the TLS client hello server
  name, and plaintext HTTP requests.
* Flow aggregation with direction, byte counts, and connection state, plus a
  map from resolved addresses back to the names that produced them.
* Detectors for vertical port scans and network sweeps, DNS tunneling and high
  rates of failed lookups, periodic beaconing, large outbound transfers, and
  matches against a supplied indicator list.
* A correlation engine that groups findings per host into incidents, each with
  a hypothesis, a confidence estimate, and a reconstructed timeline.
* Risk scoring per host.
* Output as text, json, and a standalone HTML dashboard.
* A command line with threshold overrides for tuning noise.
* A reproducible sample capture generator under examples.
* Continuous integration across Python 3.9, 3.11, and 3.12.
