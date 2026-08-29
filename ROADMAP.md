# Roadmap

Directions for NetHawk, roughly in order. Nothing here is a promise, and pull
requests that move any of it forward are welcome.

## Near term

* Live capture on a chosen interface, in addition to reading files.
* More detectors: long lived connections, rare user agents, connections to
  freshly resolved addresses, and cleartext credentials over HTTP.
* Certificate parsing from the TLS server hello to add issuer and validity to
  the picture.
* A one line per host summary mode for quick triage.

## Later

* Reading Suricata EVE json and Zeek logs as extra telemetry, so NetHawk can
  correlate its own findings with signatures you already run.
* An optional local API so other tools can submit a capture and read the
  structured result, without changing the zero dependency core.
* Persisted flows and findings for comparing captures over time.
* Tunable scoring weights through a configuration file.

## Out of scope

* Anything that sends or injects traffic. NetHawk reads captures and
  reconstructs what happened, and it stays on that side of the line.

Have an idea that is not here? Open an issue and start the conversation.
