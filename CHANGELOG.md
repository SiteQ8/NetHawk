# Changelog

All notable changes to this project are recorded here. The format follows
Keep a Changelog, and the project uses semantic versioning.

## [0.3.1] - 2025

### Tuned

* Far fewer beaconing false positives on real traffic. Beaconing now needs the
  connections to be at least ten seconds apart by default, because real command
  and control beacons slowly to stay quiet while sub interval traffic is
  application keepalive or streaming. On a real capture this cut beacon findings
  from 57 to 5 without losing the slow, stealthy ones. The floor is adjustable
  with `--beacon-min-interval`.
* The external fan out detector now only fires when the connections are mostly
  unanswered, which looks like scanning, so a normal browser reaching many
  external hosts no longer trips it. Beaconing also needs eight connections
  rather than six, for a steadier read of periodicity. Both thresholds stay
  adjustable.

### Validated

* Ran NetHawk over a 350 MB real capture of about 800,000 packets. It finished in
  under ten seconds using around 130 MB of memory, since the reader streams the
  capture rather than loading it whole. On that capture the tuning above brought
  the findings down from 65 to 13, leaving the slow beacons, the large uploads,
  the cleartext services, and the automation user agents that are worth a look.
* Also ran the detectors against smaller real captures totalling several thousand
  more packets, where after tuning they produce no false positives while still
  catching every threat in the demo scenarios and the scan style fan out covered
  by the tests. The Python and browser engines agree on all of these captures.
  A large capture dropped into the browser demo now shows a friendly notice, and
  the command line tool is the better path for very large files.

## [0.3.0] - 2025

### Fixed

* pcapng little endian files were read with the byte order test inverted, so a
  standard Wireshark pcapng could yield zero packets. Both engines now read
  little and big endian pcapng correctly.
* 802.1ad QinQ double tagged frames were dropped. The decoders now strip a stack
  of VLAN tags, both 802.1Q and 802.1ad, to reach the inner packet.

### Validated

* Ran NetHawk over more than eighty real captures from the tcpdump test corpus,
  spanning IPv6, VLAN and QinQ, GRE, VXLAN, ESP, OSPF, BGP, DHCP, LLDP, and
  deliberately malformed fuzzing cases. It parsed all of them without crashing,
  which fixed the two bugs above and confirmed malformed packets are rejected
  rather than misread. Format accurate regression tests now cover these.

### Added

* A hosted demo on GitHub Pages that runs entirely in the browser. The full
  analysis engine was ported to JavaScript, so you can drop a capture into the
  page and reconstruct incidents with no server and nothing uploaded. The demo
  sits behind a simple sign in, which is a front door for the public demo and
  not a security control.
* MITRE ATT&CK mapping. Every finding now carries the technique it maps to, and
  the techniques are shown in the text report, the HTML report, and both GUIs.
* Two more detectors: sensitive services in clear text such as FTP and Telnet,
  and a single host reaching an unusually large number of external destinations.
* Export from the demo: download the full result as JSON, a list of indicators,
  or a standalone HTML report.
* A keyboard flow in both GUIs: number keys switch tabs, the arrow keys step
  through hosts by risk and focus each one, and escape clears the focus. The page
  wiring is also guarded so it never attaches twice.
* Shareable demo links. As you pick a scenario, switch tabs, and focus a host,
  the address bar updates, and a Copy link button lets you share a URL that
  reopens exactly that scenario, tab, and focused host.
* An evidence drawer on every incident in both GUIs: expand it to see the exact
  findings that produced the incident, each with its ATT&CK technique, and the
  key flows behind it.
* A plain English summary for every incident, written from the correlated
  signals, so the reconstruction reads like a short writeup you can paste into a
  ticket. It appears in the text, JSON, and HTML output and in both GUIs, and the
  Python and browser engines produce identical wording.
* Cross view host focus in both GUIs: click a host in the risk table, the graph,
  or an incident, and the findings and flows filter to that host while the graph
  highlights it and its neighbors and dims the rest.
* Visualizations in both GUIs: a visual attack timeline that lays the incident
  events out per host across the capture, a host graph that draws the
  conversation between hosts and makes risky hosts stand out, an activity over
  time chart that surfaces bursts such as a large transfer, and an ATT&CK matrix
  that groups the observed techniques by tactic.

## [0.2.0] - 2025

### Added

* A built in web GUI, served by the standard library, that runs entirely in the
  browser. Start it with `nethawk serve`, then drop a capture in to get an
  interactive dashboard: summary, host risk, reconstructed incidents with
  timelines, a searchable and filterable findings list, a flows explorer, and
  traffic statistics.
* A JSON API. POST a capture body to `/api/analyze` and receive the same
  structured result as the json report, with no dependencies to run the server.
* A `flows` command that lists the conversations in a capture, sortable by
  bytes, duration, port, or start time.
* Three new detectors: credentials sent in clear text over HTTP, long lived
  connections, and automation user agents such as curl and python requests.
* Traffic statistics in the analysis: protocol breakdown, top talkers by bytes,
  and the busiest destination ports.

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
