# Contributing to NetHawk

Thanks for helping. NetHawk aims to stay small, fast, and dependency free, so
the most welcome contributions keep it that way.

## Getting set up

```bash
git clone https://github.com/SiteQ8/NetHawk.git
cd NetHawk
python -m unittest discover -s tests -v
python examples/make_sample.py
python -m nethawk analyze examples/sample.pcap
```

There is nothing to install. The whole project runs on the Python standard
library.

## Where things live

* `pcap.py` reads capture files into raw packets.
* `decode.py` turns raw packets into Packet records.
* `apps.py` parses DNS, the TLS client hello, and HTTP.
* `flows.py` aggregates packets into flows and DNS events.
* `detect.py` holds the detectors and their thresholds.
* `correlate.py` groups findings into incidents with a timeline.
* `report.py` prints text, json, and the HTML dashboard.

A new detector usually means a function in `detect.py` that returns findings,
wired into `run_detectors`, plus a headline in `correlate.py` so it appears in
the timeline.

## Good first contributions

* A new detector, such as long lived connections or rare user agents.
* Better handling of a link layer or an IPv6 extension header.
* More tests, especially around the beaconing score and the correlation logic.
* Improvements to the HTML dashboard.

## Testing

Please build fixtures with crafted packets, as the tests do now, so the suite
stays fast and needs no network. Keep detector thresholds covered by a test
when you change them.

## Before a pull request

1. Run the tests and make sure they pass.
2. Run the tool on the sample capture and confirm the output still makes sense.
3. Keep changes focused and describe what changed and why.
