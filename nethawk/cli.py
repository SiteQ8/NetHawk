"""Command line interface for NetHawk."""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .detect import Config
from .analyzer import analyze
from .pcap import PcapError
from . import report


def _load_iocs(path: str) -> set:
    iocs = set()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                s = line.strip()
                if s and not s.startswith("#"):
                    iocs.add(s)
    except OSError as exc:
        print(f"could not read iocs file {path}: {exc}", file=sys.stderr)
    return iocs


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nethawk",
        description="Reconstruct attacks from a packet capture.",
    )
    parser.add_argument("--version", action="version", version=f"nethawk {__version__}")
    sub = parser.add_subparsers(dest="command")

    an = sub.add_parser("analyze", help="Analyze a pcap or pcapng file.")
    an.add_argument("pcap", help="Path to a .pcap or .pcapng capture.")
    an.add_argument("--format", choices=["text", "json", "html"], default="text",
                    help="Output format.")
    an.add_argument("-o", "--output", metavar="PATH",
                    help="Write the report to a file instead of standard output.")
    an.add_argument("--iocs", metavar="PATH",
                    help="File of indicators to match, one IP or domain per line.")
    an.add_argument("--no-color", action="store_true", help="Disable colored text output.")

    # Threshold overrides for tuning noise.
    an.add_argument("--beacon-min-conns", type=int, default=None)
    an.add_argument("--beacon-min-score", type=float, default=None)
    an.add_argument("--beacon-min-interval", type=float, default=None,
                    help="Minimum seconds between beacons. Lower it to catch faster beaconing.")
    an.add_argument("--exfil-min-bytes", type=int, default=None)
    an.add_argument("--scan-min-ports", type=int, default=None)
    an.add_argument("--scan-min-hosts", type=int, default=None)

    fl = sub.add_parser("flows", help="List the conversations in a capture.")
    fl.add_argument("pcap", help="Path to a .pcap or .pcapng capture.")
    fl.add_argument("--sort", choices=["bytes", "out", "duration", "start", "port"],
                    default="bytes", help="Sort order.")
    fl.add_argument("--limit", type=int, default=40, help="How many flows to show.")
    fl.add_argument("--format", choices=["text", "json"], default="text")

    sv = sub.add_parser("serve", help="Start the local web GUI.")
    sv.add_argument("--host", default="127.0.0.1", help="Address to bind. Defaults to localhost.")
    sv.add_argument("--port", type=int, default=8080, help="Port to listen on.")
    sv.add_argument("--sample", metavar="PATH", help="A capture to offer as the sample in the GUI.")
    sv.add_argument("--open", action="store_true", help="Open the GUI in a browser on start.")

    sub.add_parser("version", help="Print the version.")
    return parser


def _config_from_args(args) -> Config:
    cfg = Config()
    if args.iocs:
        cfg.iocs = _load_iocs(args.iocs)
    for attr in ("beacon_min_conns", "beacon_min_score", "beacon_min_interval",
                 "exfil_min_bytes", "scan_min_ports", "scan_min_hosts"):
        value = getattr(args, attr, None)
        if value is not None:
            setattr(cfg, attr, value)
    return cfg


def _run_analyze(args) -> int:
    cfg = _config_from_args(args)
    try:
        analysis = analyze(args.pcap, cfg)
    except FileNotFoundError:
        print(f"no such file: {args.pcap}", file=sys.stderr)
        return 2
    except PcapError as exc:
        print(f"could not read capture: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        text = report.format_json(analysis, __version__)
    elif args.format == "html":
        text = report.format_html(analysis, __version__)
    else:
        use_color = (not args.no_color) and sys.stdout.isatty() and not args.output
        text = report.format_text(analysis, use_color=use_color)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            print(f"could not write {args.output}: {exc}", file=sys.stderr)
            return 2
        print(f"wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        print(text)
    return 0


def _run_flows(args) -> int:
    cfg = Config()
    try:
        analysis = analyze(args.pcap, cfg)
    except FileNotFoundError:
        print(f"no such file: {args.pcap}", file=sys.stderr)
        return 2
    except PcapError as exc:
        print(f"could not read capture: {exc}", file=sys.stderr)
        return 2

    flows = analysis.flows

    def key(f):
        if args.sort == "out":
            return f.a_to_b_bytes
        if args.sort == "duration":
            return f.duration
        if args.sort == "start":
            return f.first_ts
        if args.sort == "port":
            return f.b_port
        return f.total_bytes

    flows = sorted(flows, key=key, reverse=args.sort != "start")[:args.limit]

    if args.format == "json":
        import json
        print(json.dumps([f.to_dict() for f in flows], indent=2))
        return 0

    print(f"{'proto':<5} {'source':<24} {'destination':<22} {'port':>5} "
          f"{'out':>10} {'in':>10} {'dur':>8}  name")
    for f in flows:
        name = f.sni or f.http_host or ""
        src = f"{f.a_ip}:{f.a_port}"
        print(f"{f.proto:<5} {src:<24} {f.b_ip:<22} {f.b_port:>5} "
              f"{_human(f.a_to_b_bytes):>10} {_human(f.b_to_a_bytes):>10} "
              f"{_dur(f.duration):>8}  {name}")
    return 0


def _human(n: int) -> str:
    x = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if x < 1024 or unit == "TB":
            return f"{x:.1f}{unit}" if unit != "B" else f"{int(x)}B"
        x /= 1024
    return f"{n}B"


def _dur(seconds: float) -> str:
    seconds = int(seconds)
    if seconds >= 3600:
        return f"{seconds // 3600}h{seconds % 3600 // 60}m"
    if seconds >= 60:
        return f"{seconds // 60}m{seconds % 60}s"
    return f"{seconds}s"


def _locate_sample(explicit):
    import os
    candidates = []
    if explicit:
        candidates.append(explicit)
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(os.getcwd(), "examples", "sample.pcap"))
    candidates.append(os.path.join(here, "..", "examples", "sample.pcap"))
    for path in candidates:
        try:
            with open(path, "rb") as fh:
                return fh.read()
        except OSError:
            continue
    return None


def _run_serve(args) -> int:
    from .serve import run_server
    sample = _locate_sample(getattr(args, "sample", None))
    return run_server(args.host, args.port, Config(), sample_bytes=sample,
                      open_browser=args.open)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "analyze":
            return _run_analyze(args)
        if args.command == "flows":
            return _run_flows(args)
        if args.command == "serve":
            return _run_serve(args)
        if args.command == "version":
            print(f"nethawk {__version__}")
            return 0
        parser.print_help()
        return 0
    except BrokenPipeError:
        import os
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
