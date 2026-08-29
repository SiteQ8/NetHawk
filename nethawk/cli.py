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
    an.add_argument("--exfil-min-bytes", type=int, default=None)
    an.add_argument("--scan-min-ports", type=int, default=None)
    an.add_argument("--scan-min-hosts", type=int, default=None)

    sub.add_parser("version", help="Print the version.")
    return parser


def _config_from_args(args) -> Config:
    cfg = Config()
    if args.iocs:
        cfg.iocs = _load_iocs(args.iocs)
    for attr in ("beacon_min_conns", "beacon_min_score", "exfil_min_bytes",
                 "scan_min_ports", "scan_min_hosts"):
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


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "analyze":
            return _run_analyze(args)
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
