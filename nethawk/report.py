"""Render an Analysis as text, json, or a standalone HTML dashboard."""
from __future__ import annotations

import html
import json
import time
from typing import List

from .models import Analysis, Incident

_COLORS = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "green": "\033[32m", "teal": "\033[36m", "yellow": "\033[33m",
    "red": "\033[31m", "bred": "\033[1;31m",
}
_SEV_COLOR = {"critical": "bred", "high": "red", "medium": "yellow", "low": "teal", "info": "dim"}


def _c(key: str, on: bool) -> str:
    return _COLORS.get(key, "") if on else ""


def _clock(ts: float) -> str:
    if not ts:
        return "--:--:--"
    return time.strftime("%H:%M:%S", time.gmtime(ts))


def _duration(seconds: float) -> str:
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


# ------------------------------- text -------------------------------

def format_text(a: Analysis, use_color: bool = False) -> str:
    on = use_color
    out: List[str] = []
    reset = _c("reset", on)

    out.append(f"{_c('bold', on)}NetHawk report{reset}")
    out.append(f"capture   {a.path}")
    started = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(a.first_ts)) if a.first_ts else "unknown"
    out.append(f"packets   {a.packet_count}    flows {len(a.flows)}    "
               f"duration {_duration(a.duration)}    started {started}")
    out.append(f"hosts     {len(a.hosts_internal)} internal, {len(a.hosts_external)} external")
    out.append("")

    if a.host_scores:
        out.append(f"{_c('bold', on)}Top risk hosts{reset}")
        for host, score in sorted(a.host_scores.items(), key=lambda kv: kv[1], reverse=True)[:10]:
            color = "bred" if score >= 70 else "yellow" if score >= 40 else "teal"
            out.append(f"  {_c(color, on)}{score:>3}{reset}  {host}")
        out.append("")

    if a.incidents:
        out.append(f"{_c('bold', on)}Incidents{reset}")
        for i, inc in enumerate(a.incidents, 1):
            out.extend(_incident_text(i, inc, on))
        out.append("")

    out.append(f"{_c('bold', on)}All findings ({len(a.findings)}){reset}")
    if not a.findings:
        out.append(f"  {_c('green', on)}No suspicious activity detected.{reset}")
    for f in a.findings:
        sc = _SEV_COLOR.get(f.severity, "dim")
        dst = f" -> {f.dst}" if f.dst else ""
        out.append(f"  {_c(sc, on)}{f.severity.upper():<8}{reset} {f.category:<13} {f.src}{dst}  {f.title}")
        out.append(f"           {_c('dim', on)}{f.detail}{reset}")
        if f.mitre:
            ids = ", ".join(f"{m['id']} {m['name']}" for m in f.mitre)
            out.append(f"           {_c('dim', on)}ATT&CK: {ids}{reset}")
    return "\n".join(out)


def _incident_text(index: int, inc: Incident, on: bool) -> List[str]:
    reset = _c("reset", on)
    conf_color = "bred" if inc.confidence >= 70 else "yellow" if inc.confidence >= 45 else "teal"
    lines = [
        f"  {_c('bold', on)}[{index}] {inc.host}{reset}  {inc.hypothesis}  "
        f"{_c(conf_color, on)}confidence {inc.confidence}%{reset}"
    ]
    if inc.indicators:
        lines.append(f"      indicators: {', '.join(inc.indicators)}")
    if inc.timeline:
        lines.append("      timeline:")
        for ev in inc.timeline:
            lines.append(f"        {_c('teal', on)}{_clock(ev.ts)}{reset}  {ev.text}")
    lines.append("")
    return lines


# ------------------------------- json -------------------------------

def format_json(a: Analysis, version: str) -> str:
    payload = {"tool": "nethawk", "version": version}
    payload.update(a.to_dict())
    return json.dumps(payload, indent=2)


# ------------------------------- html -------------------------------

_CSS = """
:root{--bg:#0d0e14;--panel:#171922;--panel2:#1f2230;--line:#2a2e3d;
--text:#e8eaf0;--dim:#9096a0;--teal:#3dd6c4;--green:#5ad67d;--yellow:#f0be46;
--red:#e9564b;--crit:#ff4a4a;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:32px 20px 64px}
h1{font-size:26px;margin:0 0 4px}.sub{color:var(--dim);margin:0 0 24px;font-size:14px}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:28px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;
padding:16px 18px;min-width:150px;flex:1}
.card .n{font-size:24px;font-weight:700}.card .l{color:var(--dim);font-size:13px;margin-top:2px}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.06em;color:var(--dim);
margin:28px 0 12px;border-bottom:1px solid var(--line);padding-bottom:8px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
th{color:var(--dim);font-weight:600}
.bar{height:8px;border-radius:5px;background:var(--panel2);overflow:hidden;min-width:120px}
.bar span{display:block;height:100%}
.inc{background:var(--panel);border:1px solid var(--line);border-radius:12px;
padding:18px 20px;margin-bottom:16px}
.inc .top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.inc .host{font-weight:700;font-size:16px}
.inc .hyp{color:var(--text)}
.pill{padding:3px 10px;border-radius:999px;font-size:13px;font-weight:700;white-space:nowrap}
.ind{color:var(--dim);font-size:13px;margin:8px 0 4px}
.tl{list-style:none;margin:12px 0 0;padding:0;border-left:2px solid var(--line)}
.tl li{position:relative;padding:4px 0 4px 18px;font-size:14px}
.tl li:before{content:"";position:absolute;left:-6px;top:11px;width:10px;height:10px;
border-radius:50%;background:var(--teal)}
.tl .t{color:var(--teal);font-variant-numeric:tabular-nums;margin-right:10px}
.sev{font-weight:700;font-size:12px;text-transform:uppercase;letter-spacing:.03em}
.muted{color:var(--dim)}
.foot{color:var(--dim);font-size:13px;margin-top:36px;border-top:1px solid var(--line);padding-top:16px}
"""

_SEV_CSSVAR = {"critical": "--crit", "high": "--red", "medium": "--yellow", "low": "--teal", "info": "--dim"}


def _score_color(score: int) -> str:
    return "--crit" if score >= 70 else "--yellow" if score >= 40 else "--teal"


def _conf_color(conf: int) -> str:
    return "--crit" if conf >= 70 else "--yellow" if conf >= 45 else "--teal"


def format_html(a: Analysis, version: str) -> str:
    e = html.escape
    started = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(a.first_ts)) if a.first_ts else "unknown"
    sev_counts = {}
    for f in a.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    top_sev = "none"
    for s in ("critical", "high", "medium", "low"):
        if sev_counts.get(s):
            top_sev = s
            break

    parts = ["<!doctype html><html lang='en'><head><meta charset='utf-8'>",
             "<meta name='viewport' content='width=device-width,initial-scale=1'>",
             f"<title>NetHawk report</title><style>{_CSS}</style></head><body><div class='wrap'>"]

    parts.append("<h1>&#128052; NetHawk report</h1>")
    parts.append(f"<p class='sub'>{e(a.path)} &middot; started {e(started)}</p>")

    parts.append("<div class='cards'>")
    for n, l in [
        (a.packet_count, "packets"),
        (len(a.flows), "flows"),
        (_duration(a.duration), "duration"),
        (f"{len(a.hosts_internal)} / {len(a.hosts_external)}", "hosts in / out"),
        (len(a.incidents), "incidents"),
    ]:
        parts.append(f"<div class='card'><div class='n'>{e(str(n))}</div><div class='l'>{e(l)}</div></div>")
    color = _SEV_CSSVAR.get(top_sev, "--dim")
    parts.append(f"<div class='card'><div class='n' style='color:var({color})'>"
                 f"{e(top_sev)}</div><div class='l'>highest severity</div></div>")
    parts.append("</div>")

    if a.host_scores:
        parts.append("<h2>Host risk</h2><table><tr><th>host</th><th>score</th><th></th></tr>")
        for host, score in sorted(a.host_scores.items(), key=lambda kv: kv[1], reverse=True):
            var = _score_color(score)
            parts.append(
                f"<tr><td>{e(host)}</td><td>{score}</td>"
                f"<td><div class='bar'><span style='width:{min(100, score)}%;background:var({var})'></span></div></td></tr>")
        parts.append("</table>")

    if a.incidents:
        parts.append("<h2>Reconstructed incidents</h2>")
        for inc in a.incidents:
            var = _conf_color(inc.confidence)
            parts.append("<div class='inc'><div class='top'>"
                         f"<div><span class='host'>{e(inc.host)}</span> "
                         f"<span class='hyp'>&mdash; {e(inc.hypothesis)}</span></div>"
                         f"<span class='pill' style='background:var({var});color:#0d0e14'>"
                         f"confidence {inc.confidence}%</span></div>")
            if inc.indicators:
                parts.append(f"<div class='ind'>indicators: {e(', '.join(inc.indicators))}</div>")
            if inc.timeline:
                parts.append("<ul class='tl'>")
                for ev in inc.timeline:
                    parts.append(f"<li><span class='t'>{_clock(ev.ts)}</span>{e(ev.text)}</li>")
                parts.append("</ul>")
            parts.append("</div>")

    parts.append("<h2>All findings</h2>")
    if a.findings:
        parts.append("<table><tr><th>severity</th><th>type</th><th>source</th>"
                     "<th>target</th><th>att&amp;ck</th><th>detail</th></tr>")
        for f in a.findings:
            var = _SEV_CSSVAR.get(f.severity, "--dim")
            att = " ".join(m["id"] for m in f.mitre)
            parts.append(
                f"<tr><td><span class='sev' style='color:var({var})'>{e(f.severity)}</span></td>"
                f"<td>{e(f.category)}</td><td>{e(f.src)}</td><td>{e(f.dst or '')}</td>"
                f"<td class='muted'>{e(att)}</td>"
                f"<td class='muted'>{e(f.detail)}</td></tr>")
        parts.append("</table>")
    else:
        parts.append("<p class='muted'>No suspicious activity detected.</p>")

    parts.append(f"<p class='foot'>Generated by NetHawk {e(version)}. "
                 "Analyze only captures you are authorized to inspect.</p>")
    parts.append("</div></body></html>")
    return "".join(parts)
