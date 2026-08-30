/* NetHawk engine, a browser and Node port of the Python analysis pipeline.
 *
 * Input: an ArrayBuffer or Uint8Array holding a pcap or pcapng capture.
 * Output: the same structured result as the json report, so the UI can render
 * it exactly like the command line tool does. No dependencies.
 *
 * The Python package under nethawk/ is the reference. This file mirrors its
 * parsing, detectors, correlation, and scoring so the hosted demo matches.
 */
(function (root) {
  "use strict";
  var VERSION = "0.3.0";
  var SYN = 2, ACK = 16, RST = 4, FIN = 1;

  // ---- byte helpers ----
  function rd16(u, o, le) { return le ? (u[o] | (u[o + 1] << 8)) : ((u[o] << 8) | u[o + 1]); }
  function rd32(u, o, le) {
    return le ? ((u[o] | (u[o + 1] << 8) | (u[o + 2] << 16)) + u[o + 3] * 0x1000000)
              : (u[o] * 0x1000000 + ((u[o + 1] << 16) | (u[o + 2] << 8) | u[o + 3]));
  }
  function b16(d, o) { return (d[o] << 8) | d[o + 1]; }
  function ipv4Str(d, o) { return d[o] + "." + d[o + 1] + "." + d[o + 2] + "." + d[o + 3]; }
  function ipv6Str(d, o) {
    var p = [];
    for (var i = 0; i < 16; i += 2) p.push(((d[o + i] << 8) | d[o + i + 1]).toString(16));
    return p.join(":");
  }
  function latin1(d, o, n) {
    var s = "";
    for (var i = 0; i < n; i++) s += String.fromCharCode(d[o + i]);
    return s;
  }

  // ---- pcap and pcapng reader ----
  var CLASSIC = {
    "d4c3b2a1": [true, 1e6], "a1b2c3d4": [false, 1e6],
    "4d3cb2a1": [true, 1e9], "a1b23c4d": [false, 1e9]
  };
  function hex4(u) {
    function h(x) { return (x < 16 ? "0" : "") + x.toString(16); }
    return h(u[0]) + h(u[1]) + h(u[2]) + h(u[3]);
  }

  function readPackets(buf) {
    var u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    if (u.length < 4) throw new Error("file is too short to be a capture");
    var magic = hex4(u);
    if (CLASSIC[magic]) return readClassic(u, CLASSIC[magic]);
    if (magic === "0a0d0d0a") return readPcapng(u);
    throw new Error("not a pcap or pcapng file");
  }

  function readClassic(u, mode) {
    var le = mode[0], ticks = mode[1], out = [];
    if (u.length < 24) throw new Error("truncated global header");
    var linktype = rd32(u, 20, le);
    var off = 24, n = u.length;
    while (off + 16 <= n) {
      var sec = rd32(u, off, le), frac = rd32(u, off + 4, le), incl = rd32(u, off + 8, le);
      off += 16;
      if (off + incl > n) break;
      out.push({ ts: sec + frac / ticks, linktype: linktype, data: u.subarray(off, off + incl) });
      off += incl;
    }
    return out;
  }

  function idbResol(u, bodyStart, bodyLen, le) {
    var o = bodyStart + 8, end = bodyStart + bodyLen;
    while (o + 4 <= end) {
      var code = rd16(u, o, le), len = rd16(u, o + 2, le); o += 4;
      if (code === 0) break;
      if (code === 9 && len >= 1) {
        var b = u[o];
        return (b & 0x80) ? Math.pow(2, (b & 0x7f)) : Math.pow(10, b);
      }
      o += len + ((4 - len % 4) % 4);
    }
    return 1e6;
  }

  function readPcapng(u) {
    var n = u.length, off = 0, le = true, out = [], linktypes = [], resols = [];
    while (off + 8 <= n) {
      var bt = hex4(u.subarray(off, off + 4));
      if (bt === "0a0d0d0a") {
        var bom = hex4(u.subarray(off + 8, off + 12));
        le = (bom !== "1a2b3c4d");
        var totalS = rd32(u, off + 4, le);
        if (totalS < 12 || off + totalS > n) break;
        off += totalS; continue;
      }
      var total = rd32(u, off + 4, le);
      if (total < 12 || off + total > n) break;
      var t = rd32(u, off, le), bodyStart = off + 8, bodyLen = total - 12;
      if (t === 1) {
        linktypes.push(rd16(u, bodyStart, le));
        resols.push(idbResol(u, bodyStart, bodyLen, le));
      } else if (t === 6) {
        var iface = rd32(u, bodyStart, le);
        var hi = rd32(u, bodyStart + 4, le), lo = rd32(u, bodyStart + 8, le);
        var cap = rd32(u, bodyStart + 12, le);
        var res = iface < resols.length ? resols[iface] : 1e6;
        var lt = iface < linktypes.length ? linktypes[iface] : 1;
        out.push({ ts: (hi * 4294967296 + lo) / res, linktype: lt,
                   data: u.subarray(bodyStart + 20, bodyStart + 20 + cap) });
      } else if (t === 3) {
        var orig = rd32(u, bodyStart, le);
        var lt2 = linktypes.length ? linktypes[0] : 1;
        out.push({ ts: 0, linktype: lt2, data: u.subarray(bodyStart + 4, bodyStart + 4 + orig) });
      }
      off += total;
    }
    return out;
  }

  // ---- decoders ----
  function decode(ts, linktype, d) {
    var r = link(linktype, d);
    if (!r) return null;
    if (r.et === "ip4") return ipv4(ts, d, r.off);
    if (r.et === "ip6") return ipv6(ts, d, r.off);
    if (r.et === "arp") return { ts: ts, src_ip: "", dst_ip: "", proto: "ARP", src_port: 0, dst_port: 0, length: 0, flags: 0, payload: null };
    return null;
  }
  function link(linktype, d) {
    if (linktype === 1) { if (d.length < 14) return null; return ethertype(b16(d, 12), d, 14); }
    if (linktype === 113) { if (d.length < 16) return null; return ethertype(b16(d, 14), d, 16); }
    if (linktype === 101) { if (!d.length) return null; var v = d[0] >> 4; return v === 4 ? { et: "ip4", off: 0 } : v === 6 ? { et: "ip6", off: 0 } : null; }
    if (linktype === 0) {
      if (d.length < 4) return null;
      var fam = d[0] | (d[1] << 8) | (d[2] << 16) + d[3] * 0x1000000;
      if (fam > 0xffff) fam = d[3] | (d[2] << 8) | (d[1] << 16) + d[0] * 0x1000000;
      if (fam === 2) return { et: "ip4", off: 4 };
      if (fam === 23 || fam === 24 || fam === 28 || fam === 30) return { et: "ip6", off: 4 };
      return null;
    }
    if (d.length >= 14) return ethertype(b16(d, 12), d, 14);
    return null;
  }
  function ethertype(et, d, off) {
    var hops = 0;
    while ((et === 0x8100 || et === 0x88a8) && d.length >= off + 4 && hops < 4) { et = b16(d, off + 2); off += 4; hops++; }
    if (et === 0x0800) return { et: "ip4", off: off };
    if (et === 0x86dd) return { et: "ip6", off: off };
    if (et === 0x0806) return { et: "arp", off: off };
    return null;
  }
  function ipv4(ts, d, off) {
    if (d.length < off + 20) return null;
    var ihl = (d[off] & 0x0f) * 4;
    if (ihl < 20 || d.length < off + ihl) return null;
    var total = b16(d, off + 2), proto = d[off + 9];
    var src = ipv4Str(d, off + 12), dst = ipv4Str(d, off + 16);
    return transport(ts, src, dst, proto, d, off + ihl, Math.max(0, total - ihl));
  }
  function ipv6(ts, d, off) {
    if (d.length < off + 40) return null;
    var plen = b16(d, off + 4), nh = d[off + 6];
    var src = ipv6Str(d, off + 8), dst = ipv6Str(d, off + 24), l4 = off + 40, hops = 0;
    while ((nh === 0 || nh === 43 || nh === 60) && hops < 4 && d.length >= l4 + 2) {
      var extLen = (d[l4 + 1] + 1) * 8; nh = d[l4]; l4 += extLen; hops++;
    }
    return transport(ts, src, dst, nh, d, l4, plen);
  }
  function transport(ts, src, dst, proto, d, off, ipPayloadLen) {
    if (proto === 6) {
      if (d.length < off + 20) return null;
      var sport = b16(d, off), dport = b16(d, off + 2);
      var dataOff = (d[off + 12] >> 4) * 4, flags = d[off + 13];
      var payload = d.length > off + dataOff ? d.subarray(off + dataOff) : null;
      var len = ipPayloadLen || (d.length - off);
      return { ts: ts, src_ip: src, dst_ip: dst, proto: "TCP", src_port: sport, dst_port: dport, length: len, flags: flags, payload: payload };
    }
    if (proto === 17) {
      if (d.length < off + 8) return null;
      var sp = b16(d, off), dp = b16(d, off + 2);
      var pl = d.subarray(off + 8);
      var l = ipPayloadLen || (d.length - off);
      return { ts: ts, src_ip: src, dst_ip: dst, proto: "UDP", src_port: sp, dst_port: dp, length: l, flags: 0, payload: pl };
    }
    if (proto === 1 || proto === 58) {
      return { ts: ts, src_ip: src, dst_ip: dst, proto: proto === 1 ? "ICMP" : "ICMPv6", src_port: 0, dst_port: 0, length: ipPayloadLen, flags: 0, payload: null };
    }
    return { ts: ts, src_ip: src, dst_ip: dst, proto: "OTHER", src_port: 0, dst_port: 0, length: ipPayloadLen, flags: 0, payload: null };
  }

  // ---- app parsing ----
  function readName(d, off, depth) {
    depth = depth || 0;
    if (depth > 12) return [null, off];
    var labels = [], n = d.length;
    while (true) {
      if (off >= n) return [null, off];
      var len = d[off];
      if (len === 0) { off += 1; break; }
      if ((len & 0xc0) === 0xc0) {
        if (off + 2 > n) return [null, off];
        var ptr = ((len & 0x3f) << 8) | d[off + 1];
        var sub = readName(d, ptr, depth + 1)[0];
        off += 2;
        if (sub) labels.push(sub);
        return [labels.join("."), off];
      }
      off += 1;
      if (off + len > n) return [null, off];
      labels.push(latin1(d, off, len));
      off += len;
    }
    return [labels.join("."), off];
  }
  function parseDns(d) {
    if (!d || d.length < 12) return null;
    var flags = b16(d, 2), qd = b16(d, 4), an = b16(d, 6);
    if (qd < 1) return null;
    var qr = (flags >> 15) & 1, rcode = flags & 0x000f, off = 12;
    var nm = readName(d, off); if (nm[0] === null) return null;
    var qname = nm[0]; off = nm[1];
    var qtype = 0;
    if (off + 4 <= d.length) { qtype = b16(d, off); off += 4; }
    var answers = [];
    for (var i = 0; i < an; i++) {
      var an2 = readName(d, off); off = an2[1];
      if (off + 10 > d.length) break;
      var atype = b16(d, off), rdlen = b16(d, off + 8); off += 10;
      if (atype === 1 && rdlen === 4) answers.push(ipv4Str(d, off));
      else if (atype === 28 && rdlen === 16) answers.push(ipv6Str(d, off));
      off += rdlen;
    }
    return { is_response: !!qr, rcode: rcode, qname: qname, qtype: qtype, answers: answers };
  }
  function parseTlsSni(d) {
    if (!d || d.length < 6 || d[0] !== 0x16) return null;
    var off = 5;
    if (d[off] !== 0x01) return null;
    var hsLen = (d[off + 1] << 16) | (d[off + 2] << 8) | d[off + 3];
    var end = Math.min(d.length, off + 4 + hsLen);
    off += 4; off += 2 + 32;
    if (off >= end) return null;
    var sidLen = d[off]; off += 1 + sidLen;
    if (off + 2 > end) return null;
    var csLen = b16(d, off); off += 2 + csLen;
    if (off + 1 > end) return null;
    var compLen = d[off]; off += 1 + compLen;
    if (off + 2 > end) return null;
    var extTotal = b16(d, off); off += 2;
    var extEnd = Math.min(end, off + extTotal);
    while (off + 4 <= extEnd) {
      var etype = b16(d, off), elen = b16(d, off + 2); off += 4;
      if (etype === 0x0000) {
        var p = off;
        if (p + 2 > extEnd) return null;
        p += 2; if (p + 3 > extEnd) return null;
        p += 1; var nlen = b16(d, p); p += 2;
        if (p + nlen > extEnd) return null;
        return latin1(d, p, nlen);
      }
      off += elen;
    }
    return null;
  }
  var HTTP_METHODS = ["GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT "];
  function parseHttp(d) {
    if (!d) return null;
    var head = latin1(d, 0, Math.min(d.length, 2048));
    var ok = false;
    for (var i = 0; i < HTTP_METHODS.length; i++) if (head.indexOf(HTTP_METHODS[i]) === 0) { ok = true; break; }
    if (!ok) return null;
    head = head.split("\r\n\r\n")[0];
    var lines = head.split("\r\n");
    var first = lines[0].split(" ");
    if (first.length < 2) return null;
    var info = { method: first[0], host: "", path: first[1], user_agent: "", has_auth: false };
    for (var j = 1; j < lines.length; j++) {
      var low = lines[j].toLowerCase();
      if (low.indexOf("host:") === 0) info.host = lines[j].split(":").slice(1).join(":").trim();
      else if (low.indexOf("user-agent:") === 0) info.user_agent = lines[j].split(":").slice(1).join(":").trim();
      else if (low.indexOf("authorization:") === 0) info.has_auth = true;
    }
    return info;
  }

  // ---- flows ----
  function isInternal(ip) {
    if (ip.indexOf(":") >= 0) {
      var low = ip.toLowerCase();
      return low === "::1" || low.indexOf("fe80") === 0 || low.indexOf("fc") === 0 || low.indexOf("fd") === 0;
    }
    var p = ip.split(".");
    if (p.length !== 4) return false;
    var a = +p[0], b = +p[1];
    if (a === 10 || a === 127) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true;
    return false;
  }

  function buildFlows(packets) {
    var flows = {}, dnsEvents = [], ipDomain = {}, ips = {}, first = null, last = null, count = 0;
    for (var i = 0; i < packets.length; i++) {
      var p = packets[i]; count++;
      if (p.ts) { first = first === null ? p.ts : Math.min(first, p.ts); last = last === null ? p.ts : Math.max(last, p.ts); }
      if (p.src_ip) ips[p.src_ip] = 1;
      if (p.dst_ip) ips[p.dst_ip] = 1;
      if (p.proto !== "TCP" && p.proto !== "UDP") continue;
      if (p.proto === "UDP" && (p.dst_port === 53 || p.src_port === 53)) {
        var m = parseDns(p.payload);
        if (m) {
          var client, server;
          if (m.is_response) { client = p.dst_ip; server = p.src_ip; for (var k = 0; k < m.answers.length; k++) ipDomain[m.answers[k]] = m.qname; }
          else { client = p.src_ip; server = p.dst_ip; }
          dnsEvents.push({ ts: p.ts, client: client, server: server, qname: m.qname, qtype: m.qtype, is_response: m.is_response, rcode: m.rcode, answers: m.answers });
        }
      }
      var a = p.src_ip + ":" + p.src_port, b = p.dst_ip + ":" + p.dst_port;
      var lohi = a < b ? [a, b] : [b, a];
      var key = p.proto + "|" + lohi[0] + "|" + lohi[1];
      var fl = flows[key];
      if (!fl) {
        var senderInit = true;
        if (p.proto === "TCP" && (p.flags & (SYN | ACK)) === (SYN | ACK)) senderInit = false;
        var aip, apt, bip, bpt;
        if (senderInit) { aip = p.src_ip; apt = p.src_port; bip = p.dst_ip; bpt = p.dst_port; }
        else { aip = p.dst_ip; apt = p.dst_port; bip = p.src_ip; bpt = p.src_port; }
        fl = { proto: p.proto, a_ip: aip, a_port: apt, b_ip: bip, b_port: bpt, first_ts: p.ts, last_ts: p.ts,
               a_to_b_bytes: 0, b_to_a_bytes: 0, a_to_b_pkts: 0, b_to_a_pkts: 0,
               saw_syn: false, saw_synack: false, saw_rst: false, saw_fin: false, sni: "", http_host: "", user_agent: "", http_auth: false };
        flows[key] = fl;
      }
      if (p.src_ip === fl.a_ip && p.src_port === fl.a_port) { fl.a_to_b_bytes += p.length; fl.a_to_b_pkts++; }
      else { fl.b_to_a_bytes += p.length; fl.b_to_a_pkts++; }
      if (p.ts) { fl.first_ts = fl.first_ts ? Math.min(fl.first_ts, p.ts) : p.ts; fl.last_ts = Math.max(fl.last_ts, p.ts); }
      if (p.proto === "TCP") {
        var masked = p.flags & (SYN | ACK);
        if (masked === SYN) fl.saw_syn = true; else if (masked === (SYN | ACK)) fl.saw_synack = true;
        if (p.flags & RST) fl.saw_rst = true;
        if (p.flags & FIN) fl.saw_fin = true;
        if (p.payload && p.payload.length) {
          if (p.payload[0] === 0x16 && !fl.sni) { var sni = parseTlsSni(p.payload); if (sni) fl.sni = sni; }
          else if (!fl.http_host) {
            var http = parseHttp(p.payload);
            if (http) { fl.http_host = http.host; if (http.user_agent && !fl.user_agent) fl.user_agent = http.user_agent; if (http.has_auth) fl.http_auth = true; }
          }
        }
      }
    }
    var flowList = [], internal = [], external = [];
    for (var kk in flows) if (flows.hasOwnProperty(kk)) flowList.push(flows[kk]);
    for (var ip in ips) if (ips.hasOwnProperty(ip)) (isInternal(ip) ? internal : external).push(ip);
    internal.sort(); external.sort();
    return { flows: flowList, dnsEvents: dnsEvents, ipDomain: ipDomain, internal: internal, external: external, count: count, first: first || 0, last: last || 0 };
  }

  function established(f) { return f.saw_syn && f.saw_synack; }
  function duration(f) { return Math.max(0, f.last_ts - f.first_ts); }
  function totalBytes(f) { return f.a_to_b_bytes + f.b_to_a_bytes; }

  // ---- helpers ----
  function median(arr) {
    if (!arr.length) return 0;
    var s = arr.slice().sort(function (x, y) { return x - y; });
    var m = Math.floor(s.length / 2);
    return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
  }
  function entropy(s) {
    if (!s) return 0;
    var c = {}, n = s.length;
    for (var i = 0; i < n; i++) c[s[i]] = (c[s[i]] || 0) + 1;
    var e = 0;
    for (var k in c) if (c.hasOwnProperty(k)) { var pr = c[k] / n; e -= pr * Math.log(pr) / Math.log(2); }
    return e;
  }
  function humanInterval(s) { return s < 90 ? Math.round(s) + "s" : s < 5400 ? Math.round(s / 60) + "m" : (s / 3600).toFixed(1) + "h"; }
  function humanBytes(n) {
    var x = n, u = ["B", "KB", "MB", "GB", "TB"], i = 0;
    while (x >= 1024 && i < u.length - 1) { x /= 1024; i++; }
    return i === 0 ? (x + " B") : (x.toFixed(1) + " " + u[i]);
  }
  function splitDomain(q) {
    var l = q.replace(/^\.|\.$/g, "").split(".");
    if (l.length <= 2) return [q, ""];
    return [l.slice(-2).join("."), l.slice(0, -2).join(".")];
  }
  function F(cat, sev, src, dst, title, detail, first, last, score, ev) {
    return { category: cat, severity: sev, src: src, dst: dst, title: title, detail: detail, first_ts: first || 0, last_ts: last || 0, score: score, evidence: ev || {}, mitre: [] };
  }

  // ---- detectors ----
  var DEFAULTS = {
    scan_min_ports: 15, scan_min_hosts: 15, beacon_min_conns: 6, beacon_min_score: 0.7,
    exfil_min_bytes: 5e6, exfil_ratio: 5.0, dns_tunnel_min_subdomains: 20, dns_tunnel_min_entropy: 3.2,
    dga_min_nxdomain: 20, dga_min_ratio: 0.5, long_conn_seconds: 3600, long_conn_min_bytes: 1e5,
    fanout_min_hosts: 50,
    rare_ua_tokens: ["curl", "wget", "python-requests", "python-urllib", "go-http-client", "powershell", "winhttp", "libwww-perl", "httpie", "java/", "nikto", "sqlmap", "masscan", "nmap"],
    iocs: []
  };
  var CLEARTEXT = { 21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP" };
  var MITRE = {
    port_scan: [["T1046", "Network Service Discovery"]], external_fanout: [["T1046", "Network Service Discovery"]],
    dns_tunnel: [["T1071.004", "Application Layer Protocol: DNS"]], dga: [["T1568.002", "Dynamic Resolution: Domain Generation Algorithms"]],
    beacon: [["T1071", "Application Layer Protocol"]], exfil: [["T1048", "Exfiltration Over Alternative Protocol"]],
    cleartext_creds: [["T1552", "Unsecured Credentials"]], cleartext_protocol: [["T1040", "Network Sniffing"]],
    long_connection: [["T1572", "Protocol Tunneling"]], rare_user_agent: [["T1071.001", "Application Layer Protocol: Web Protocols"]],
    ioc: [["T1071", "Application Layer Protocol"]]
  };

  function detectPortScans(flows, cfg) {
    var vert = {}, horiz = {}, out = [];
    flows.forEach(function (f) {
      if (f.proto !== "TCP" || !f.saw_syn) return;
      var vk = f.a_ip + ">" + f.b_ip;
      (vert[vk] = vert[vk] || []).push([f.b_port, established(f), f.first_ts, f.last_ts]);
      var hk = f.a_ip + ">" + f.b_port;
      var h = horiz[hk] = horiz[hk] || { hosts: {}, unest: 0, total: 0, first: null, last: null };
      h.hosts[f.b_ip] = 1; h.total++; if (!established(f)) h.unest++;
      h.first = h.first === null ? f.first_ts : Math.min(h.first, f.first_ts);
      h.last = h.last === null ? f.last_ts : Math.max(h.last, f.last_ts);
    });
    Object.keys(vert).forEach(function (vk) {
      var lst = vert[vk], ports = {}, unest = 0;
      lst.forEach(function (x) { ports[x[0]] = 1; if (!x[1]) unest++; });
      var np = Object.keys(ports).length;
      if (np >= cfg.scan_min_ports && unest >= 0.7 * lst.length) {
        var parts = vk.split(">");
        var first = Math.min.apply(null, lst.map(function (x) { return x[2]; }));
        var last = Math.max.apply(null, lst.map(function (x) { return x[3]; }));
        out.push(F("port_scan", "high", parts[0], parts[1], "Vertical port scan",
          parts[0] + " probed " + np + " ports on " + parts[1] + ", mostly without completing a connection.",
          first, last, 25, { ports: np, attempts: lst.length, unanswered: unest }));
      }
    });
    Object.keys(horiz).forEach(function (hk) {
      var h = horiz[hk], nh = Object.keys(h.hosts).length;
      if (nh >= cfg.scan_min_hosts && h.unest >= 0.7 * h.total) {
        var parts = hk.split(">");
        out.push(F("port_scan", "high", parts[0], "", "Network sweep",
          parts[0] + " contacted " + nh + " hosts on port " + parts[1] + ", mostly without completing a connection.",
          h.first, h.last, 25, { hosts: nh, port: +parts[1] }));
      }
    });
    return out;
  }

  function detectDns(dnsEvents, cfg) {
    var tun = {}, nx = {}, out = [];
    dnsEvents.forEach(function (e) {
      if (e.is_response) {
        var d = nx[e.client] = nx[e.client] || { nx: 0, total: 0, first: null, last: null };
        d.total++; if (e.rcode === 3) d.nx++;
        d.first = d.first === null ? e.ts : Math.min(d.first, e.ts); d.last = d.last === null ? e.ts : Math.max(d.last, e.ts);
      } else {
        var sd = splitDomain(e.qname); if (!sd[1]) return;
        var k = e.client + "|" + sd[0];
        var t = tun[k] = tun[k] || { subs: {}, ent: [], first: null, last: null, count: 0 };
        t.subs[sd[1]] = 1; t.ent.push(entropy(sd[1].replace(/\./g, ""))); t.count++;
        t.first = t.first === null ? e.ts : Math.min(t.first, e.ts); t.last = t.last === null ? e.ts : Math.max(t.last, e.ts);
      }
    });
    Object.keys(tun).forEach(function (k) {
      var t = tun[k], subs = Object.keys(t.subs).length;
      if (subs >= cfg.dns_tunnel_min_subdomains && t.ent.length) {
        var avg = t.ent.reduce(function (a, b) { return a + b; }, 0) / t.ent.length;
        if (avg >= cfg.dns_tunnel_min_entropy) {
          var parts = k.split("|");
          out.push(F("dns_tunnel", "high", parts[0], parts[1], "Possible DNS tunneling",
            subs + " unique high entropy subdomains under " + parts[1] + " (average entropy " + avg.toFixed(1) + ").",
            t.first, t.last, 30, { parent: parts[1], unique_subdomains: subs, avg_entropy: +avg.toFixed(2), queries: t.count }));
        }
      }
    });
    Object.keys(nx).forEach(function (c) {
      var d = nx[c];
      if (d.nx >= cfg.dga_min_nxdomain && d.total && d.nx / d.total >= cfg.dga_min_ratio) {
        out.push(F("dga", "medium", c, "", "High rate of failed lookups",
          d.nx + " failed lookups out of " + d.total + " responses, which can indicate algorithmically generated domains.",
          d.first, d.last, 20, { nxdomain: d.nx, responses: d.total }));
      }
    });
    return out;
  }

  function detectBeacon(flows, cfg, ipDomain) {
    var groups = {}, out = [];
    flows.forEach(function (f) {
      var k = f.a_ip + "|" + f.b_ip + "|" + f.b_port;
      (groups[k] = groups[k] || []).push([f.first_ts, f.a_to_b_bytes]);
    });
    Object.keys(groups).forEach(function (k) {
      var evs = groups[k];
      if (evs.length < cfg.beacon_min_conns) return;
      evs.sort(function (a, b) { return a[0] - b[0]; });
      var ts = evs.map(function (e) { return e[0]; });
      var intervals = [];
      for (var i = 1; i < ts.length; i++) { var dt = ts[i] - ts[i - 1]; if (dt >= 0) intervals.push(dt); }
      if (intervals.length < cfg.beacon_min_conns - 1) return;
      var med = median(intervals); if (med <= 0.5) return;
      var mad = median(intervals.map(function (x) { return Math.abs(x - med); }));
      var score = Math.max(0, 1 - (med ? mad / med : 1));
      var sizes = evs.map(function (e) { return e[1]; });
      if (sizes.length >= 2 && median(sizes) > 0) {
        var sd = median(sizes.map(function (s) { return Math.abs(s - median(sizes)); })) / median(sizes);
        if (sd < 0.25) score = Math.min(1, score + 0.05);
      }
      if (score >= cfg.beacon_min_score) {
        var parts = k.split("|"), a = parts[0], b = parts[1], port = +parts[2];
        var dom = ipDomain[b] || "", ext = !isInternal(b);
        var name = b + (dom ? " (" + dom + ")" : "");
        out.push(F("beacon", ext ? "high" : "medium", a, b, "Periodic beaconing",
          evs.length + " connections to " + name + " on port " + port + ", about every " + humanInterval(med) + ".",
          ts[0], ts[ts.length - 1], ext ? 35 : 20,
          { count: evs.length, interval_seconds: +med.toFixed(1), regularity: +score.toFixed(2), port: port, domain: dom }));
      }
    });
    return out;
  }

  function detectExfil(flows, cfg, ipDomain) {
    var agg = {}, out = [];
    flows.forEach(function (f) {
      if (!f.b_ip || isInternal(f.b_ip)) return;
      var k = f.a_ip + "|" + f.b_ip;
      var d = agg[k] = agg[k] || { out: 0, in: 0, first: null, last: null, sni: "" };
      d.out += f.a_to_b_bytes; d.in += f.b_to_a_bytes;
      d.first = d.first === null ? f.first_ts : Math.min(d.first, f.first_ts);
      d.last = d.last === null ? f.last_ts : Math.max(d.last, f.last_ts);
      if (f.sni && !d.sni) d.sni = f.sni;
    });
    Object.keys(agg).forEach(function (k) {
      var d = agg[k];
      if (d.out >= cfg.exfil_min_bytes && d.out >= cfg.exfil_ratio * Math.max(d.in, 1)) {
        var parts = k.split("|"), a = parts[0], b = parts[1];
        var dom = d.sni || ipDomain[b] || "", name = b + (dom ? " (" + dom + ")" : "");
        out.push(F("exfil", d.out >= 5e7 ? "critical" : "high", a, b, "Large outbound transfer",
          humanBytes(d.out) + " sent from " + a + " to " + name + ", far more than was received.",
          d.first, d.last, 35, { bytes_out: d.out, bytes_in: d.in, domain: dom }));
      }
    });
    return out;
  }

  function detectCleartextCreds(flows) {
    var out = [], seen = {};
    flows.forEach(function (f) {
      if (f.http_auth) {
        var k = f.a_ip + "|" + f.b_ip; if (seen[k]) return; seen[k] = 1;
        var host = f.http_host || f.b_ip;
        out.push(F("cleartext_creds", "high", f.a_ip, f.b_ip, "Credentials sent in clear text",
          "An HTTP authorization header was sent to " + host + " without TLS.", f.first_ts, f.last_ts, 30, { host: host }));
      }
    });
    return out;
  }

  function detectCleartextProtocol(flows) {
    var out = [], seen = {};
    flows.forEach(function (f) {
      if (f.proto !== "TCP") return;
      var svc = CLEARTEXT[f.b_port]; if (!svc) return;
      if (!established(f)) return;
      var k = f.a_ip + "|" + f.b_ip + "|" + f.b_port; if (seen[k]) return; seen[k] = 1;
      var sev = (f.b_port === 21 || f.b_port === 23) ? "medium" : "low";
      out.push(F("cleartext_protocol", sev, f.a_ip, f.b_ip, svc + " in clear text",
        svc + " traffic to " + f.b_ip + " on port " + f.b_port + " is unencrypted and can expose data or credentials.",
        f.first_ts, f.last_ts, sev === "medium" ? 12 : 6, { service: svc, port: f.b_port }));
    });
    return out;
  }

  function detectLongConnections(flows, cfg) {
    var out = [];
    flows.forEach(function (f) {
      if (f.proto !== "TCP") return;
      if (duration(f) >= cfg.long_conn_seconds && totalBytes(f) >= cfg.long_conn_min_bytes) {
        var ext = !isInternal(f.b_ip), dom = f.sni || f.http_host, name = f.b_ip + (dom ? " (" + dom + ")" : "");
        out.push(F("long_connection", ext ? "medium" : "low", f.a_ip, f.b_ip, "Long lived connection",
          "A single connection to " + name + " on port " + f.b_port + " lasted " + humanInterval(duration(f)) + ".",
          f.first_ts, f.last_ts, ext ? 15 : 8, { duration_seconds: +duration(f).toFixed(1), port: f.b_port, bytes: totalBytes(f) }));
      }
    });
    return out;
  }

  function detectRareUa(flows, cfg) {
    var out = [], seen = {};
    flows.forEach(function (f) {
      var ua = (f.user_agent || "").toLowerCase(); if (!ua) return;
      var hit = null;
      for (var i = 0; i < cfg.rare_ua_tokens.length; i++) if (ua.indexOf(cfg.rare_ua_tokens[i]) >= 0) { hit = cfg.rare_ua_tokens[i]; break; }
      if (hit) {
        var k = f.a_ip + "|" + hit; if (seen[k]) return; seen[k] = 1;
        out.push(F("rare_user_agent", "low", f.a_ip, f.b_ip, "Automation user agent",
          f.a_ip + ' used the user agent "' + f.user_agent + '", which is common for scripts and tools.',
          f.first_ts, f.last_ts, 8, { user_agent: f.user_agent }));
      }
    });
    return out;
  }

  function detectFanout(flows, cfg) {
    var dsts = {}, span = {}, out = [];
    flows.forEach(function (f) {
      if (!isInternal(f.a_ip) || isInternal(f.b_ip) || !f.b_ip) return;
      (dsts[f.a_ip] = dsts[f.a_ip] || {})[f.b_ip] = 1;
      var s = span[f.a_ip] = span[f.a_ip] || [null, null];
      s[0] = s[0] === null ? f.first_ts : Math.min(s[0], f.first_ts);
      s[1] = s[1] === null ? f.last_ts : Math.max(s[1], f.last_ts);
    });
    Object.keys(dsts).forEach(function (h) {
      var n = Object.keys(dsts[h]).length;
      if (n >= cfg.fanout_min_hosts) {
        out.push(F("external_fanout", "medium", h, "", "Many external destinations",
          h + " connected to " + n + " distinct external hosts, which can indicate scanning or automated activity.",
          span[h][0], span[h][1], 15, { external_hosts: n }));
      }
    });
    return out;
  }

  function detectIocs(flows, dnsEvents, cfg) {
    if (!cfg.iocs || !cfg.iocs.length) return [];
    var set = {}; cfg.iocs.forEach(function (x) { set[x] = 1; });
    var out = [], seen = {};
    flows.forEach(function (f) {
      var cand = [f.b_ip, f.a_ip, f.sni, f.http_host].filter(function (c) { return c && set[c]; })[0];
      if (cand) { var k = f.a_ip + "|" + cand; if (seen[k]) return; seen[k] = 1;
        out.push(F("ioc", "critical", f.a_ip, f.b_ip, "Contact with a known indicator", "Traffic involving indicator " + cand + ".", f.first_ts, f.last_ts, 40, { indicator: cand })); }
    });
    dnsEvents.forEach(function (e) {
      [e.qname].concat(e.answers).forEach(function (cand) {
        if (set[cand] && !seen[e.client + "|" + cand]) { seen[e.client + "|" + cand] = 1;
          out.push(F("ioc", "critical", e.client, (cand.indexOf(".") >= 0 && /[a-z]/i.test(cand[0])) ? cand : "", "Contact with a known indicator", "DNS activity involving indicator " + cand + ".", e.ts, e.ts, 40, { indicator: cand })); }
      });
    });
    return out;
  }

  var SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  function runDetectors(built, cfg) {
    var f = [];
    f = f.concat(detectPortScans(built.flows, cfg));
    f = f.concat(detectDns(built.dnsEvents, cfg));
    f = f.concat(detectBeacon(built.flows, cfg, built.ipDomain));
    f = f.concat(detectExfil(built.flows, cfg, built.ipDomain));
    f = f.concat(detectCleartextCreds(built.flows));
    f = f.concat(detectCleartextProtocol(built.flows));
    f = f.concat(detectLongConnections(built.flows, cfg));
    f = f.concat(detectRareUa(built.flows, cfg));
    f = f.concat(detectFanout(built.flows, cfg));
    f = f.concat(detectIocs(built.flows, built.dnsEvents, cfg));
    f.forEach(function (x) { x.mitre = (MITRE[x.category] || []).map(function (m) { return { id: m[0], name: m[1] }; }); });
    f.sort(function (a, b) { return (SEV_RANK[a.severity] - SEV_RANK[b.severity]) || (b.score - a.score); });
    return f;
  }

  // ---- correlate ----
  function looksIp(v) { if (v.indexOf(":") >= 0) return true; var p = v.split("."); return p.length === 4 && p.every(function (x) { return /^\d+$/.test(x); }); }
  function headline(f) {
    var dom = f.evidence.domain || "";
    if (f.category === "beacon") { var t = f.dst + (dom ? " (" + dom + ")" : ""); var every = f.evidence.interval_seconds; return "Periodic beaconing to " + t + " begins" + (every ? ", about every " + Math.round(every) + "s" : ""); }
    if (f.category === "exfil") { var t2 = f.dst + (dom ? " (" + dom + ")" : ""); return "Large outbound transfer to " + t2 + " detected"; }
    if (f.category === "port_scan") return f.title + (f.dst ? " of " + f.dst : "");
    if (f.category === "dns_tunnel") return "Possible DNS tunneling to " + f.dst;
    if (f.category === "dga") return "High rate of failed DNS lookups";
    if (f.category === "cleartext_creds") return "Credentials sent in clear text to " + (f.evidence.host || f.dst);
    if (f.category === "cleartext_protocol") return (f.evidence.service || "A service") + " in clear text to " + f.dst;
    if (f.category === "external_fanout") return "Connections to " + (f.evidence.external_hosts || "many") + " external hosts";
    if (f.category === "long_connection") return "Long lived connection to " + f.dst + " on port " + (f.evidence.port || "");
    if (f.category === "rare_user_agent") return "Automation user agent seen: " + (f.evidence.user_agent || "");
    if (f.category === "ioc") return "Contact with known indicator " + (f.evidence.indicator || f.dst);
    return f.title;
  }
  function hypothesis(cats) {
    var has = function (c) { return cats.indexOf(c) >= 0; };
    if (has("ioc")) return "Contact with a known indicator";
    if (has("beacon") && has("exfil")) return "Possible command and control with data exfiltration";
    if (has("beacon") && (has("dns_tunnel") || has("dga"))) return "Possible command and control channel";
    if (has("beacon")) return "Possible command and control beaconing";
    if (has("dns_tunnel")) return "Possible DNS tunneling or covert channel";
    if (has("exfil")) return "Possible data exfiltration";
    if (has("cleartext_creds")) return "Credentials exposed in clear text";
    if (has("port_scan") || has("external_fanout")) return "Possible internal reconnaissance";
    if (has("cleartext_protocol")) return "Sensitive service exposed in clear text";
    if (has("dga")) return "Possible algorithmically generated domain activity";
    return "Unusual network activity";
  }
  function confidence(findings) {
    var base = { ioc: 75, beacon: 55, dns_tunnel: 55, exfil: 55, cleartext_creds: 60, port_scan: 50, dga: 45, external_fanout: 45, cleartext_protocol: 40, long_connection: 35, rare_user_agent: 30 };
    var cats = {}; findings.forEach(function (f) { cats[f.category] = 1; });
    var keys = Object.keys(cats);
    var start = 35; keys.forEach(function (c) { if ((base[c] || 35) > start) start = base[c] || 35; });
    var conf = start + (keys.length - 1) * 10;
    findings.forEach(function (f) { if (f.category === "beacon") conf += Math.round((f.evidence.regularity || 0) * 10); if (f.category === "ioc") conf += 10; });
    return Math.max(20, Math.min(95, conf));
  }
  function clockUTC(ts) { if (!ts) return "--:--:--"; return new Date(ts * 1000).toISOString().substr(11, 8); }
  var SUMMARY_ORDER = ["ioc", "beacon", "exfil", "dns_tunnel", "dga", "cleartext_creds", "cleartext_protocol", "port_scan", "external_fanout", "long_connection", "rare_user_agent"];
  function clause(f) {
    var cat = f.category, ev = f.evidence || {}, dst = f.dst || "";
    var dom = ev.domain || "", name = dst + (dom ? " (" + dom + ")" : "");
    if (cat === "beacon") return "periodic beaconing to " + (name || dst);
    if (cat === "exfil") return "a large outbound transfer to " + (name || dst);
    if (cat === "port_scan") return "a port scan of " + (dst || "internal hosts");
    if (cat === "dns_tunnel") return "DNS tunneling under " + (ev.parent || dst);
    if (cat === "dga") return "a high rate of failed DNS lookups";
    if (cat === "cleartext_creds") return "credentials sent in the clear";
    if (cat === "cleartext_protocol") return (ev.service || "a service") + " used in clear text";
    if (cat === "long_connection") return "a long lived connection to " + dst;
    if (cat === "rare_user_agent") return "an automation user agent";
    if (cat === "external_fanout") return "connections to many external hosts";
    if (cat === "ioc") return "contact with a known indicator";
    return (f.title || "").toLowerCase();
  }
  function summarize(host, hypothesis, confidence, findings, indicators, timeline) {
    var byCat = {};
    findings.forEach(function (f) { if (!(f.category in byCat)) byCat[f.category] = f; });
    var parts = [];
    SUMMARY_ORDER.forEach(function (c) { if (byCat[c]) parts.push(clause(byCat[c])); });
    Object.keys(byCat).forEach(function (c) { if (SUMMARY_ORDER.indexOf(c) < 0) parts.push(clause(byCat[c])); });
    var s = host + ": " + hypothesis.charAt(0).toLowerCase() + hypothesis.slice(1) + " (confidence " + confidence + "%).";
    var ts = timeline.map(function (e) { return e.ts; }).filter(function (t) { return t; });
    if (ts.length) s += " Activity ran from " + clockUTC(Math.min.apply(null, ts)) + " to " + clockUTC(Math.max.apply(null, ts)) + ".";
    if (parts.length) {
      var joined = parts.length === 1 ? parts[0] : parts.length === 2 ? parts[0] + " and " + parts[1] : parts.slice(0, -1).join(", ") + ", and " + parts[parts.length - 1];
      s += " It involved " + joined + ".";
    }
    if (indicators.length) s += " Indicators: " + indicators.join(", ") + ".";
    return s;
  }

  function correlate(findings, flows, dnsEvents, ipDomain) {
    var byHost = {};
    findings.forEach(function (f) { if (f.src) (byHost[f.src] = byHost[f.src] || []).push(f); });
    var flowsByPair = {};
    flows.forEach(function (f) { (flowsByPair[f.a_ip + "|" + f.b_ip] = flowsByPair[f.a_ip + "|" + f.b_ip] || []).push(f.first_ts); });
    var incidents = [];
    Object.keys(byHost).forEach(function (host) {
      var hf = byHost[host];
      var cats = []; hf.forEach(function (f) { if (cats.indexOf(f.category) < 0) cats.push(f.category); });
      var indicators = {}, timeline = [];
      hf.forEach(function (f) {
        if (f.dst) indicators[f.dst] = 1;
        ["domain", "parent", "indicator"].forEach(function (k) { if (f.evidence[k]) indicators[f.evidence[k]] = 1; });
        timeline.push({ ts: f.first_ts, host: host, text: headline(f) });
      });
      hf.forEach(function (f) {
        if (f.dst && looksIp(f.dst)) {
          var dom = ipDomain[f.dst] || "";
          if (dom) {
            var q = dnsEvents.filter(function (e) { return !e.is_response && e.client === host && e.qname.indexOf(dom) >= 0; }).map(function (e) { return e.ts; });
            if (q.length) timeline.push({ ts: Math.min.apply(null, q), host: host, text: "DNS query for " + dom });
          }
          var conns = flowsByPair[host + "|" + f.dst];
          if (conns) timeline.push({ ts: Math.min.apply(null, conns), host: host, text: "First connection to " + f.dst });
        }
      });
      var seen = {}, ordered = [];
      timeline.sort(function (a, b) { return a.ts - b.ts; }).forEach(function (ev) {
        var key = ev.ts.toFixed(3) + "|" + ev.text; if (seen[key]) return; seen[key] = 1; ordered.push(ev);
      });
      var inds = Object.keys(indicators).filter(Boolean).sort();
      incidents.push({ host: host, hypothesis: hypothesis(cats), confidence: confidence(hf), findings: hf, timeline: ordered, indicators: inds, summary: summarize(host, hypothesis(cats), confidence(hf), hf, inds, ordered) });
    });
    incidents.sort(function (a, b) { return b.confidence - a.confidence; });
    return incidents;
  }

  // ---- scoring and stats ----
  function scoreHosts(findings) {
    var s = {};
    findings.forEach(function (f) { if (f.src) s[f.src] = (s[f.src] || 0) + f.score; });
    Object.keys(s).forEach(function (h) { s[h] = Math.min(100, s[h]); });
    return s;
  }
  function computeStats(flows) {
    var proto = {}, talkers = {}, ports = {};
    flows.forEach(function (f) {
      proto[f.proto] = (proto[f.proto] || 0) + 1;
      talkers[f.a_ip] = (talkers[f.a_ip] || 0) + totalBytes(f);
      talkers[f.b_ip] = (talkers[f.b_ip] || 0) + totalBytes(f);
      if ((f.proto === "TCP" || f.proto === "UDP") && f.b_port) ports[f.b_port] = (ports[f.b_port] || 0) + 1;
    });
    function top(obj, keyName, valName) {
      return Object.keys(obj).map(function (k) { var o = {}; o[keyName] = keyName === "port" ? +k : k; o[valName] = obj[k]; return o; })
        .sort(function (a, b) { return b[valName] - a[valName]; }).slice(0, 10);
    }
    var protoSorted = {};
    Object.keys(proto).sort(function (a, b) { return proto[b] - proto[a]; }).forEach(function (k) { protoSorted[k] = proto[k]; });
    return { protocols: protoSorted, top_talkers: top(talkers, "host", "bytes"), top_ports: top(ports, "port", "flows") };
  }

  function flowDict(f) {
    return { proto: f.proto, src: f.a_ip, src_port: f.a_port, dst: f.b_ip, dst_port: f.b_port,
      first_ts: f.first_ts, last_ts: f.last_ts, duration: +duration(f).toFixed(3),
      bytes_out: f.a_to_b_bytes, bytes_in: f.b_to_a_bytes, pkts_out: f.a_to_b_pkts, pkts_in: f.b_to_a_pkts,
      established: established(f), reset: f.saw_rst, sni: f.sni, http_host: f.http_host, user_agent: f.user_agent, resolved: !!(f.sni || f.http_host) };
  }

  function computeActivity(packets, first, last, nb) {
    nb = nb || 48;
    if (!packets.length) return { bucket_seconds: 0, start: first, buckets: [] };
    var span = last - first;
    if (span <= 0) {
      var total = 0; packets.forEach(function (p) { total += p.length; });
      return { bucket_seconds: 0, start: first, buckets: [{ t: first, bytes: total, packets: packets.length }] };
    }
    var bs = span / nb, byts = [], pkts = [], i;
    for (i = 0; i < nb; i++) { byts[i] = 0; pkts[i] = 0; }
    packets.forEach(function (p) {
      var idx = Math.floor((p.ts - first) / span * nb);
      if (idx < 0) idx = 0; else if (idx >= nb) idx = nb - 1;
      byts[idx] += p.length; pkts[idx] += 1;
    });
    var buckets = [];
    for (i = 0; i < nb; i++) buckets.push({ t: first + i * bs, bytes: byts[i], packets: pkts[i] });
    return { bucket_seconds: bs, start: first, buckets: buckets };
  }

  function analyze(buf, cfg) {
    cfg = mergeCfg(cfg);
    var packets = readPackets(buf).map(function (p) { return decode(p.ts, p.linktype, p.data); }).filter(Boolean);
    var built = buildFlows(packets);
    var findings = runDetectors(built, cfg);
    var incidents = correlate(findings, built.flows, built.dnsEvents, built.ipDomain);
    var stats = computeStats(built.flows);
    stats.activity = computeActivity(packets, built.first, built.last);
    return {
      tool: "nethawk", version: VERSION, path: "capture.pcap",
      packet_count: built.count, duration: +Math.max(0, built.last - built.first).toFixed(3),
      first_ts: built.first, last_ts: built.last,
      hosts_internal: built.internal, hosts_external: built.external,
      host_scores: scoreHosts(findings), stats: stats,
      flows: built.flows.map(flowDict), findings: findings, incidents: incidents
    };
  }
  function mergeCfg(cfg) {
    var out = {}; for (var k in DEFAULTS) out[k] = DEFAULTS[k];
    if (cfg) for (var j in cfg) out[j] = cfg[j];
    return out;
  }

  var api = { analyze: analyze, VERSION: VERSION, isInternal: isInternal };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.NetHawkEngine = api;
})(typeof self !== "undefined" ? self : this);
