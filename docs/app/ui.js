/* NetHawk demo front end.
 *
 * Runs entirely in the browser. Analysis happens client side through
 * NetHawkEngine (app/engine.js); nothing is uploaded anywhere.
 *
 * The sign in is a front door for this public demo, not a security control:
 * the check runs in the browser and the credentials are shown on the page.
 */
(function () {
  "use strict";

  // Demo credentials. Shown on the login card on purpose.
  var DEMO_USER = "demo";
  var DEMO_PASS = "nethawk";
  var SESSION_KEY = "nethawk_demo_signed_in";

  var DATA = null;
  var findSev = "all", findQ = "", flowSort = "bytes", flowDir = "desc", flowQ = "", focusHost = null;

  function $(s, r) { return (r || document).querySelector(s); }
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }
  function fmtBytes(n) { n = Number(n) || 0; var u = ["B", "KB", "MB", "GB", "TB"], i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return (i === 0 ? n : n.toFixed(1)) + " " + u[i]; }
  function fmtDur(s) { s = Math.floor(Number(s) || 0); var h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60; return h ? h + "h " + m + "m" : (m ? m + "m " + x + "s" : x + "s"); }
  function clock(ts) { if (!ts) return "--:--:--"; return new Date(ts * 1000).toISOString().substr(11, 8); }
  var SEV = { critical: "var(--crit)", high: "var(--red)", medium: "var(--yellow)", low: "var(--teal)", info: "var(--dim)" };
  function scoreColor(v) { return v >= 70 ? "var(--crit)" : v >= 40 ? "var(--yellow)" : "var(--teal)"; }
  function confColor(v) { return v >= 70 ? "var(--crit)" : v >= 45 ? "var(--yellow)" : "var(--teal)"; }
  var TACTIC_ORDER = ["Discovery", "Credential Access", "Command and Control", "Exfiltration"];
  var TECH_TACTIC = {
    "T1046": "Discovery", "T1040": "Credential Access", "T1552": "Credential Access",
    "T1071": "Command and Control", "T1071.001": "Command and Control",
    "T1071.004": "Command and Control", "T1568.002": "Command and Control",
    "T1572": "Command and Control", "T1048": "Exfiltration"
  };
  var LANE_COLORS = ["var(--crit)", "var(--violet)", "var(--teal)", "var(--yellow)", "var(--green)"];

  // ---------- login ----------
  function showApp() { $("#login").classList.add("hidden"); $("#app").classList.remove("hidden"); }
  function signIn(u, p) {
    if (u === DEMO_USER && p === DEMO_PASS) {
      try { sessionStorage.setItem(SESSION_KEY, "1"); } catch (e) {}
      $("#login-err").textContent = "";
      showApp();
      return true;
    }
    $("#login-err").textContent = "Incorrect username or password.";
    return false;
  }
  function signOut() {
    try { sessionStorage.removeItem(SESSION_KEY); } catch (e) {}
    DATA = null;
    $("#dash").innerHTML = "";
    $("#intro").classList.remove("hidden");
    $("#exports").classList.add("hidden");
    $("#app").classList.add("hidden");
    $("#login").classList.remove("hidden");
    $("#password").value = "";
  }

  // ---------- analysis ----------
  function analyzeBuffer(buf) {
    $("#err").textContent = "";
    $("#intro").classList.add("hidden");
    $("#spin").classList.remove("hidden");
    // Defer so the spinner paints before the parse runs.
    setTimeout(function () {
      try {
        var result = window.NetHawkEngine.analyze(buf);
        DATA = result;
        $("#spin").classList.add("hidden");
        $("#exports").classList.remove("hidden");
        render(result);
      } catch (e) {
        $("#spin").classList.add("hidden");
        $("#intro").classList.remove("hidden");
        $("#err").textContent = String(e && e.message ? e.message : e);
      }
    }, 30);
  }
  function loadSample(file, name) {
    $("#err").textContent = "";
    fetch(file).then(function (r) {
      if (!r.ok) throw new Error("could not load the capture");
      return r.arrayBuffer();
    }).then(function (b) { DATA_NAME = name || "sample.pcap"; analyzeBuffer(b); })
      .catch(function (e) { $("#err").textContent = String(e.message || e); });
  }
  var DATA_NAME = "capture.pcap";

  // ---------- render ----------
  function card(n, l) { return '<div class="card"><div class="n">' + esc(n) + '</div><div class="l">' + esc(l) + "</div></div>"; }

  function setFocus(h) {
    focusHost = (focusHost === h) ? null : h;
    var bar = $("#focusbar");
    if (bar) {
      if (focusHost) {
        bar.innerHTML = 'Focused on <b class="mono">' + esc(focusHost) + '</b> <button class="chip" id="clearfocus">show all</button>';
        bar.classList.remove("hidden");
        $("#clearfocus").onclick = function () { setFocus(focusHost); };
      } else { bar.classList.add("hidden"); bar.innerHTML = ""; }
    }
    Array.prototype.forEach.call(document.querySelectorAll("#dash tr[data-host]"), function (tr) {
      if (tr.getAttribute("data-host") === focusHost) tr.classList.add("on"); else tr.classList.remove("on");
    });
    renderFindings(); renderFlows(); renderNetwork();
  }

  function render(data) {
    DATA = data; focusHost = null;
    var sc = {}; (data.findings || []).forEach(function (f) { sc[f.severity] = (sc[f.severity] || 0) + 1; });
    var top = "none"; ["critical", "high", "medium", "low"].forEach(function (s) { if (top === "none" && sc[s]) top = s; });
    var started = data.first_ts ? new Date(data.first_ts * 1000).toISOString().replace("T", " ").substr(0, 19) + " UTC" : "unknown";

    var html = "";
    html += '<p class="tag-line">' + esc(DATA_NAME) + " &middot; started " + esc(started) + "</p>";
    html += '<div id="focusbar" class="focusbar hidden"></div>';
    html += '<div class="cards">';
    html += card(data.packet_count, "packets");
    html += card((data.flows || []).length, "flows");
    html += card(fmtDur(data.duration), "duration");
    html += card((data.hosts_internal || []).length + " / " + (data.hosts_external || []).length, "hosts in / out");
    html += card((data.incidents || []).length, "incidents");
    html += '<div class="card"><div class="n" style="color:' + (SEV[top] || "var(--dim)") + '">' + esc(top) + '</div><div class="l">highest severity</div></div>';
    html += "</div>";

    // severity summary
    var order = ["critical", "high", "medium", "low", "info"];
    html += '<div class="sevbar">';
    order.forEach(function (s) { if (sc[s]) html += '<span class="sevchip" style="color:' + SEV[s] + ';border-color:' + SEV[s] + '">' + sc[s] + " " + s + "</span>"; });
    if (!(data.findings || []).length) html += '<span class="sevchip" style="color:var(--green);border-color:var(--green)">no findings</span>';
    html += "</div>";

    // host risk
    var hs = data.host_scores || {}; var keys = Object.keys(hs).sort(function (a, b) { return hs[b] - hs[a]; });
    if (keys.length) {
      html += "<h2>Host risk</h2><table><tr><th>host</th><th>score</th><th></th></tr>";
      keys.forEach(function (k) { var v = hs[k]; html += '<tr data-host="' + esc(k) + '" class="clickrow"><td class="mono">' + esc(k) + "</td><td>" + v + '</td><td><div class="bar"><span style="width:' + Math.min(100, v) + "%;background:" + scoreColor(v) + '"></span></div></td></tr>'; });
      html += "</table>";
    }

    html += '<div class="nav">'
      + '<button data-tab="inc" class="active">Incidents</button>'
      + '<button data-tab="find">Findings</button>'
      + '<button data-tab="flow">Flows</button>'
      + '<button data-tab="net">Network</button>'
      + '<button data-tab="traf">Traffic</button></div>';
    html += '<div id="p-inc" class="panel active"></div>';
    html += '<div id="p-find" class="panel"></div>';
    html += '<div id="p-flow" class="panel"></div>';
    html += '<div id="p-net" class="panel"></div>';
    html += '<div id="p-traf" class="panel"></div>';
    html += '<p class="foot">Analyzed in your browser by NetHawk ' + esc(data.version || "") + ". Nothing was uploaded. Analyze only captures you are authorized to inspect.</p>";

    $("#dash").innerHTML = html;
    Array.prototype.forEach.call(document.querySelectorAll(".nav button"), function (b) {
      b.onclick = function () {
        Array.prototype.forEach.call(document.querySelectorAll(".nav button"), function (x) { x.classList.remove("active"); });
        Array.prototype.forEach.call(document.querySelectorAll(".panel"), function (x) { x.classList.remove("active"); });
        b.classList.add("active"); $("#p-" + b.getAttribute("data-tab")).classList.add("active");
      };
    });
    Array.prototype.forEach.call(document.querySelectorAll("#dash tr[data-host]"), function (tr) {
      tr.onclick = function () { setFocus(tr.getAttribute("data-host")); };
    });
    renderIncidents(); renderFindings(); renderFlows(); renderNetwork(); renderTraffic();
  }

  function attackTimeline(incidents) {
    var events = [];
    incidents.forEach(function (i) { (i.timeline || []).forEach(function (e) { if (e.ts) events.push(e); }); });
    if (events.length < 2) return "";
    var first = Math.min.apply(null, events.map(function (e) { return e.ts; }));
    var last = Math.max.apply(null, events.map(function (e) { return e.ts; }));
    var firstByHost = {};
    events.forEach(function (e) { if (firstByHost[e.host] == null || e.ts < firstByHost[e.host]) firstByHost[e.host] = e.ts; });
    var hosts = Object.keys(firstByHost).sort(function (a, b) { return firstByHost[a] - firstByHost[b]; });
    var colorByHost = {}; hosts.forEach(function (h, i) { colorByHost[h] = LANE_COLORS[i % LANE_COLORS.length]; });
    var W = 700, padL = 96, padR = 20, top = 22, laneH = 44, H = top + hosts.length * laneH + 34, span = last - first;
    function x(ts) { return span > 0 ? padL + (ts - first) / span * (W - padL - padR) : padL; }
    var svg = "";
    hosts.forEach(function (h, i) {
      var y = top + i * laneH + laneH / 2;
      svg += '<line x1="' + padL + '" y1="' + y + '" x2="' + (W - padR) + '" y2="' + y + '" stroke="var(--line)" stroke-width="1"/>';
      svg += '<text x="4" y="' + (y + 4) + '" font-size="11" fill="' + colorByHost[h] + '">' + esc(shortHost(h)) + "</text>";
      var evs = events.filter(function (e) { return e.host === h; }).sort(function (a, b) { return a.ts - b.ts; });
      for (var j = 1; j < evs.length; j++) svg += '<line x1="' + x(evs[j - 1].ts).toFixed(1) + '" y1="' + y + '" x2="' + x(evs[j].ts).toFixed(1) + '" y2="' + y + '" stroke="' + colorByHost[h] + '" stroke-opacity="0.35" stroke-width="2"/>';
      evs.forEach(function (e) { svg += '<circle cx="' + x(e.ts).toFixed(1) + '" cy="' + y + '" r="5" fill="' + colorByHost[h] + '"><title>' + clock(e.ts) + "  " + esc(e.text) + "</title></circle>"; });
    });
    var ay = H - 14;
    [0, 0.5, 1].forEach(function (f) {
      var ts = first + span * f, xx = x(ts), anchor = f === 0 ? "start" : f === 1 ? "end" : "middle";
      svg += '<text x="' + xx.toFixed(1) + '" y="' + ay + '" font-size="10" fill="var(--dim)" text-anchor="' + anchor + '">' + clock(ts) + "</text>";
    });
    return '<h2>Attack timeline</h2><div class="chart"><svg viewBox="0 0 ' + W + " " + H + '" class="swim" preserveAspectRatio="xMidYMid meet">' + svg + "</svg></div>";
  }

  function incidentEvidence(inc) {
    var h = '<div class="evidence hidden">';
    if (inc.findings && inc.findings.length) {
      h += '<div class="ev-h">Findings behind this incident</div>';
      inc.findings.forEach(function (f) {
        var att = (f.mitre || []).map(function (m) { return m.id; }).join(" ");
        h += '<div class="ev-f"><span class="sev" style="color:' + (SEV[f.severity] || "var(--dim)") + '">' + esc(f.severity) + "</span> "
          + "<b>" + esc(f.category) + "</b> " + (att ? '<span class="mono muted">' + esc(att) + "</span> " : "")
          + '<span class="muted">' + esc(f.detail) + "</span></div>";
      });
    }
    var indSet = {}; (inc.indicators || []).forEach(function (x) { indSet[x] = 1; });
    var flows = (DATA.flows || []).filter(function (fl) { return fl.src === inc.host && (indSet[fl.dst] || indSet[fl.sni] || indSet[fl.http_host]); });
    if (!flows.length) flows = (DATA.flows || []).filter(function (fl) { return fl.src === inc.host; });
    flows = flows.slice(0, 12);
    if (flows.length) {
      h += '<div class="ev-h">Key flows</div><table><tr><th>start</th><th>destination</th><th>port</th><th>out</th><th>in</th><th>name</th></tr>';
      flows.forEach(function (fl) {
        var name = fl.sni || fl.http_host || "";
        h += '<tr><td class="mono">' + clock(fl.first_ts) + '</td><td class="mono">' + esc(fl.dst) + '</td><td class="mono">' + fl.dst_port + '</td><td class="mono">' + fmtBytes(fl.bytes_out) + '</td><td class="mono">' + fmtBytes(fl.bytes_in) + '</td><td class="muted">' + esc(name) + "</td></tr>";
      });
      h += "</table>";
    }
    return h + "</div>";
  }

  function renderIncidents() {
    var el = $("#p-inc"); var inc = DATA.incidents || [];
    if (!inc.length) { el.innerHTML = '<p class="muted">No incidents reconstructed.</p>'; return; }
    var h = attackTimeline(inc);
    inc.forEach(function (i) {
      h += '<div class="inc"><div class="top"><div><span class="host mono" data-host="' + esc(i.host) + '">' + esc(i.host) + '</span> <span>&middot; ' + esc(i.hypothesis) + "</span></div>"
        + '<span class="pill" style="background:' + confColor(i.confidence) + '">confidence ' + i.confidence + "%</span></div>";
      if (i.summary) h += '<p class="summary">' + esc(i.summary) + "</p>";
      if (i.timeline && i.timeline.length) { h += '<ul class="tl">'; i.timeline.forEach(function (e) { h += '<li><span class="t">' + clock(e.ts) + "</span>" + esc(e.text) + "</li>"; }); h += "</ul>"; }
      h += '<button class="ev-toggle chip">show evidence</button>';
      h += incidentEvidence(i);
      h += "</div>";
    });
    el.innerHTML = h;
    Array.prototype.forEach.call(el.querySelectorAll(".host[data-host]"), function (s) {
      s.style.cursor = "pointer"; s.onclick = function () { setFocus(s.getAttribute("data-host")); };
    });
    Array.prototype.forEach.call(el.querySelectorAll(".ev-toggle"), function (btn) {
      btn.onclick = function () { var ev = btn.nextElementSibling; var hidden = ev.classList.toggle("hidden"); btn.textContent = hidden ? "show evidence" : "hide evidence"; };
    });
  }

  function techniquesObserved() {
    var seen = {}, list = [];
    (DATA.findings || []).forEach(function (f) { (f.mitre || []).forEach(function (m) { if (!seen[m.id]) { seen[m.id] = 1; list.push(m); } }); });
    return list;
  }

  function attckMatrix() {
    var techs = techniquesObserved(); if (!techs.length) return "";
    var byTactic = {};
    techs.forEach(function (m) { var t = TECH_TACTIC[m.id] || "Other"; (byTactic[t] = byTactic[t] || []).push(m); });
    var order = TACTIC_ORDER.filter(function (t) { return byTactic[t]; });
    Object.keys(byTactic).forEach(function (t) { if (order.indexOf(t) < 0) order.push(t); });
    var h = '<div class="matrix">';
    order.forEach(function (t) {
      h += '<div class="col"><div class="col-h">' + esc(t) + "</div>";
      byTactic[t].forEach(function (m) { h += '<span class="t"><b>' + esc(m.id) + "</b> " + esc(m.name) + "</span>"; });
      h += "</div>";
    });
    return h + "</div>";
  }

  function renderFindings() {
    var el = $("#p-find");
    var th = attckMatrix();
    var chips = ["all", "critical", "high", "medium", "low"];
    var c = '<div class="controls">';
    chips.forEach(function (s) { c += '<button class="chip' + (findSev === s ? " on" : "") + '" data-sev="' + s + '">' + s + "</button>"; });
    c += '<input type="text" id="fq" placeholder="search findings" value="' + esc(findQ) + '"></div>';
    var rows = (DATA.findings || []).filter(function (f) {
      if (focusHost && f.src !== focusHost && f.dst !== focusHost) return false;
      if (findSev !== "all" && f.severity !== findSev) return false;
      if (findQ) { var s = (f.category + " " + f.src + " " + f.dst + " " + f.title + " " + f.detail).toLowerCase(); if (s.indexOf(findQ.toLowerCase()) < 0) return false; }
      return true;
    });
    var t = "<table><tr><th>severity</th><th>type</th><th>source</th><th>target</th><th>att&amp;ck</th><th>detail</th></tr>";
    if (!rows.length) t += '<tr><td colspan="6" class="muted">No matching findings.</td></tr>';
    rows.forEach(function (f) {
      var att = (f.mitre || []).map(function (m) { return m.id; }).join(" ");
      t += '<tr><td><span class="sev" style="color:' + (SEV[f.severity] || "var(--dim)") + '">' + esc(f.severity) + "</span></td>"
        + "<td>" + esc(f.category) + '</td><td class="mono">' + esc(f.src) + '</td><td class="mono">' + esc(f.dst || "") + "</td>"
        + '<td class="muted mono">' + esc(att) + "</td>"
        + '<td class="muted">' + esc(f.detail) + "</td></tr>";
    });
    t += "</table>";
    el.innerHTML = th + c + t;
    Array.prototype.forEach.call(el.querySelectorAll(".chip"), function (b) { b.onclick = function () { findSev = b.getAttribute("data-sev"); renderFindings(); }; });
    var q = $("#fq", el); q.oninput = function () { findQ = q.value; var pos = q.selectionStart; renderFindings(); var nq = $("#fq"); if (nq) { nq.focus(); try { nq.selectionStart = nq.selectionEnd = pos; } catch (e) {} } };
  }

  function renderFlows() {
    var el = $("#p-flow");
    var c = '<div class="controls"><input type="text" id="flq" placeholder="filter by host, port, or name" value="' + esc(flowQ) + '"></div>';
    var flows = (DATA.flows || []).slice();
    if (focusHost) flows = flows.filter(function (f) { return f.src === focusHost || f.dst === focusHost; });
    if (flowQ) { var q = flowQ.toLowerCase(); flows = flows.filter(function (f) { var s = (f.src + " " + f.dst + " " + f.dst_port + " " + (f.sni || "") + " " + (f.http_host || "") + " " + f.proto).toLowerCase(); return s.indexOf(q) >= 0; }); }
    flows.sort(function (a, b) {
      var x, y;
      if (flowSort === "bytes") { x = a.bytes_out + a.bytes_in; y = b.bytes_out + b.bytes_in; }
      else if (flowSort === "out") { x = a.bytes_out; y = b.bytes_out; }
      else if (flowSort === "duration") { x = a.duration; y = b.duration; }
      else if (flowSort === "port") { x = a.dst_port; y = b.dst_port; }
      else { x = a.first_ts; y = b.first_ts; }
      return flowDir === "desc" ? y - x : x - y;
    });
    var total = flows.length, cap = 500, shown = flows.slice(0, cap);
    function th(k, label) { var ar = flowSort === k ? (flowDir === "desc" ? " \u25be" : " \u25b4") : ""; return '<th class="sortable" data-k="' + k + '">' + label + ar + "</th>"; }
    var t = "<table><tr>" + th("start", "start") + "<th>proto</th><th>source</th><th>destination</th>" + th("port", "port") + th("out", "out") + "<th>in</th>" + th("duration", "duration") + "<th>name</th></tr>";
    if (!shown.length) t += '<tr><td colspan="9" class="muted">No matching flows.</td></tr>';
    shown.forEach(function (f) {
      var name = f.sni || f.http_host || "";
      t += '<tr><td class="mono">' + clock(f.first_ts) + "</td><td>" + esc(f.proto) + "</td>"
        + '<td class="mono">' + esc(f.src) + ":" + f.src_port + '</td><td class="mono">' + esc(f.dst) + "</td>"
        + '<td class="mono">' + f.dst_port + '</td><td class="mono">' + fmtBytes(f.bytes_out) + "</td>"
        + '<td class="mono">' + fmtBytes(f.bytes_in) + '</td><td class="mono">' + fmtDur(f.duration) + "</td>"
        + '<td class="muted">' + esc(name) + "</td></tr>";
    });
    t += "</table>";
    if (total > cap) t += '<p class="note">Showing the first ' + cap + " of " + total + " flows. Use the filter to narrow down.</p>";
    el.innerHTML = c + t;
    Array.prototype.forEach.call(el.querySelectorAll("th.sortable"), function (h) {
      h.onclick = function () { var k = h.getAttribute("data-k"); if (flowSort === k) { flowDir = flowDir === "desc" ? "asc" : "desc"; } else { flowSort = k; flowDir = "desc"; } renderFlows(); };
    });
    var q2 = $("#flq", el); q2.oninput = function () { flowQ = q2.value; var pos = q2.selectionStart; renderFlows(); var nq = $("#flq"); if (nq) { nq.focus(); try { nq.selectionStart = nq.selectionEnd = pos; } catch (e) {} } };
  }

  function shortHost(h) {
    if (h.indexOf(":") >= 0) return h.split(":").slice(-2).join(":");
    var p = h.split("."); return p.length === 4 ? p.slice(-2).join(".") : h;
  }

  function renderNetwork() {
    var el = $("#p-net");
    var flows = DATA.flows || [];
    if (!flows.length) { el.innerHTML = '<p class="muted">No conversations to graph.</p>'; return; }
    var bytesBy = {}, edges = {};
    flows.forEach(function (f) {
      var w = f.bytes_out + f.bytes_in;
      bytesBy[f.src] = (bytesBy[f.src] || 0) + w; bytesBy[f.dst] = (bytesBy[f.dst] || 0) + w;
      var k = f.src < f.dst ? f.src + "|" + f.dst : f.dst + "|" + f.src;
      edges[k] = (edges[k] || 0) + w;
    });
    var hosts = Object.keys(bytesBy).sort(function (a, b) { return bytesBy[b] - bytesBy[a]; });
    var cap = 40, shown = hosts.slice(0, cap), cx = 350, cy = 250, R = 200, N = shown.length, posByHost = {};
    shown.forEach(function (h, i) { var a = -Math.PI / 2 + 2 * Math.PI * i / Math.max(1, N); posByHost[h] = { h: h, a: a, x: cx + R * Math.cos(a), y: cy + R * Math.sin(a) }; });
    var internalSet = {}; (DATA.hosts_internal || []).forEach(function (h) { internalSet[h] = 1; });
    var scores = DATA.host_scores || {};
    var neighbors = {};
    if (focusHost) Object.keys(edges).forEach(function (k) { var pr = k.split("|"); if (pr[0] === focusHost) neighbors[pr[1]] = 1; else if (pr[1] === focusHost) neighbors[pr[0]] = 1; });
    var emax = Math.max.apply(null, Object.keys(edges).map(function (k) { return edges[k]; }).concat([1]));
    var lines = "";
    Object.keys(edges).forEach(function (k) {
      var pr = k.split("|"); if (!posByHost[pr[0]] || !posByHost[pr[1]]) return;
      var p1 = posByHost[pr[0]], p2 = posByHost[pr[1]], op;
      if (focusHost) op = (pr[0] === focusHost || pr[1] === focusHost) ? 0.6 : 0.04;
      else op = 0.06 + 0.5 * edges[k] / emax;
      lines += '<line x1="' + p1.x.toFixed(1) + '" y1="' + p1.y.toFixed(1) + '" x2="' + p2.x.toFixed(1) + '" y2="' + p2.y.toFixed(1) + '" stroke="var(--teal)" stroke-opacity="' + op.toFixed(2) + '" stroke-width="1"/>';
    });
    var bmax = Math.max.apply(null, shown.map(function (h) { return bytesBy[h]; }).concat([1])), nodes = "", labels = "";
    shown.forEach(function (h) {
      var p = posByHost[h], sc = scores[h] || 0;
      var color = sc >= 70 ? "var(--crit)" : sc >= 40 ? "var(--yellow)" : internalSet[h] ? "var(--teal)" : "var(--dim)";
      var r = (4 + 9 * Math.sqrt(bytesBy[h] / bmax)).toFixed(1);
      var op = !focusHost ? 0.92 : (h === focusHost || neighbors[h] ? 0.98 : 0.16);
      var stroke = h === focusHost ? "var(--text)" : "#0d0e14", sw = h === focusHost ? 2 : 1;
      nodes += '<circle data-host="' + esc(h) + '" cx="' + p.x.toFixed(1) + '" cy="' + p.y.toFixed(1) + '" r="' + r + '" fill="' + color + '" fill-opacity="' + op + '" stroke="' + stroke + '" stroke-width="' + sw + '" style="cursor:pointer"><title>' + esc(h) + (sc ? " \u00b7 risk " + sc : "") + " \u00b7 " + fmtBytes(bytesBy[h]) + "</title></circle>";
      var showLabel = (!focusHost && (sc >= 40 || bytesBy[h] >= 0.14 * bmax)) || (focusHost && (h === focusHost || neighbors[h]));
      if (showLabel) {
        var lx = cx + (R + 12) * Math.cos(p.a), ly = cy + (R + 12) * Math.sin(p.a);
        var anchor = Math.cos(p.a) < -0.3 ? "end" : (Math.cos(p.a) > 0.3 ? "start" : "middle");
        labels += '<text x="' + lx.toFixed(1) + '" y="' + (ly + 3).toFixed(1) + '" text-anchor="' + anchor + '" font-size="10" fill="var(--dim)">' + esc(shortHost(h)) + "</text>";
      }
    });
    var legend = '<div class="legend">'
      + '<span><i style="background:var(--crit)"></i> high risk</span>'
      + '<span><i style="background:var(--yellow)"></i> elevated</span>'
      + '<span><i style="background:var(--teal)"></i> internal</span>'
      + '<span><i style="background:var(--dim)"></i> external</span></div>';
    var note = hosts.length > cap ? '<p class="note">Showing the ' + cap + " busiest hosts of " + hosts.length + ". Click a host to focus. Node size is total traffic; edges are conversations.</p>"
      : '<p class="note">Click a host to focus. Node size is total traffic; edges are conversations.</p>';
    el.innerHTML = "<h2>Host graph</h2>" + legend
      + '<div class="chart"><svg viewBox="0 0 700 500" class="netsvg" preserveAspectRatio="xMidYMid meet">' + lines + nodes + labels + "</svg></div>" + note;
    Array.prototype.forEach.call(el.querySelectorAll("circle[data-host]"), function (c) { c.onclick = function () { setFocus(c.getAttribute("data-host")); }; });
  }

  function activityChart(act) {
    if (!act || !act.buckets || act.buckets.length < 2) return "";
    var b = act.buckets, n = b.length;
    var max = Math.max.apply(null, b.map(function (x) { return x.bytes; }).concat([1]));
    var W = n * 10, H = 120, bars = "";
    b.forEach(function (x, i) {
      var bh = Math.max(0, Math.round((H - 6) * x.bytes / max));
      bars += '<rect x="' + (i * 10 + 1) + '" y="' + (H - bh) + '" width="8" height="' + bh + '" fill="var(--teal)" fill-opacity="0.85"><title>' + clock(x.t) + "  " + fmtBytes(x.bytes) + "  " + x.packets + " pkts</title></rect>";
    });
    var endT = b[n - 1].t + (act.bucket_seconds || 0);
    return "<h2>Activity over time</h2><div class=\"chart\"><svg viewBox=\"0 0 " + W + " " + H + "\" preserveAspectRatio=\"none\" class=\"tsvg\">" + bars + "</svg></div>"
      + '<div class="axis"><span>' + clock(b[0].t) + "</span><span>peak " + fmtBytes(max) + "</span><span>" + clock(endT) + "</span></div>";
  }

  function renderTraffic() {
    var el = $("#p-traf"); var st = DATA.stats || {};
    var h = activityChart(st.activity);
    var protos = st.protocols || {}; var pk = Object.keys(protos); var pmax = Math.max.apply(null, pk.map(function (k) { return protos[k]; }).concat([1]));
    h += "<h2>Protocols</h2><table>";
    pk.forEach(function (k) { h += '<tr><td class="mono">' + esc(k) + '</td><td class="mono">' + protos[k] + ' flows</td><td><div class="bar"><span style="width:' + (100 * protos[k] / pmax) + '%;background:var(--violet)"></span></div></td></tr>'; });
    h += "</table>";
    var tt = st.top_talkers || []; var tmax = Math.max.apply(null, tt.map(function (x) { return x.bytes; }).concat([1]));
    h += "<h2>Top talkers</h2><table>";
    tt.forEach(function (x) { h += '<tr><td class="mono">' + esc(x.host) + '</td><td class="mono">' + fmtBytes(x.bytes) + '</td><td><div class="bar"><span style="width:' + (100 * x.bytes / tmax) + '%;background:var(--teal)"></span></div></td></tr>'; });
    h += "</table>";
    var tp = st.top_ports || [];
    h += "<h2>Top destination ports</h2><table><tr><th>port</th><th>flows</th></tr>";
    tp.forEach(function (x) { h += '<tr><td class="mono">' + x.port + '</td><td class="mono">' + x.flows + "</td></tr>"; });
    h += "</table>";
    el.innerHTML = h;
  }

  // ---------- export ----------
  function download(name, text, type) {
    var blob = new Blob([text], { type: type || "text/plain" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url; a.download = name; document.body.appendChild(a); a.click();
    document.body.removeChild(a); setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }
  function exportJson() { if (DATA) download("nethawk-report.json", JSON.stringify(DATA, null, 2), "application/json"); }
  function exportIndicators() {
    if (!DATA) return;
    var set = {};
    (DATA.findings || []).forEach(function (f) {
      if (f.dst) set[f.dst] = 1;
      ["domain", "parent", "indicator", "host"].forEach(function (k) { if (f.evidence && f.evidence[k]) set[f.evidence[k]] = 1; });
    });
    (DATA.incidents || []).forEach(function (i) { (i.indicators || []).forEach(function (x) { if (x) set[x] = 1; }); });
    var lines = Object.keys(set).filter(Boolean).sort();
    var text = "# NetHawk indicators from " + DATA_NAME + "\n# " + lines.length + " indicators\n" + lines.join("\n") + "\n";
    download("nethawk-indicators.txt", text, "text/plain");
  }
  function exportHtml() {
    if (!DATA) return;
    fetch("app/styles.css").then(function (r) { return r.text(); }).then(function (css) {
      var clone = $("#dash").cloneNode(true);
      var nav = clone.querySelector(".nav"); if (nav) nav.parentNode.removeChild(nav);
      var doc = "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        + "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        + "<title>NetHawk report</title><style>" + css + "\n.panel{display:block!important}\nbody{padding:0}</style>"
        + "</head><body><div class='wrap'><div class='topbar'><div class='brand'>"
        + "<span style='font-size:22px'>&#129413;</span><h1>NetHawk report</h1></div></div>"
        + clone.innerHTML + "</div></body></html>";
      download("nethawk-report.html", doc, "text/html");
    });
  }

  // ---------- wiring ----------
  window.addEventListener("load", function () {
    // login form
    var form = $("#login-form");
    if (form) form.addEventListener("submit", function (e) {
      e.preventDefault();
      signIn($("#username").value.trim(), $("#password").value);
    });
    try { if (sessionStorage.getItem(SESSION_KEY) === "1") showApp(); } catch (e) {}

    // dropzone
    var dz = $("#drop"), fi = $("#file");
    dz.addEventListener("click", function () { fi.click(); });
    dz.addEventListener("dragover", function (e) { e.preventDefault(); dz.classList.add("hot"); });
    dz.addEventListener("dragleave", function () { dz.classList.remove("hot"); });
    dz.addEventListener("drop", function (e) {
      e.preventDefault(); dz.classList.remove("hot");
      if (e.dataTransfer.files.length) { DATA_NAME = e.dataTransfer.files[0].name; e.dataTransfer.files[0].arrayBuffer().then(analyzeBuffer); }
    });
    fi.addEventListener("change", function () { if (fi.files.length) { DATA_NAME = fi.files[0].name; fi.files[0].arrayBuffer().then(analyzeBuffer); } });

    Array.prototype.forEach.call(document.querySelectorAll(".samp"), function (b) {
      b.addEventListener("click", function () { loadSample(b.getAttribute("data-file"), b.getAttribute("data-name")); });
    });
    $("#signout").addEventListener("click", signOut);
    $("#again").addEventListener("click", function () { DATA = null; $("#dash").innerHTML = ""; $("#exports").classList.add("hidden"); $("#intro").classList.remove("hidden"); $("#err").textContent = ""; });
    $("#dl-json").addEventListener("click", exportJson);
    $("#dl-ioc").addEventListener("click", exportIndicators);
    $("#dl-html").addEventListener("click", exportHtml);

    // Optional preview mode: render a supplied analysis without a file.
    if (window.NETHAWK_PREVIEW) {
      showApp();
      DATA_NAME = window.NETHAWK_PREVIEW.__name || "sample.pcap";
      $("#exports").classList.remove("hidden");
      $("#intro").classList.add("hidden");
      render(window.NETHAWK_PREVIEW);
    }
  });
})();
