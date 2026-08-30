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
  var findSev = "all", findQ = "", flowSort = "bytes", flowDir = "desc", flowQ = "";

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
  function loadSample() {
    $("#err").textContent = "";
    fetch("sample.pcap").then(function (r) {
      if (!r.ok) throw new Error("could not load the sample");
      return r.arrayBuffer();
    }).then(function (b) { DATA_NAME = "sample.pcap"; analyzeBuffer(b); })
      .catch(function (e) { $("#err").textContent = String(e.message || e); });
  }
  var DATA_NAME = "capture.pcap";

  // ---------- render ----------
  function card(n, l) { return '<div class="card"><div class="n">' + esc(n) + '</div><div class="l">' + esc(l) + "</div></div>"; }

  function render(data) {
    DATA = data;
    var sc = {}; (data.findings || []).forEach(function (f) { sc[f.severity] = (sc[f.severity] || 0) + 1; });
    var top = "none"; ["critical", "high", "medium", "low"].forEach(function (s) { if (top === "none" && sc[s]) top = s; });
    var started = data.first_ts ? new Date(data.first_ts * 1000).toISOString().replace("T", " ").substr(0, 19) + " UTC" : "unknown";

    var html = "";
    html += '<p class="tag-line">' + esc(DATA_NAME) + " &middot; started " + esc(started) + "</p>";
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
      keys.forEach(function (k) { var v = hs[k]; html += '<tr><td class="mono">' + esc(k) + "</td><td>" + v + '</td><td><div class="bar"><span style="width:' + Math.min(100, v) + "%;background:" + scoreColor(v) + '"></span></div></td></tr>'; });
      html += "</table>";
    }

    html += '<div class="nav">'
      + '<button data-tab="inc" class="active">Incidents</button>'
      + '<button data-tab="find">Findings</button>'
      + '<button data-tab="flow">Flows</button>'
      + '<button data-tab="traf">Traffic</button></div>';
    html += '<div id="p-inc" class="panel active"></div>';
    html += '<div id="p-find" class="panel"></div>';
    html += '<div id="p-flow" class="panel"></div>';
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
    renderIncidents(); renderFindings(); renderFlows(); renderTraffic();
  }

  function renderIncidents() {
    var el = $("#p-inc"); var inc = DATA.incidents || [];
    if (!inc.length) { el.innerHTML = '<p class="muted">No incidents reconstructed.</p>'; return; }
    var h = "";
    inc.forEach(function (i) {
      h += '<div class="inc"><div class="top"><div><span class="host mono">' + esc(i.host) + '</span> <span>&middot; ' + esc(i.hypothesis) + "</span></div>"
        + '<span class="pill" style="background:' + confColor(i.confidence) + '">confidence ' + i.confidence + "%</span></div>";
      if (i.indicators && i.indicators.length) h += '<div class="ind">indicators: ' + esc(i.indicators.join(", ")) + "</div>";
      if (i.timeline && i.timeline.length) { h += '<ul class="tl">'; i.timeline.forEach(function (e) { h += '<li><span class="t">' + clock(e.ts) + "</span>" + esc(e.text) + "</li>"; }); h += "</ul>"; }
      h += "</div>";
    });
    el.innerHTML = h;
  }

  function techniquesObserved() {
    var seen = {}, list = [];
    (DATA.findings || []).forEach(function (f) { (f.mitre || []).forEach(function (m) { if (!seen[m.id]) { seen[m.id] = 1; list.push(m); } }); });
    return list;
  }

  function renderFindings() {
    var el = $("#p-find");
    var techs = techniquesObserved();
    var th = "";
    if (techs.length) {
      th = '<div class="techs">';
      techs.forEach(function (m) { th += '<span class="t"><b>' + esc(m.id) + "</b> " + esc(m.name) + "</span>"; });
      th += "</div>";
    }
    var chips = ["all", "critical", "high", "medium", "low"];
    var c = '<div class="controls">';
    chips.forEach(function (s) { c += '<button class="chip' + (findSev === s ? " on" : "") + '" data-sev="' + s + '">' + s + "</button>"; });
    c += '<input type="text" id="fq" placeholder="search findings" value="' + esc(findQ) + '"></div>';
    var rows = (DATA.findings || []).filter(function (f) {
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

  function renderTraffic() {
    var el = $("#p-traf"); var st = DATA.stats || {};
    var h = "";
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
  function exportHtml() {
    if (!DATA) return;
    fetch("app/styles.css").then(function (r) { return r.text(); }).then(function (css) {
      var clone = $("#dash").cloneNode(true);
      var nav = clone.querySelector(".nav"); if (nav) nav.parentNode.removeChild(nav);
      var doc = "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        + "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        + "<title>NetHawk report</title><style>" + css + "\n.panel{display:block!important}\nbody{padding:0}</style>"
        + "</head><body><div class='wrap'><div class='topbar'><div class='brand'>"
        + "<span style='font-size:22px'>&#128052;</span><h1>NetHawk report</h1></div></div>"
        + clone.innerHTML + "</div></body></html>";
      download("nethawk-report.html", doc, "text/html");
    });
  }

  // ---------- wiring ----------
  window.addEventListener("load", function () {
    // login form
    var form = $("#login-form");
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      signIn($("#username").value.trim(), $("#password").value);
    });
    if (sessionStorage.getItem(SESSION_KEY) === "1") showApp();

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

    $("#sample").addEventListener("click", loadSample);
    $("#signout").addEventListener("click", signOut);
    $("#again").addEventListener("click", function () { DATA = null; $("#dash").innerHTML = ""; $("#exports").classList.add("hidden"); $("#intro").classList.remove("hidden"); $("#err").textContent = ""; });
    $("#dl-json").addEventListener("click", exportJson);
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
