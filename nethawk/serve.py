"""A local web GUI and JSON API for NetHawk, served by the standard library.

Run `nethawk serve` and open the printed address. Drop a capture into the page
and it is analyzed locally and rendered as an interactive dashboard: summary,
host risk, reconstructed incidents with timelines, a searchable findings list,
a flows explorer, and traffic statistics.

There is no framework and no external resource. The page is one document with
inline styles and vanilla JavaScript. The API endpoint POST /api/analyze takes
a raw capture body and returns the same structured result as the json report.
"""
from __future__ import annotations

import json
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from . import __version__
from .analyzer import analyze_bytes
from .detect import Config

MAX_UPLOAD = 300 * 1024 * 1024  # 300 MB safety cap

_CSS = """
:root{--bg:#0d0e14;--panel:#171922;--panel2:#1f2230;--line:#2a2e3d;--text:#e8eaf0;
--dim:#9096a0;--teal:#3dd6c4;--green:#5ad67d;--yellow:#f0be46;--red:#e9564b;--crit:#ff4a4a;--violet:#8b5cf6;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
a{color:var(--teal)}
.wrap{max-width:1120px;margin:0 auto;padding:26px 20px 72px}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:4px}
.brand h1{font-size:24px;margin:0}
.brand .v{color:var(--dim);font-size:13px;border:1px solid var(--line);border-radius:999px;padding:1px 8px}
.tag{color:var(--dim);margin:0 0 22px;font-size:14px}
.drop{border:2px dashed var(--line);border-radius:16px;padding:54px 24px;text-align:center;
background:var(--panel);transition:.15s;cursor:pointer}
.drop.hot{border-color:var(--teal);background:#141c22}
.drop .big{font-size:18px;font-weight:600}
.drop .small{color:var(--dim);font-size:14px;margin-top:6px}
.row{display:flex;gap:10px;justify-content:center;margin-top:16px;flex-wrap:wrap}
button.btn{background:var(--panel2);color:var(--text);border:1px solid var(--line);
border-radius:10px;padding:9px 16px;font-size:14px;cursor:pointer}
button.btn:hover{border-color:var(--teal)}
button.btn.primary{background:var(--teal);color:#0d0e14;border-color:var(--teal);font-weight:600}
.err{color:var(--crit);text-align:center;margin-top:14px;min-height:20px}
.spin{display:none;text-align:center;color:var(--dim);margin-top:20px}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:6px 0 22px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:15px 17px;min-width:140px;flex:1}
.card .n{font-size:23px;font-weight:700}.card .l{color:var(--dim);font-size:13px;margin-top:2px}
h2{font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:var(--dim);
margin:26px 0 12px;border-bottom:1px solid var(--line);padding-bottom:8px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:600}
th.sortable{cursor:pointer;user-select:none}
th.sortable:hover{color:var(--text)}
.bar{height:8px;border-radius:5px;background:var(--panel2);overflow:hidden;min-width:110px}
.bar span{display:block;height:100%}
.nav{display:flex;gap:6px;margin:8px 0 16px;flex-wrap:wrap}
.nav button{background:none;border:1px solid var(--line);color:var(--dim);border-radius:999px;
padding:6px 14px;font-size:13px;cursor:pointer}
.nav button.active{background:var(--panel2);color:var(--text);border-color:var(--teal)}
.panel{display:none}.panel.active{display:block}
.inc{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:17px 19px;margin-bottom:15px}
.inc .top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.inc .host{font-weight:700;font-size:16px}
.pill{padding:3px 10px;border-radius:999px;font-size:13px;font-weight:700;white-space:nowrap;color:#0d0e14}
.ind{color:var(--dim);font-size:13px;margin:8px 0 2px}
.tl{list-style:none;margin:12px 0 0;padding:0;border-left:2px solid var(--line)}
.tl li{position:relative;padding:4px 0 4px 18px;font-size:14px}
.tl li:before{content:"";position:absolute;left:-6px;top:11px;width:10px;height:10px;border-radius:50%;background:var(--teal)}
.tl .t{color:var(--teal);font-variant-numeric:tabular-nums;margin-right:10px}
.sev{font-weight:700;font-size:12px;text-transform:uppercase}
.controls{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center}
.controls input[type=text]{background:var(--panel);border:1px solid var(--line);color:var(--text);
border-radius:8px;padding:8px 12px;font-size:14px;min-width:220px}
.chip{background:none;border:1px solid var(--line);color:var(--dim);border-radius:999px;
padding:5px 12px;font-size:13px;cursor:pointer}
.chip.on{background:var(--panel2);color:var(--text);border-color:var(--teal)}
.muted{color:var(--dim)}
.mono{font-variant-numeric:tabular-nums}
.note{color:var(--dim);font-size:13px;margin-top:10px}
.foot{color:var(--dim);font-size:13px;margin-top:40px;border-top:1px solid var(--line);padding-top:16px}
"""

_JS = r"""
var DATA=null, findSev='all', findQ='', flowSort='bytes', flowDir='desc', flowQ='';
function $(s,r){return (r||document).querySelector(s);}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){
return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function fmtBytes(n){n=Number(n)||0;var u=['B','KB','MB','GB','TB'],i=0;
while(n>=1024&&i<u.length-1){n/=1024;i++;}return (i===0?n:n.toFixed(1))+' '+u[i];}
function fmtDur(s){s=Math.floor(Number(s)||0);var h=Math.floor(s/3600),m=Math.floor(s%3600/60),x=s%60;
return h?h+'h '+m+'m':(m?m+'m '+x+'s':x+'s');}
function clock(ts){if(!ts)return '--:--:--';return new Date(ts*1000).toISOString().substr(11,8);}
var SEV={critical:'var(--crit)',high:'var(--red)',medium:'var(--yellow)',low:'var(--teal)',info:'var(--dim)'};
function scoreColor(v){return v>=70?'var(--crit)':v>=40?'var(--yellow)':'var(--teal)';}
function confColor(v){return v>=70?'var(--crit)':v>=45?'var(--yellow)':'var(--teal)';}

function showUpload(){ $('#dash').innerHTML=''; $('#intro').style.display='block'; }
function analyzeBytes(buf){
  $('#err').textContent=''; $('#spin').style.display='block'; $('#intro').style.display='none';
  fetch('/api/analyze',{method:'POST',body:buf}).then(function(r){
    if(!r.ok) return r.text().then(function(t){throw new Error(t||('error '+r.status));});
    return r.json();
  }).then(function(d){ $('#spin').style.display='none'; render(d); })
  .catch(function(e){ $('#spin').style.display='none'; $('#intro').style.display='block';
    $('#err').textContent=String(e.message||e); });
}
function loadSample(){
  $('#err').textContent=''; $('#spin').style.display='block'; $('#intro').style.display='none';
  fetch('/api/sample').then(function(r){ if(!r.ok) throw new Error('sample not available'); return r.json(); })
  .then(function(d){ $('#spin').style.display='none'; render(d); })
  .catch(function(e){ $('#spin').style.display='none'; $('#intro').style.display='block';
    $('#err').textContent=String(e.message||e); });
}

function render(data){
  DATA=data;
  var sc={}; (data.findings||[]).forEach(function(f){sc[f.severity]=(sc[f.severity]||0)+1;});
  var top='none'; ['critical','high','medium','low'].forEach(function(s){if(top==='none'&&sc[s])top=s;});
  var started = data.first_ts ? new Date(data.first_ts*1000).toISOString().replace('T',' ').substr(0,19)+' UTC' : 'unknown';
  var html='';
  html+='<p class="tag">'+esc(data.path||'capture')+' &middot; started '+esc(started)+'</p>';
  html+='<div class="cards">';
  html+=card(data.packet_count,'packets');
  html+=card((data.flows||[]).length,'flows');
  html+=card(fmtDur(data.duration),'duration');
  html+=card((data.hosts_internal||[]).length+' / '+(data.hosts_external||[]).length,'hosts in / out');
  html+=card((data.incidents||[]).length,'incidents');
  html+='<div class="card"><div class="n" style="color:'+(SEV[top]||'var(--dim)')+'">'+esc(top)+'</div><div class="l">highest severity</div></div>';
  html+='</div>';

  // host risk
  var hs=data.host_scores||{}; var keys=Object.keys(hs).sort(function(a,b){return hs[b]-hs[a];});
  if(keys.length){
    html+='<h2>Host risk</h2><table><tr><th>host</th><th>score</th><th></th></tr>';
    keys.forEach(function(k){var v=hs[k];
      html+='<tr><td class="mono">'+esc(k)+'</td><td>'+v+'</td><td><div class="bar"><span style="width:'+Math.min(100,v)+'%;background:'+scoreColor(v)+'"></span></div></td></tr>';});
    html+='</table>';
  }

  // tabs
  html+='<div class="nav">'
    +'<button data-tab="inc" class="active">Incidents</button>'
    +'<button data-tab="find">Findings</button>'
    +'<button data-tab="flow">Flows</button>'
    +'<button data-tab="traf">Traffic</button></div>';
  html+='<div id="p-inc" class="panel active"></div>';
  html+='<div id="p-find" class="panel"></div>';
  html+='<div id="p-flow" class="panel"></div>';
  html+='<div id="p-traf" class="panel"></div>';
  html+='<p class="foot">Generated by NetHawk '+esc(data.version||'')+'. Analyze only captures you are authorized to inspect.</p>';

  $('#dash').innerHTML=html;
  Array.prototype.forEach.call(document.querySelectorAll('.nav button'),function(b){
    b.onclick=function(){
      Array.prototype.forEach.call(document.querySelectorAll('.nav button'),function(x){x.classList.remove('active');});
      Array.prototype.forEach.call(document.querySelectorAll('.panel'),function(x){x.classList.remove('active');});
      b.classList.add('active'); $('#p-'+b.getAttribute('data-tab')).classList.add('active');
    };
  });
  renderIncidents(); renderFindings(); renderFlows(); renderTraffic();
}
function card(n,l){return '<div class="card"><div class="n">'+esc(n)+'</div><div class="l">'+esc(l)+'</div></div>';}

function renderIncidents(){
  var el=$('#p-inc'); var inc=DATA.incidents||[];
  if(!inc.length){el.innerHTML='<p class="muted">No incidents reconstructed.</p>';return;}
  var h='';
  inc.forEach(function(i){
    h+='<div class="inc"><div class="top"><div><span class="host mono">'+esc(i.host)+'</span> <span>&mdash; '+esc(i.hypothesis)+'</span></div>'
      +'<span class="pill" style="background:'+confColor(i.confidence)+'">confidence '+i.confidence+'%</span></div>';
    if(i.indicators&&i.indicators.length) h+='<div class="ind">indicators: '+esc(i.indicators.join(', '))+'</div>';
    if(i.timeline&&i.timeline.length){h+='<ul class="tl">';
      i.timeline.forEach(function(e){h+='<li><span class="t">'+clock(e.ts)+'</span>'+esc(e.text)+'</li>';});
      h+='</ul>';}
    h+='</div>';
  });
  el.innerHTML=h;
}

function renderFindings(){
  var el=$('#p-find');
  var chips=['all','critical','high','medium','low'];
  var c='<div class="controls">';
  chips.forEach(function(s){c+='<button class="chip'+(findSev===s?' on':'')+'" data-sev="'+s+'">'+s+'</button>';});
  c+='<input type="text" id="fq" placeholder="search findings" value="'+esc(findQ)+'"></div>';
  var rows=(DATA.findings||[]).filter(function(f){
    if(findSev!=='all'&&f.severity!==findSev) return false;
    if(findQ){var s=(f.category+' '+f.src+' '+f.dst+' '+f.title+' '+f.detail).toLowerCase();
      if(s.indexOf(findQ.toLowerCase())<0) return false;}
    return true;});
  var t='<table><tr><th>severity</th><th>type</th><th>source</th><th>target</th><th>detail</th></tr>';
  if(!rows.length){t+='<tr><td colspan="5" class="muted">No matching findings.</td></tr>';}
  rows.forEach(function(f){
    t+='<tr><td><span class="sev" style="color:'+(SEV[f.severity]||'var(--dim)')+'">'+esc(f.severity)+'</span></td>'
     +'<td>'+esc(f.category)+'</td><td class="mono">'+esc(f.src)+'</td><td class="mono">'+esc(f.dst||'')+'</td>'
     +'<td class="muted">'+esc(f.detail)+'</td></tr>';});
  t+='</table>';
  el.innerHTML=c+t;
  Array.prototype.forEach.call(el.querySelectorAll('.chip'),function(b){
    b.onclick=function(){findSev=b.getAttribute('data-sev');renderFindings();};});
  var q=$('#fq',el); q.oninput=function(){findQ=q.value;var pos=q.selectionStart;renderFindings();
    var nq=$('#fq');if(nq){nq.focus();try{nq.selectionStart=nq.selectionEnd=pos;}catch(e){}}};
}

function renderFlows(){
  var el=$('#p-flow');
  var c='<div class="controls"><input type="text" id="flq" placeholder="filter by host, port, or name" value="'+esc(flowQ)+'"></div>';
  var flows=(DATA.flows||[]).slice();
  if(flowQ){var q=flowQ.toLowerCase();flows=flows.filter(function(f){
    var s=(f.src+' '+f.dst+' '+f.dst_port+' '+(f.sni||'')+' '+(f.http_host||'')+' '+f.proto).toLowerCase();
    return s.indexOf(q)>=0;});}
  flows.sort(function(a,b){var x,y;
    if(flowSort==='bytes'){x=a.bytes_out+a.bytes_in;y=b.bytes_out+b.bytes_in;}
    else if(flowSort==='out'){x=a.bytes_out;y=b.bytes_out;}
    else if(flowSort==='duration'){x=a.duration;y=b.duration;}
    else if(flowSort==='port'){x=a.dst_port;y=b.dst_port;}
    else{x=a.first_ts;y=b.first_ts;}
    return flowDir==='desc'?y-x:x-y;});
  var total=flows.length, cap=500; var shown=flows.slice(0,cap);
  function th(k,label){var ar=flowSort===k?(flowDir==='desc'?' \u25be':' \u25b4'):'';return '<th class="sortable" data-k="'+k+'">'+label+ar+'</th>';}
  var t='<table><tr>'+th('start','start')+'<th>proto</th><th>source</th><th>destination</th>'+th('port','port')
    +th('out','out')+'<th>in</th>'+th('duration','duration')+'<th>name</th></tr>';
  if(!shown.length){t+='<tr><td colspan="9" class="muted">No matching flows.</td></tr>';}
  shown.forEach(function(f){
    var name=f.sni||f.http_host||'';
    t+='<tr><td class="mono">'+clock(f.first_ts)+'</td><td>'+esc(f.proto)+'</td>'
     +'<td class="mono">'+esc(f.src)+':'+f.src_port+'</td><td class="mono">'+esc(f.dst)+'</td>'
     +'<td class="mono">'+f.dst_port+'</td><td class="mono">'+fmtBytes(f.bytes_out)+'</td>'
     +'<td class="mono">'+fmtBytes(f.bytes_in)+'</td><td class="mono">'+fmtDur(f.duration)+'</td>'
     +'<td class="muted">'+esc(name)+'</td></tr>';});
  t+='</table>';
  if(total>cap) t+='<p class="note">Showing the first '+cap+' of '+total+' flows. Use the filter to narrow down.</p>';
  el.innerHTML=c+t;
  Array.prototype.forEach.call(el.querySelectorAll('th.sortable'),function(th){
    th.onclick=function(){var k=th.getAttribute('data-k');
      if(flowSort===k){flowDir=flowDir==='desc'?'asc':'desc';}else{flowSort=k;flowDir='desc';}renderFlows();};});
  var q=$('#flq',el); q.oninput=function(){flowQ=q.value;var pos=q.selectionStart;renderFlows();
    var nq=$('#flq');if(nq){nq.focus();try{nq.selectionStart=nq.selectionEnd=pos;}catch(e){}}};
}

function renderTraffic(){
  var el=$('#p-traf'); var st=DATA.stats||{};
  var h='';
  var protos=st.protocols||{}; var pk=Object.keys(protos); var pmax=Math.max.apply(null,pk.map(function(k){return protos[k];}).concat([1]));
  h+='<h2>Protocols</h2><table>';
  pk.forEach(function(k){h+='<tr><td class="mono">'+esc(k)+'</td><td class="mono">'+protos[k]+' flows</td>'
    +'<td><div class="bar"><span style="width:'+(100*protos[k]/pmax)+'%;background:var(--violet)"></span></div></td></tr>';});
  h+='</table>';
  var tt=st.top_talkers||[]; var tmax=Math.max.apply(null,tt.map(function(x){return x.bytes;}).concat([1]));
  h+='<h2>Top talkers</h2><table>';
  tt.forEach(function(x){h+='<tr><td class="mono">'+esc(x.host)+'</td><td class="mono">'+fmtBytes(x.bytes)+'</td>'
    +'<td><div class="bar"><span style="width:'+(100*x.bytes/tmax)+'%;background:var(--teal)"></span></div></td></tr>';});
  h+='</table>';
  var tp=st.top_ports||[];
  h+='<h2>Top destination ports</h2><table><tr><th>port</th><th>flows</th></tr>';
  tp.forEach(function(x){h+='<tr><td class="mono">'+x.port+'</td><td class="mono">'+x.flows+'</td></tr>';});
  h+='</table>';
  el.innerHTML=h;
}

// WIRE
window.addEventListener('load',function(){
  var dz=$('#drop'), fi=$('#file');
  if(dz){
    dz.addEventListener('click',function(){fi.click();});
    dz.addEventListener('dragover',function(e){e.preventDefault();dz.classList.add('hot');});
    dz.addEventListener('dragleave',function(){dz.classList.remove('hot');});
    dz.addEventListener('drop',function(e){e.preventDefault();dz.classList.remove('hot');
      if(e.dataTransfer.files.length) e.dataTransfer.files[0].arrayBuffer().then(analyzeBytes);});
    fi.addEventListener('change',function(){if(fi.files.length) fi.files[0].arrayBuffer().then(analyzeBytes);});
  }
  var sb=$('#sample'); if(sb) sb.addEventListener('click',loadSample);
  // hide sample button if the server has no bundled sample
  fetch('/api/health').then(function(r){return r.json();}).then(function(d){
    if(sb&&!d.sample) sb.style.display='none';}).catch(function(){});
  if(window.__EMBEDDED__){ $('#intro').style.display='none'; render(window.__EMBEDDED__); }
});
"""

_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetHawk</title><style>/*CSS*/</style></head><body><div class="wrap">
<div class="brand"><h1>&#128052; NetHawk</h1><span class="v">/*VER*/</span></div>
<p class="tag">Reconstruct attacks from a packet capture. Drop a capture below to analyze it in your browser.</p>
<div id="intro">
  <div class="drop" id="drop">
    <div class="big">Drop a .pcap or .pcapng here</div>
    <div class="small">or click to choose a file. Everything is analyzed locally.</div>
  </div>
  <div class="row">
    <button class="btn" id="sample">Load the sample capture</button>
  </div>
  <div class="err" id="err"></div>
  <input type="file" id="file" accept=".pcap,.pcapng,.cap" style="display:none">
</div>
<div class="spin" id="spin">analyzing...</div>
<div id="dash"></div>
</div>
<script>window.__EMBEDDED__=/*EMBEDDED*/;</script>
<script>/*JS*/</script>
</body></html>"""


def render_page(embedded_json: str = "null") -> str:
    return (_PAGE
            .replace("/*CSS*/", _CSS)
            .replace("/*VER*/", __version__)
            .replace("/*EMBEDDED*/", embedded_json)
            .replace("/*JS*/", _JS))


# Core render logic without the browser wiring, for producing static previews.
_JS_CORE = _JS.split("// WIRE", 1)[0]


def render_preview(embedded_json: str) -> str:
    """A self contained, populated page with no network calls, for screenshots."""
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<style>{_CSS}</style></head><body><div class='wrap'>"
            "<div class='brand'><h1>&#128052; NetHawk</h1>"
            f"<span class='v'>{__version__}</span></div>"
            "<div id='intro' style='display:none'></div><div id='dash'></div></div>"
            f"<script>{_JS_CORE}\nwindow.__EMBEDDED__={embedded_json};render(window.__EMBEDDED__);</script>"
            "</body></html>")


def _make_handler(cfg: Config, sample_bytes: Optional[bytes]):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"NetHawk/{__version__}"

        def log_message(self, fmt, *args):
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            try:
                self.wfile.write(data)
            except BrokenPipeError:
                pass

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/":
                self._send(200, render_page(), "text/html; charset=utf-8")
            elif path == "/api/health":
                self._send(200, json.dumps({"status": "ok", "version": __version__,
                                            "sample": sample_bytes is not None}))
            elif path == "/api/sample":
                if sample_bytes is None:
                    self._send(404, json.dumps({"error": "no sample bundled"}))
                    return
                a = analyze_bytes(sample_bytes, cfg, name="sample.pcap")
                payload = {"tool": "nethawk", "version": __version__}
                payload.update(a.to_dict())
                self._send(200, json.dumps(payload))
            elif path == "/favicon.ico":
                self._send(204, b"", "image/x-icon")
            else:
                self._send(404, json.dumps({"error": "not found"}))

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            if path != "/api/analyze":
                self._send(404, json.dumps({"error": "not found"}))
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0:
                self._send(400, json.dumps({"error": "empty upload"}))
                return
            if length > MAX_UPLOAD:
                self._send(413, json.dumps({"error": "capture is too large"}))
                return
            data = self.rfile.read(length)
            try:
                a = analyze_bytes(data, cfg, name="upload.pcap")
            except Exception as exc:  # keep the server alive on a bad file
                self._send(400, json.dumps({"error": f"could not analyze capture: {exc}"}))
                return
            payload = {"tool": "nethawk", "version": __version__}
            payload.update(a.to_dict())
            self._send(200, json.dumps(payload))

    return Handler


def run_server(host: str, port: int, cfg: Config, sample_bytes: Optional[bytes] = None,
               open_browser: bool = False) -> int:
    handler = _make_handler(cfg, sample_bytes)
    httpd = ThreadingHTTPServer((host, port), handler)
    shown = host if host not in ("0.0.0.0", "::") else "127.0.0.1"
    url = f"http://{shown}:{port}/"
    print(f"NetHawk GUI is running at {url}")
    print("Open it in your browser and drop a capture in. Press Ctrl C to stop.")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping.")
    finally:
        httpd.server_close()
    return 0
