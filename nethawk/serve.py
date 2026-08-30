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
.sevbar{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 18px}
.sevchip{border:1px solid var(--line);border-radius:999px;padding:5px 12px;font-size:13px;font-weight:600}
.techs{display:flex;flex-wrap:wrap;gap:6px;margin:2px 0 14px}
.techs .t{background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:3px 9px;font-size:12px}
.techs .t b{color:var(--violet)}
.chart{width:100%;margin-bottom:4px}
.tsvg{width:100%;height:120px;display:block;background:var(--panel);border:1px solid var(--line);border-radius:10px}
.netsvg{width:100%;height:auto;background:var(--panel);border:1px solid var(--line);border-radius:12px}
.axis{display:flex;justify-content:space-between;color:var(--dim);font-size:12px;margin:2px 2px 16px}
.legend{display:flex;gap:16px;flex-wrap:wrap;color:var(--dim);font-size:13px;margin-bottom:10px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:50%;vertical-align:middle;margin-right:4px}
.swim{width:100%;height:auto;background:var(--panel);border:1px solid var(--line);border-radius:12px;margin-bottom:16px}
.matrix{display:flex;gap:12px;flex-wrap:wrap;margin:2px 0 16px}
.matrix .col{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 12px;min-width:170px;flex:1}
.matrix .col-h{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--dim);margin-bottom:8px;border-bottom:1px solid var(--line);padding-bottom:6px}
.matrix .col .t{display:block;font-size:13px;margin:5px 0}
.matrix .col .t b{color:var(--violet)}
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
var TACTIC_ORDER=['Discovery','Credential Access','Command and Control','Exfiltration'];
var TECH_TACTIC={'T1046':'Discovery','T1040':'Credential Access','T1552':'Credential Access','T1071':'Command and Control','T1071.001':'Command and Control','T1071.004':'Command and Control','T1568.002':'Command and Control','T1572':'Command and Control','T1048':'Exfiltration'};
var LANE_COLORS=['var(--crit)','var(--violet)','var(--teal)','var(--yellow)','var(--green)'];

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

  // severity summary
  var order=['critical','high','medium','low','info'];
  html+='<div class="sevbar">';
  order.forEach(function(s){if(sc[s])html+='<span class="sevchip" style="color:'+SEV[s]+';border-color:'+SEV[s]+'">'+sc[s]+' '+s+'</span>';});
  if(!(data.findings||[]).length)html+='<span class="sevchip" style="color:var(--green);border-color:var(--green)">no findings</span>';
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
    +'<button data-tab="net">Network</button>'
    +'<button data-tab="traf">Traffic</button></div>';
  html+='<div id="p-inc" class="panel active"></div>';
  html+='<div id="p-find" class="panel"></div>';
  html+='<div id="p-flow" class="panel"></div>';
  html+='<div id="p-net" class="panel"></div>';
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
  renderIncidents(); renderFindings(); renderFlows(); renderNetwork(); renderTraffic();
}
function card(n,l){return '<div class="card"><div class="n">'+esc(n)+'</div><div class="l">'+esc(l)+'</div></div>';}

function attackTimeline(incidents){
  var events=[];
  incidents.forEach(function(i){(i.timeline||[]).forEach(function(e){if(e.ts)events.push(e);});});
  if(events.length<2)return '';
  var first=Math.min.apply(null,events.map(function(e){return e.ts;}));
  var last=Math.max.apply(null,events.map(function(e){return e.ts;}));
  var firstByHost={};
  events.forEach(function(e){if(firstByHost[e.host]==null||e.ts<firstByHost[e.host])firstByHost[e.host]=e.ts;});
  var hosts=Object.keys(firstByHost).sort(function(a,b){return firstByHost[a]-firstByHost[b];});
  var colorByHost={};hosts.forEach(function(h,i){colorByHost[h]=LANE_COLORS[i%LANE_COLORS.length];});
  var W=700,padL=96,padR=20,top=22,laneH=44,H=top+hosts.length*laneH+34,span=last-first;
  function x(ts){return span>0?padL+(ts-first)/span*(W-padL-padR):padL;}
  var svg='';
  hosts.forEach(function(h,i){
    var y=top+i*laneH+laneH/2;
    svg+='<line x1="'+padL+'" y1="'+y+'" x2="'+(W-padR)+'" y2="'+y+'" stroke="var(--line)" stroke-width="1"/>';
    svg+='<text x="4" y="'+(y+4)+'" font-size="11" fill="'+colorByHost[h]+'">'+esc(shortHost(h))+'</text>';
    var evs=events.filter(function(e){return e.host===h;}).sort(function(a,b){return a.ts-b.ts;});
    for(var j=1;j<evs.length;j++)svg+='<line x1="'+x(evs[j-1].ts).toFixed(1)+'" y1="'+y+'" x2="'+x(evs[j].ts).toFixed(1)+'" y2="'+y+'" stroke="'+colorByHost[h]+'" stroke-opacity="0.35" stroke-width="2"/>';
    evs.forEach(function(e){svg+='<circle cx="'+x(e.ts).toFixed(1)+'" cy="'+y+'" r="5" fill="'+colorByHost[h]+'"><title>'+clock(e.ts)+'  '+esc(e.text)+'</title></circle>';});
  });
  var ay=H-14;
  [0,0.5,1].forEach(function(f){var ts=first+span*f,xx=x(ts),anchor=f===0?'start':f===1?'end':'middle';
    svg+='<text x="'+xx.toFixed(1)+'" y="'+ay+'" font-size="10" fill="var(--dim)" text-anchor="'+anchor+'">'+clock(ts)+'</text>';});
  return '<h2>Attack timeline</h2><div class="chart"><svg viewBox="0 0 '+W+' '+H+'" class="swim" preserveAspectRatio="xMidYMid meet">'+svg+'</svg></div>';
}
function renderIncidents(){
  var el=$('#p-inc'); var inc=DATA.incidents||[];
  if(!inc.length){el.innerHTML='<p class="muted">No incidents reconstructed.</p>';return;}
  var h=attackTimeline(inc);
  inc.forEach(function(i){
    h+='<div class="inc"><div class="top"><div><span class="host mono">'+esc(i.host)+'</span> <span>&middot; '+esc(i.hypothesis)+'</span></div>'
      +'<span class="pill" style="background:'+confColor(i.confidence)+'">confidence '+i.confidence+'%</span></div>';
    if(i.indicators&&i.indicators.length) h+='<div class="ind">indicators: '+esc(i.indicators.join(', '))+'</div>';
    if(i.timeline&&i.timeline.length){h+='<ul class="tl">';
      i.timeline.forEach(function(e){h+='<li><span class="t">'+clock(e.ts)+'</span>'+esc(e.text)+'</li>';});
      h+='</ul>';}
    h+='</div>';
  });
  el.innerHTML=h;
}

function techniquesObserved(){
  var seen={},list=[];
  (DATA.findings||[]).forEach(function(f){(f.mitre||[]).forEach(function(m){if(!seen[m.id]){seen[m.id]=1;list.push(m);}});});
  return list;
}
function attckMatrix(){
  var techs=techniquesObserved();if(!techs.length)return '';
  var byTactic={};
  techs.forEach(function(m){var t=TECH_TACTIC[m.id]||'Other';(byTactic[t]=byTactic[t]||[]).push(m);});
  var order=TACTIC_ORDER.filter(function(t){return byTactic[t];});
  Object.keys(byTactic).forEach(function(t){if(order.indexOf(t)<0)order.push(t);});
  var h='<div class="matrix">';
  order.forEach(function(t){h+='<div class="col"><div class="col-h">'+esc(t)+'</div>';
    byTactic[t].forEach(function(m){h+='<span class="t"><b>'+esc(m.id)+'</b> '+esc(m.name)+'</span>';});h+='</div>';});
  return h+'</div>';
}
function renderFindings(){
  var el=$('#p-find');
  var th=attckMatrix();
  var chips=['all','critical','high','medium','low'];
  var c='<div class="controls">';
  chips.forEach(function(s){c+='<button class="chip'+(findSev===s?' on':'')+'" data-sev="'+s+'">'+s+'</button>';});
  c+='<input type="text" id="fq" placeholder="search findings" value="'+esc(findQ)+'"></div>';
  var rows=(DATA.findings||[]).filter(function(f){
    if(findSev!=='all'&&f.severity!==findSev) return false;
    if(findQ){var s=(f.category+' '+f.src+' '+f.dst+' '+f.title+' '+f.detail).toLowerCase();
      if(s.indexOf(findQ.toLowerCase())<0) return false;}
    return true;});
  var t='<table><tr><th>severity</th><th>type</th><th>source</th><th>target</th><th>att&amp;ck</th><th>detail</th></tr>';
  if(!rows.length){t+='<tr><td colspan="6" class="muted">No matching findings.</td></tr>';}
  rows.forEach(function(f){
    var att=(f.mitre||[]).map(function(m){return m.id;}).join(' ');
    t+='<tr><td><span class="sev" style="color:'+(SEV[f.severity]||'var(--dim)')+'">'+esc(f.severity)+'</span></td>'
     +'<td>'+esc(f.category)+'</td><td class="mono">'+esc(f.src)+'</td><td class="mono">'+esc(f.dst||'')+'</td>'
     +'<td class="muted mono">'+esc(att)+'</td>'
     +'<td class="muted">'+esc(f.detail)+'</td></tr>';});
  t+='</table>';
  el.innerHTML=th+c+t;
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

function shortHost(h){if(h.indexOf(':')>=0)return h.split(':').slice(-2).join(':');var p=h.split('.');return p.length===4?p.slice(-2).join('.'):h;}
function renderNetwork(){
  var el=$('#p-net'); var flows=DATA.flows||[];
  if(!flows.length){el.innerHTML='<p class="muted">No conversations to graph.</p>';return;}
  var bytesBy={},edges={};
  flows.forEach(function(f){var w=f.bytes_out+f.bytes_in;bytesBy[f.src]=(bytesBy[f.src]||0)+w;bytesBy[f.dst]=(bytesBy[f.dst]||0)+w;
    var k=f.src<f.dst?f.src+'|'+f.dst:f.dst+'|'+f.src;edges[k]=(edges[k]||0)+w;});
  var hosts=Object.keys(bytesBy).sort(function(a,b){return bytesBy[b]-bytesBy[a];});
  var cap=40,shown=hosts.slice(0,cap),cx=350,cy=250,R=200,N=shown.length,posByHost={};
  shown.forEach(function(h,i){var a=-Math.PI/2+2*Math.PI*i/Math.max(1,N);posByHost[h]={h:h,a:a,x:cx+R*Math.cos(a),y:cy+R*Math.sin(a)};});
  var internalSet={};(DATA.hosts_internal||[]).forEach(function(h){internalSet[h]=1;});
  var scores=DATA.host_scores||{};
  var emax=Math.max.apply(null,Object.keys(edges).map(function(k){return edges[k];}).concat([1]));
  var lines='';
  Object.keys(edges).forEach(function(k){var pr=k.split('|');if(!posByHost[pr[0]]||!posByHost[pr[1]])return;
    var p1=posByHost[pr[0]],p2=posByHost[pr[1]],op=(0.06+0.5*edges[k]/emax).toFixed(2);
    lines+='<line x1="'+p1.x.toFixed(1)+'" y1="'+p1.y.toFixed(1)+'" x2="'+p2.x.toFixed(1)+'" y2="'+p2.y.toFixed(1)+'" stroke="var(--teal)" stroke-opacity="'+op+'" stroke-width="1"/>';});
  var bmax=Math.max.apply(null,shown.map(function(h){return bytesBy[h];}).concat([1])),nodes='',labels='';
  shown.forEach(function(h){var p=posByHost[h],sc=scores[h]||0;
    var color=sc>=70?'var(--crit)':sc>=40?'var(--yellow)':internalSet[h]?'var(--teal)':'var(--dim)';
    var r=(4+9*Math.sqrt(bytesBy[h]/bmax)).toFixed(1);
    nodes+='<circle cx="'+p.x.toFixed(1)+'" cy="'+p.y.toFixed(1)+'" r="'+r+'" fill="'+color+'" fill-opacity="0.92" stroke="#0d0e14" stroke-width="1"><title>'+esc(h)+(sc?' \u00b7 risk '+sc:'')+' \u00b7 '+fmtBytes(bytesBy[h])+'</title></circle>';
    if(sc>=40||bytesBy[h]>=0.14*bmax){var lx=cx+(R+12)*Math.cos(p.a),ly=cy+(R+12)*Math.sin(p.a);
      var anchor=Math.cos(p.a)<-0.3?'end':(Math.cos(p.a)>0.3?'start':'middle');
      labels+='<text x="'+lx.toFixed(1)+'" y="'+(ly+3).toFixed(1)+'" text-anchor="'+anchor+'" font-size="10" fill="var(--dim)">'+esc(shortHost(h))+'</text>';}});
  var legend='<div class="legend"><span><i style="background:var(--crit)"></i> high risk</span>'
    +'<span><i style="background:var(--yellow)"></i> elevated</span>'
    +'<span><i style="background:var(--teal)"></i> internal</span>'
    +'<span><i style="background:var(--dim)"></i> external</span></div>';
  var note=hosts.length>cap?'<p class="note">Showing the '+cap+' busiest hosts of '+hosts.length+'. Node size is total traffic; edges are conversations.</p>':'<p class="note">Node size is total traffic; edges are conversations.</p>';
  el.innerHTML='<h2>Host graph</h2>'+legend+'<div class="chart"><svg viewBox="0 0 700 500" class="netsvg" preserveAspectRatio="xMidYMid meet">'+lines+nodes+labels+'</svg></div>'+note;
}
function activityChart(act){
  if(!act||!act.buckets||act.buckets.length<2)return '';
  var b=act.buckets,n=b.length,max=Math.max.apply(null,b.map(function(x){return x.bytes;}).concat([1])),W=n*10,H=120,bars='';
  b.forEach(function(x,i){var bh=Math.max(0,Math.round((H-6)*x.bytes/max));
    bars+='<rect x="'+(i*10+1)+'" y="'+(H-bh)+'" width="8" height="'+bh+'" fill="var(--teal)" fill-opacity="0.85"><title>'+clock(x.t)+'  '+fmtBytes(x.bytes)+'  '+x.packets+' pkts</title></rect>';});
  var endT=b[n-1].t+(act.bucket_seconds||0);
  return '<h2>Activity over time</h2><div class="chart"><svg viewBox="0 0 '+W+' '+H+'" preserveAspectRatio="none" class="tsvg">'+bars+'</svg></div>'
    +'<div class="axis"><span>'+clock(b[0].t)+'</span><span>peak '+fmtBytes(max)+'</span><span>'+clock(endT)+'</span></div>';
}
function renderTraffic(){
  var el=$('#p-traf'); var st=DATA.stats||{};
  var h=activityChart(st.activity);
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
<div class="brand"><h1>&#129413; NetHawk</h1><span class="v">/*VER*/</span></div>
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
            "<div class='brand'><h1>&#129413; NetHawk</h1>"
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
