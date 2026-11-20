/* Dashboard chart engine (build 509) — dashSVG(type, cols, rows, spec) → SVG/HTML string.
   Shared by the Dashboards app (web/dashboards.html). Ported unchanged from the Custom Dashboard;
   every label is escaped with _dsEsc. */
var DS_PAL=['var(--cx-5a5fe0)','var(--cx-3f78c2)','var(--cx-2f9d9d)','var(--cx-2fa06e)','var(--cx-7d64d4)','var(--cx-3f8fb0)','var(--cx-4a6fd0)','var(--cx-2f9e88)','var(--cx-6f73e0)','var(--cx-2f88a8)','var(--cx-5a7fc0)','var(--cx-8a67d6)'];
var DS_AXIS='#64748b', DS_LABEL='#94a3b8', DS_GRID='rgba(148,163,184,.22)';
function _dsEsc(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function _dsNum(v){ var n=parseFloat(v); return isFinite(n)?n:NaN; }
function _dsIsNumCol(rows,c){ var k=0,t=0; rows.forEach(function(r){ if(r[c]!=null&&r[c]!==''){ t++; if(isFinite(_dsNum(r[c]))) k++; } }); return t>0 && k/t>=0.7; }
function _dsFmt(n){ if(!isFinite(n)) return String(n); var a=Math.abs(n); if(a>=1e9)return (n/1e9).toFixed(1)+'B'; if(a>=1e6)return (n/1e6).toFixed(1)+'M'; if(a>=1e3)return (n/1e3).toFixed(1)+'k'; return (Math.round(n*100)/100).toString(); }

/* shape detection -> {lc, series:[{name, values:[...]}], labels:[...]} */
function dashData(cols, rows, spec){
  cols=cols&&cols.length?cols:(rows.length?Object.keys(rows[0]):[]);
  var numCols=cols.filter(function(c){ return _dsIsNumCol(rows,c); });
  var lc=(spec&&spec.label_col&&cols.indexOf(spec.label_col)>=0)?spec.label_col
        :(cols.filter(function(c){return numCols.indexOf(c)<0;})[0]||cols[0]);
  var valCols=numCols.filter(function(c){ return c!==lc; });
  var textCols=cols.filter(function(c){ return c!==lc && numCols.indexOf(c)<0; });
  // long format: label + one text (series) + one value  ->  pivot to wide
  if(valCols.length===1 && textCols.length>=1){
    var sc=textCols[0], vc=valCols[0], labels=[], sers={}, order=[];
    rows.forEach(function(r){ var L=String(r[lc]==null?'':r[lc]); if(labels.indexOf(L)<0)labels.push(L);
      var S=String(r[sc]==null?'':r[sc]); if(!sers[S]){sers[S]={};order.push(S);} sers[S][L]=_dsNum(r[vc])||0; });
    return {lc:lc, labels:labels, series:order.map(function(S){ return {name:S, values:labels.map(function(L){return sers[S][L]||0;})}; }), pivoted:true};
  }
  var labs=rows.map(function(r){ return String(r[lc]==null?'':r[lc]); });
  if(!valCols.length) return {lc:lc, labels:labs, series:[], none:true};
  return {lc:lc, labels:labs, series:valCols.map(function(c){ return {name:c, values:rows.map(function(r){return _dsNum(r[c])||0;})}; })};
}

function _dsWrap(inner, w, h){ return '<svg viewBox="0 0 '+w+' '+h+'" width="100%" style="max-width:'+w+'px;height:auto;font-family:system-ui,Segoe UI,Arial,sans-serif" xmlns="http://www.w3.org/2000/svg">'+inner+'</svg>'; }
function _dsLegend(names){ if(names.length<2)return ''; return '<div style="display:flex;flex-wrap:wrap;gap:12px;margin-top:8px;font-size:12px;color:'+DS_LABEL+'">'+names.map(function(n,i){return '<span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:'+DS_PAL[i%DS_PAL.length]+';vertical-align:middle;margin-right:5px"></span>'+_dsEsc(n)+'</span>';}).join('')+'</div>'; }

/* ---- individual renderers (each returns an <svg> …) ---- */
function _dsColumn(d,stacked,grouped){
  var W=680,H=300,pad=40,bottom=48,left=48,plotW=W-left-pad,plotH=H-bottom-20,n=d.labels.length;
  var totals=d.labels.map(function(_,i){ return stacked? d.series.reduce(function(s,se){return s+(se.values[i]||0);},0) : Math.max.apply(null,d.series.map(function(se){return se.values[i]||0;})); });
  var max=Math.max.apply(null,totals.concat([1]));
  var g='', gw=plotW/n, ns=d.series.length;
  var ticks=4, tick='';
  for(var t=0;t<=ticks;t++){ var yv=max*t/ticks, y=20+plotH-plotH*t/ticks; tick+='<line x1="'+left+'" y1="'+y+'" x2="'+(left+plotW)+'" y2="'+y+'" stroke="'+DS_GRID+'"/><text x="'+(left-6)+'" y="'+(y+3)+'" text-anchor="end" font-size="10" fill="'+DS_AXIS+'">'+_dsFmt(yv)+'</text>'; }
  d.labels.forEach(function(L,i){ var x0=left+i*gw;
    if(stacked){ var acc=0; d.series.forEach(function(se,si){ var v=se.values[i]||0, bh=plotH*v/max, y=20+plotH-acc-bh; acc+=bh; if(v>0)g+='<rect x="'+(x0+gw*0.18)+'" y="'+y+'" width="'+(gw*0.64)+'" height="'+Math.max(0,bh)+'" fill="'+DS_PAL[si%DS_PAL.length]+'"><title>'+_dsEsc(se.name)+' · '+_dsEsc(L)+': '+v+'</title></rect>'; }); }
    else { var bw=(gw*0.64)/ns; d.series.forEach(function(se,si){ var v=se.values[i]||0, bh=plotH*v/max, y=20+plotH-bh, x=x0+gw*0.18+si*bw; g+='<rect x="'+x+'" y="'+y+'" width="'+Math.max(0,bw-1)+'" height="'+Math.max(0,bh)+'" fill="'+DS_PAL[si%DS_PAL.length]+'"><title>'+_dsEsc(se.name)+' · '+_dsEsc(L)+': '+v+'</title></rect>'; }); }
    var lab=L.length>10?L.slice(0,9)+'…':L; g+='<text x="'+(x0+gw/2)+'" y="'+(H-bottom+16)+'" text-anchor="middle" font-size="10.5" fill="'+DS_LABEL+'">'+_dsEsc(lab)+'</text>'; });
  return _dsWrap(tick+g,W,H)+_dsLegend(d.series.map(function(s){return s.name;}));
}
function _dsBar(d){ // horizontal, single or grouped
  var rowsN=d.labels.length, ns=d.series.length, rh=Math.max(20,Math.min(34,240/Math.max(1,rowsN))), gap=8;
  var W=680,left=170,right=54,plotW=W-left-right,H=rowsN*(rh+gap)+20;
  var max=Math.max.apply(null,[].concat.apply([1],d.series.map(function(s){return s.values;})));
  var g='';
  d.labels.forEach(function(L,i){ var y=10+i*(rh+gap); var sh=rh/ns;
    d.series.forEach(function(se,si){ var v=se.values[i]||0, bw=plotW*v/max; var yy=y+si*sh;
      g+='<rect x="'+left+'" y="'+yy+'" width="'+Math.max(0,bw)+'" height="'+Math.max(0,sh-1)+'" rx="3" fill="'+DS_PAL[(ns>1?si:i)%DS_PAL.length]+'"><title>'+_dsEsc(L)+': '+v+'</title></rect>';
      if(ns===1)g+='<text x="'+(left+bw+6)+'" y="'+(yy+sh/2+4)+'" font-size="12" fill="'+DS_LABEL+'">'+_dsFmt(v)+'</text>'; });
    var lab=L.length>24?L.slice(0,23)+'…':L; g+='<text x="'+(left-8)+'" y="'+(y+rh/2+4)+'" text-anchor="end" font-size="12.5" fill="'+DS_LABEL+'">'+_dsEsc(lab)+'</text>'; });
  return _dsWrap(g,W,H)+(ns>1?_dsLegend(d.series.map(function(s){return s.name;})):'');
}
function _dsLine(d,area,combo){
  var W=680,H=290,left=48,right=20,top=16,bottom=42,plotW=W-left-right,plotH=H-top-bottom,n=d.labels.length;
  var allv=[].concat.apply([],d.series.map(function(s){return s.values;})); var max=Math.max.apply(null,allv.concat([1])),min=Math.min.apply(null,allv.concat([0])); if(min>0)min=0;
  var xf=function(i){return left+(n<=1?plotW/2:plotW*i/(n-1));}, yf=function(v){return top+plotH-plotH*(v-min)/((max-min)||1);};
  var tick='';for(var t=0;t<=4;t++){var yv=min+(max-min)*t/4,y=top+plotH-plotH*t/4;tick+='<line x1="'+left+'" y1="'+y+'" x2="'+(left+plotW)+'" y2="'+y+'" stroke="'+DS_GRID+'"/><text x="'+(left-6)+'" y="'+(y+3)+'" text-anchor="end" font-size="10" fill="'+DS_AXIS+'">'+_dsFmt(yv)+'</text>';}
  var g='';
  d.series.forEach(function(se,si){ if(combo&&si===0){ // first series as columns
      var gw=plotW/n; se.values.forEach(function(v,i){ var bh=plotH*(v-min)/((max-min)||1),y=top+plotH-bh; g+='<rect x="'+(xf(i)-gw*0.3)+'" y="'+y+'" width="'+(gw*0.6)+'" height="'+Math.max(0,bh)+'" fill="'+DS_PAL[0]+'" opacity="0.85"/>'; }); return; }
    var pts=se.values.map(function(v,i){return xf(i)+','+yf(v);}).join(' '); var col=DS_PAL[si%DS_PAL.length];
    if(area&&d.series.length===1){ g+='<polygon points="'+left+','+(top+plotH)+' '+pts+' '+(left+plotW)+','+(top+plotH)+'" fill="'+col+'" opacity="0.18"/>'; }
    g+='<polyline points="'+pts+'" fill="none" stroke="'+col+'" stroke-width="2.5"/>';
    se.values.forEach(function(v,i){ g+='<circle cx="'+xf(i)+'" cy="'+yf(v)+'" r="3" fill="'+col+'"><title>'+_dsEsc(se.name)+' · '+_dsEsc(d.labels[i])+': '+v+'</title></circle>'; }); });
  var step=Math.ceil(n/8); d.labels.forEach(function(L,i){ if(i%step)return; var lab=L.length>10?L.slice(0,9)+'…':L; g+='<text x="'+xf(i)+'" y="'+(H-bottom+18)+'" text-anchor="middle" font-size="10.5" fill="'+DS_LABEL+'">'+_dsEsc(lab)+'</text>'; });
  return _dsWrap(tick+g,W,H)+_dsLegend(d.series.map(function(s){return s.name;}));
}
function _dsPie(d,donut){
  var s=d.series[0]; if(!s) return '<p style="color:'+DS_LABEL+'">No numeric data.</p>';
  var data=d.labels.map(function(L,i){return {l:L,v:Math.max(0,s.values[i]||0)};}).filter(function(x){return x.v>0;});
  var tot=data.reduce(function(a,b){return a+b.v;},0)||1, cx=150,cy=150,r=120,ir=donut?64:0,ang=-Math.PI/2,g='';
  data.forEach(function(x,i){ var a2=ang+2*Math.PI*x.v/tot, x1=cx+r*Math.cos(ang),y1=cy+r*Math.sin(ang),x2=cx+r*Math.cos(a2),y2=cy+r*Math.sin(a2),big=(a2-ang)>Math.PI?1:0,col=DS_PAL[i%DS_PAL.length];
    if(ir){ var xi1=cx+ir*Math.cos(a2),yi1=cy+ir*Math.sin(a2),xi2=cx+ir*Math.cos(ang),yi2=cy+ir*Math.sin(ang);
      g+='<path d="M'+x1+' '+y1+' A'+r+' '+r+' 0 '+big+' 1 '+x2+' '+y2+' L'+xi1+' '+yi1+' A'+ir+' '+ir+' 0 '+big+' 0 '+xi2+' '+yi2+' Z" fill="'+col+'"><title>'+_dsEsc(x.l)+': '+x.v+' ('+Math.round(x.v/tot*100)+'%)</title></path>'; }
    else g+='<path d="M'+cx+' '+cy+' L'+x1+' '+y1+' A'+r+' '+r+' 0 '+big+' 1 '+x2+' '+y2+' Z" fill="'+col+'"><title>'+_dsEsc(x.l)+': '+x.v+' ('+Math.round(x.v/tot*100)+'%)</title></path>';
    ang=a2; });
  if(donut)g+='<text x="'+cx+'" y="'+(cy-2)+'" text-anchor="middle" font-size="26" font-weight="700" fill="'+DS_LABEL+'">'+_dsFmt(tot)+'</text><text x="'+cx+'" y="'+(cy+16)+'" text-anchor="middle" font-size="11" fill="'+DS_AXIS+'">total</text>';
  return _dsWrap(g,300,300)+_dsLegend(data.map(function(x){return x.l;}));
}
function _dsTreemap(d){
  var s=d.series[0]; if(!s)return''; var W=680,H=320;
  var items=d.labels.map(function(L,i){return {l:L,v:Math.max(0,s.values[i]||0)};}).filter(function(x){return x.v>0;}).sort(function(a,b){return b.v-a.v;}).slice(0,24);
  var tot=items.reduce(function(a,b){return a+b.v;},0)||1, g='';
  // simple row-based squarify
  var x=0,y=0,rowH,i=0; var area=W*H; items.forEach(function(it){it.a=it.v/tot*area;});
  while(i<items.length){ var remW=W-x; var row=[],sum=0; // greedily fill a row spanning remaining width
    var rh=Math.max(28, Math.sqrt(items[i].a)); rh=Math.min(rh,H-y);
    var acc=0; while(i<items.length && acc< remW*rh*0.98){ row.push(items[i]); acc+=items[i].a; i++; if(acc>=remW*rh) break; }
    var rowSum=row.reduce(function(a,b){return a+b.a;},0); var rowh=Math.min(H-y, rowSum/remW); if(rowh<24)rowh=Math.min(H-y,24);
    var cx=x; row.forEach(function(it,k){ var w=it.a/rowSum*remW; var col=DS_PAL[(items.indexOf(it))%DS_PAL.length];
      g+='<rect x="'+cx+'" y="'+y+'" width="'+Math.max(0,w-2)+'" height="'+Math.max(0,rowh-2)+'" fill="'+col+'" rx="3"><title>'+_dsEsc(it.l)+': '+it.v+'</title></rect>';
      if(w>52&&rowh>24){ g+='<text x="'+(cx+5)+'" y="'+(y+16)+'" font-size="11.5" fill="#10131a" font-weight="700">'+_dsEsc(it.l.length>Math.floor(w/8)?it.l.slice(0,Math.floor(w/8))+'…':it.l)+'</text><text x="'+(cx+5)+'" y="'+(y+30)+'" font-size="10.5" fill="#10131a">'+_dsFmt(it.v)+'</text>'; }
      cx+=w; }); y+=rowh; if(y>=H)break; }
  return _dsWrap(g,W,H);
}
function _dsFunnel(d){
  var s=d.series[0]; if(!s)return''; var W=560, items=d.labels.map(function(L,i){return {l:L,v:Math.max(0,s.values[i]||0)};});
  var max=Math.max.apply(null,items.map(function(x){return x.v;}).concat([1])), rh=44,gap=8,H=items.length*(rh+gap)+10,g='';
  items.forEach(function(it,i){ var w=(W-160)*it.v/max, x=(W-160-w)/2+130, y=10+i*(rh+gap); var col=DS_PAL[i%DS_PAL.length];
    var wN=i<items.length-1?(W-160)*items[i+1].v/max:w, xN=(W-160-wN)/2+130;
    g+='<polygon points="'+x+','+y+' '+(x+w)+','+y+' '+(xN+wN)+','+(y+rh)+' '+xN+','+(y+rh)+'" fill="'+col+'"><title>'+_dsEsc(it.l)+': '+it.v+'</title></polygon>';
    g+='<text x="122" y="'+(y+rh/2+4)+'" text-anchor="end" font-size="12.5" fill="'+DS_LABEL+'">'+_dsEsc(it.l.length>18?it.l.slice(0,17)+'…':it.l)+'</text>';
    g+='<text x="'+(W/2)+'" y="'+(y+rh/2+5)+'" text-anchor="middle" font-size="13" font-weight="700" fill="#10131a">'+_dsFmt(it.v)+'</text>'; });
  return _dsWrap(g,W,H);
}
function _dsWaterfall(d){
  var s=d.series[0]; if(!s)return''; var W=680,H=300,left=48,bottom=48,top=16,plotW=W-left-20,plotH=H-top-bottom;
  var vals=d.labels.map(function(L,i){return s.values[i]||0;}); var run=0,cum=[0]; vals.forEach(function(v){run+=v;cum.push(run);});
  var mx=Math.max.apply(null,cum),mn=Math.min.apply(null,cum.concat([0])); var yf=function(v){return top+plotH-plotH*(v-mn)/((mx-mn)||1);};
  var gw=plotW/vals.length,g='';
  vals.forEach(function(v,i){ var y0=yf(cum[i]),y1=yf(cum[i+1]),x=left+i*gw+gw*0.2,w=gw*0.6,col=v>=0?'var(--ok)':'var(--cx-e0607e)';
    g+='<rect x="'+x+'" y="'+Math.min(y0,y1)+'" width="'+w+'" height="'+Math.max(1,Math.abs(y1-y0))+'" fill="'+col+'"><title>'+_dsEsc(d.labels[i])+': '+(v>=0?'+':'')+v+'</title></rect>';
    var lab=d.labels[i]; g+='<text x="'+(x+w/2)+'" y="'+(H-bottom+16)+'" text-anchor="middle" font-size="10" fill="'+DS_LABEL+'">'+_dsEsc(lab.length>8?lab.slice(0,7)+'…':lab)+'</text>'; });
  return _dsWrap(g,W,H);
}
function _dsRadar(d){
  var W=340,H=340,cx=170,cy=170,R=120,n=d.labels.length; if(n<3)return _dsBar(d);
  var max=Math.max.apply(null,[].concat.apply([1],d.series.map(function(s){return s.values;})));
  var ang=function(i){return -Math.PI/2+2*Math.PI*i/n;}, g='';
  for(var t=1;t<=4;t++){ var pts=d.labels.map(function(_,i){var r=R*t/4;return (cx+r*Math.cos(ang(i)))+','+(cy+r*Math.sin(ang(i)));}).join(' '); g+='<polygon points="'+pts+'" fill="none" stroke="'+DS_GRID+'"/>'; }
  d.labels.forEach(function(L,i){ g+='<line x1="'+cx+'" y1="'+cy+'" x2="'+(cx+R*Math.cos(ang(i)))+'" y2="'+(cy+R*Math.sin(ang(i)))+'" stroke="'+DS_GRID+'"/><text x="'+(cx+(R+14)*Math.cos(ang(i)))+'" y="'+(cy+(R+14)*Math.sin(ang(i)))+'" text-anchor="middle" font-size="10.5" fill="'+DS_LABEL+'">'+_dsEsc(L.length>10?L.slice(0,9)+'…':L)+'</text>'; });
  d.series.forEach(function(se,si){ var pts=se.values.map(function(v,i){var r=R*(v/max);return (cx+r*Math.cos(ang(i)))+','+(cy+r*Math.sin(ang(i)));}).join(' '); var col=DS_PAL[si%DS_PAL.length]; g+='<polygon points="'+pts+'" fill="'+col+'" fill-opacity="0.18" stroke="'+col+'" stroke-width="2"/>'; });
  return _dsWrap(g,W,H)+_dsLegend(d.series.map(function(s){return s.name;}));
}
function _dsScatter(d,bubble){
  var xs=d.series[0], ys=d.series[1]; if(!xs||!ys)return '<p style="color:'+DS_LABEL+'">Scatter needs two numeric columns.</p>';
  var zs=bubble?d.series[2]:null; var W=680,H=320,left=52,bottom=44,top=16,plotW=W-left-20,plotH=H-top-bottom;
  var xmax=Math.max.apply(null,xs.values.concat([1])),ymax=Math.max.apply(null,ys.values.concat([1])),zmax=zs?Math.max.apply(null,zs.values.concat([1])):1;
  var xf=function(v){return left+plotW*v/xmax;},yf=function(v){return top+plotH-plotH*v/ymax;},g='';
  for(var t=0;t<=4;t++){var y=top+plotH-plotH*t/4;g+='<line x1="'+left+'" y1="'+y+'" x2="'+(left+plotW)+'" y2="'+y+'" stroke="'+DS_GRID+'"/><text x="'+(left-6)+'" y="'+(y+3)+'" text-anchor="end" font-size="10" fill="'+DS_AXIS+'">'+_dsFmt(ymax*t/4)+'</text>';}
  xs.values.forEach(function(v,i){ var r=zs?4+10*Math.sqrt((zs.values[i]||0)/zmax):4; g+='<circle cx="'+xf(v)+'" cy="'+yf(ys.values[i]||0)+'" r="'+r+'" fill="'+DS_PAL[1]+'" fill-opacity="0.6" stroke="'+DS_PAL[1]+'"><title>'+_dsEsc(d.labels[i])+': ('+v+', '+(ys.values[i]||0)+(zs?', '+(zs.values[i]||0):'')+')</title></circle>'; });
  g+='<text x="'+(left+plotW/2)+'" y="'+(H-6)+'" text-anchor="middle" font-size="11" fill="'+DS_AXIS+'">'+_dsEsc(xs.name)+'</text>';
  return _dsWrap(g,W,H);
}
function _dsHeatmap(d){
  if(!d.pivoted && d.series.length<2) return _dsBar(d);
  var cols=d.series.map(function(s){return s.name;}), rowsL=d.labels;
  var left=158, top=52, cellH=50;
  var cellW=Math.max(92,Math.min(190,Math.round((760-left)/Math.max(1,cols.length))));
  var W=left+cols.length*cellW+16, H=top+rowsL.length*cellH+18;
  var mx=Math.max.apply(null,[].concat.apply([1],d.series.map(function(s){return s.values;}))),g='';
  cols.forEach(function(c,j){ g+='<text x="'+(left+j*cellW+cellW/2)+'" y="'+(top-14)+'" text-anchor="middle" font-size="12.5" font-weight="600" fill="'+DS_LABEL+'">'+_dsEsc(c.length>16?c.slice(0,15)+'…':c)+'</text>'; });
  rowsL.forEach(function(L,i){ g+='<text x="'+(left-12)+'" y="'+(top+i*cellH+cellH/2+4)+'" text-anchor="end" font-size="13" fill="'+DS_LABEL+'">'+_dsEsc(L.length>22?L.slice(0,21)+'…':L)+'</text>';
    d.series.forEach(function(se,j){ var v=se.values[i]||0, a=mx?v/mx:0; g+='<rect x="'+(left+j*cellW+3)+'" y="'+(top+i*cellH+3)+'" width="'+(cellW-6)+'" height="'+(cellH-6)+'" rx="5" fill="var(--cx-3ea6ff)" fill-opacity="'+(0.10+0.85*a).toFixed(2)+'"><title>'+_dsEsc(L)+' · '+_dsEsc(se.name)+': '+v+'</title></rect><text x="'+(left+j*cellW+cellW/2)+'" y="'+(top+i*cellH+cellH/2+4)+'" text-anchor="middle" font-size="12.5" font-weight="600" fill="'+(a>0.5?'#07131f':'var(--ink-2,#c8d6e8)')+'">'+_dsFmt(v)+'</text>'; }); });
  return _dsWrap(g,W,H);
}
function _dsGauge(d){
  var s=d.series[0]; var v=s?(s.values[0]||0):0; var max=(s&&s.values.length===1&&v>=0&&v<=100)?100:Math.max.apply(null,(s?s.values:[1]).concat([1]));   /* build 511: one value ≤ 100 is a percentage */ var pct=Math.max(0,Math.min(1,v/(max||1)));
  var cx=150,cy=160,r=110,a0=Math.PI,a1=Math.PI*(1-pct); var x0=cx+r*Math.cos(Math.PI),y0=cy,x1=cx+r*Math.cos(a1),y1=cy+r*Math.sin(-a1)*0+cy-r*Math.sin(a1);
  var arc=function(a,col,wdt){ var xa=cx+r*Math.cos(Math.PI),ya=cy; var xb=cx+r*Math.cos(a),yb=cy-r*Math.sin(a); var big=(Math.PI-a)>Math.PI?1:0; return '<path d="M'+xa+' '+ya+' A'+r+' '+r+' 0 '+big+' 1 '+xb+' '+yb+'" fill="none" stroke="'+col+'" stroke-width="'+wdt+'" stroke-linecap="round"/>'; };
  var g=arc(0,DS_GRID,16)+arc(Math.PI*(1-pct),'var(--ok)',16)+'<text x="'+cx+'" y="'+(cy-6)+'" text-anchor="middle" font-size="34" font-weight="700" fill="'+DS_LABEL+'">'+_dsFmt(v)+'</text><text x="'+cx+'" y="'+(cy+16)+'" text-anchor="middle" font-size="12" fill="'+DS_AXIS+'">'+_dsEsc(d.labels[0]||'')+'</text>';
  return _dsWrap(g,300,190);
}
function _dsProgress(d){
  var s=d.series[0]; if(!s)return''; var max=Math.max.apply(null,s.values.concat([1])),W=680,rh=30,gap=12,H=d.labels.length*(rh+gap)+8,g='';
  d.labels.forEach(function(L,i){ var v=s.values[i]||0,w=(W-220)*v/max,y=8+i*(rh+gap),pct=Math.round(v/max*100);
    g+='<text x="8" y="'+(y+rh/2+4)+'" font-size="12.5" fill="'+DS_LABEL+'">'+_dsEsc(L.length>24?L.slice(0,23)+'…':L)+'</text>';
    g+='<rect x="170" y="'+y+'" width="'+(W-220)+'" height="'+rh+'" rx="6" fill="'+DS_GRID+'"/><rect x="170" y="'+y+'" width="'+Math.max(2,w)+'" height="'+rh+'" rx="6" fill="'+DS_PAL[i%DS_PAL.length]+'"><title>'+_dsEsc(L)+': '+v+'</title></rect>';
    g+='<text x="'+(W-42)+'" y="'+(y+rh/2+4)+'" font-size="12" fill="'+DS_LABEL+'">'+_dsFmt(v)+'</text>'; });
  return _dsWrap(g,W,H);
}
function _dsHistogram(d){ // bucket a single numeric series' VALUES into bins
  var s=d.series[0]; if(!s)return''; var vals=s.values.filter(function(v){return isFinite(v);}); if(!vals.length)return'';
  var mn=Math.min.apply(null,vals),mx=Math.max.apply(null,vals),bins=Math.min(12,Math.max(4,Math.round(Math.sqrt(vals.length)))),bw=(mx-mn)/bins||1;
  var counts=new Array(bins).fill(0); vals.forEach(function(v){var b=Math.min(bins-1,Math.floor((v-mn)/bw));counts[b]++;});
  var dd={lc:'bin',labels:counts.map(function(_,i){return _dsFmt(mn+i*bw);}),series:[{name:'count',values:counts}]};
  return _dsColumn(dd,false,false);
}
function dashTableHTML(cols,rows,limit){ cols=cols&&cols.length?cols:(rows.length?Object.keys(rows[0]):[]); var rs=rows.slice(0,limit||50);
  return '<table style="border-collapse:collapse;width:100%;font-size:12.5px"><thead><tr>'+cols.map(function(c){return '<th style="text-align:left;padding:5px 8px;border-bottom:1px solid '+DS_GRID+';color:'+DS_LABEL+'">'+_dsEsc(c)+'</th>';}).join('')+'</tr></thead><tbody>'+rs.map(function(r){return '<tr>'+cols.map(function(c){return '<td style="padding:5px 8px;border-bottom:1px solid '+DS_GRID+';color:'+DS_LABEL+'">'+_dsEsc(r[c])+'</td>';}).join('')+'</tr>';}).join('')+'</tbody></table>'+(rows.length>rs.length?'<div style="font-size:11px;color:'+DS_AXIS+';margin-top:4px">… '+(rows.length-rs.length)+' more row(s)</div>':''); }

/* ---- the single entry point ---- */
function dashSVG(type, cols, rows, spec){
  if(!rows||!rows.length) return '<p style="color:'+DS_LABEL+'">No rows.</p>';
  var d=dashData(cols,rows,spec);
  switch(String(type||'').toLowerCase()){
    case 'kpi': { var r0=rows[0]; return '<div style="display:flex;gap:14px;flex-wrap:wrap">'+cols.filter(function(c){return String(c).indexOf('__')!==0;}).map(function(c){return '<div style="min-width:110px"><div style="font-size:26px;font-weight:800;color:'+DS_PAL[1]+'">'+_dsEsc(r0[c])+'</div><div style="font-size:11px;color:'+DS_LABEL+'">'+_dsEsc(c)+'</div></div>';}).join('')+'</div>'; }
    case 'bar': return _dsBar(d);
    case 'column': return _dsColumn(d,false,false);
    case 'grouped': case 'grouped_bar': case 'group': return d.series.length>1?_dsColumn(d,false,true):_dsColumn(d,false,false);
    case 'stacked': case 'stacked_bar': case 'stackedcolumn': return _dsColumn(d,true,false);
    case 'pie': return _dsPie(d,false);
    case 'donut': return _dsPie(d,true);
    case 'line': return _dsLine(d,false,false);
    case 'multiline': case 'multi_line': return _dsLine(d,false,false);
    case 'area': return _dsLine(d,true,false);
    case 'combo': return _dsLine(d,false,true);
    case 'gauge': return _dsGauge(d);
    case 'radar': return _dsRadar(d);
    case 'treemap': return _dsTreemap(d);
    case 'funnel': return _dsFunnel(d);
    case 'waterfall': return _dsWaterfall(d);
    case 'scatter': return _dsScatter(d,false);
    case 'bubble': return _dsScatter(d,true);
    case 'heatmap': case 'matrix': return _dsHeatmap(d);
    case 'progress': case 'bullet': return _dsProgress(d);
    case 'histogram': return _dsHistogram(d);
    case 'table': return dashTableHTML(cols,rows);
    default: return d.series.length? _dsBar(d) : dashTableHTML(cols,rows);
  }
}
var DASH_TYPES=['auto','bar','column','stacked','grouped','pie','donut','line','multiline','area','combo','scatter','bubble','heatmap','treemap','funnel','waterfall','radar','gauge','progress','histogram','kpi','table'];
