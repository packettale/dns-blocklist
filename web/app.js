'use strict';
const $=id=>document.getElementById(id),number=n=>Number(n||0).toLocaleString();
const labels={ads:'Ads',analytics:'Analytics',tracking:'Tracking',telemetry:'Telemetry',mixed:'Mixed ads / trackers / malware',malware:'Malware',phishing:'Phishing',fraud:'Fraud & scams',cryptomining:'Cryptomining',fingerprinting:'Fingerprinting','email-tracking':'Email tracking','session-replay':'Session replay',social:'Social networks',adult:'Adult content',gambling:'Gambling',violence:'Violence',piracy:'Piracy','threat-intelligence':'Custom threat intelligence',tor:'Tor nodes','security-threats':'Security threats','attacking-ips':'Attacking / suspicious IPs','cname-tracking':'CNAME-cloaked trackers','cname-ads':'CNAME-cloaked ads','popup-ads':'Pop-up ads','push-notifications':'Push notifications','newly-registered-domains':'Newly registered domains',dga:'DGA / high-entropy new domains','encrypted-dns':'Encrypted DNS / DoH',bypass:'DNS / VPN / Tor / proxy bypass','dynamic-dns':'Dynamic DNS','badware-hosting':'Badware hosting','free-hosting':'Free hosting','no-safesearch':'Search without SafeSearch','url-shorteners':'URL shorteners','referral-tracking':'Referral tracking',p2p:'P2P infrastructure','compromised-ips':'Compromised IPs','botnet-c2':'Botnet command and control',suspicious:'Suspicious / spam',stalkerware:'Stalkerware','game-console-ads':'Game console ads','smart-tv':'Smart TV ads / tracking','certificate-crl':'Certificate revocation endpoints','certificate-ocsp':'Certificate status endpoints',ai:'AI services',cryptocurrency:'Cryptocurrency services',dating:'Dating',fonts:'Web fonts','chat-widgets':'Chat widgets',marketing:'Marketing services','remote-access':'Remote access',risk:'Risk / monitoring',typosquatting:'Typosquatting','vpn-proxy':'VPN / proxy services',abuse:'Abuse',drugs:'Drugs',ransomware:'Ransomware',redirects:'Redirect services',torrent:'Torrents','social-tiktok':'TikTok services','social-whatsapp':'WhatsApp services','social-youtube':'YouTube services','social-twitter':'Twitter / X services',vaping:'Vaping','apple-bloat':'Apple bloat','microsoft-bloat':'Microsoft bloat','dns-resolvers':'DNS resolvers'};
labels['malware-and-support']='Malware / remote-support policy';
for(const [key,name]of Object.entries({amazon:'Amazon',apple:'Apple',huawei:'Huawei',lg:'LG webOS','oppo-realme':'OPPO / Realme',roku:'Roku',samsung:'Samsung',tiktok:'TikTok',vivo:'Vivo',microsoft:'Microsoft',xiaomi:'Xiaomi'}))labels['trackers-'+key]=name+' trackers';
for(const [key,name]of Object.entries({amazon:'Amazon',apple:'Apple',google:'Google',meta:'Meta / Facebook',microsoft:'Microsoft'}))labels['big-tech-'+key]=name+' services';
for(const [key,name]of Object.entries({no:'Nordic',pl:'Polish',ko:'Korean',vn:'Vietnamese',sv:'Swedish',ir:'Persian',mk:'Macedonian',zh:'Chinese',id:'Indonesian',tr:'Turkish',hu:'Hungarian',lt:'Lithuanian',he:'Hebrew',ua:'Ukrainian'}))labels['regional-'+key]=name+' ads / trackers';
let data,scopeGeneration=0,format='domains',query='',toastTimer;
try{const saved=localStorage.getItem('dns-ip-blocklist:format');if(['domains','ips','both'].includes(saved))format=saved;}catch{}
const scopes=new Map(),openGroups=new Map();
const icons={copy:'<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',download:'<path d="M12 3v12m-5-5 5 5 5-5M4 16v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4"/>',chevron:'<path d="m9 5 7 7-7 7"/>',check:'<path d="m5 12 4 4L20 5"/>'};
function icon(name){const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox','0 0 24 24');svg.setAttribute('aria-hidden','true');svg.innerHTML=icons[name];return svg;}
function el(tag,text,className){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(className)n.className=className;return n;}
function safeLink(url,text){const a=el('a',text);try{const parsed=new URL(url,location.href);if(['http:','https:'].includes(parsed.protocol)){a.href=parsed.href;if(parsed.origin!==location.origin){a.target='_blank';a.rel='noopener noreferrer';}}}catch{}return a;}
function labelFor(name){return name==='protection'?'Ads, trackers & threats':name==='all'?'All categories':name.startsWith('groups/')?`Combined ${data.groups?.[name.slice(7)]?.label||name.slice(7)}`:data?.categories[name]?.label||labels[name]||name;}
function selection(name,counts){
  const hasDomains=counts.domains>0,hasIPs=counts.ips>0;
  if(format==='domains'&&!hasDomains)return {available:false,switchTo:'ips',count:counts.ips,kind:'IPs'};
  if(format==='ips'&&!hasIPs)return {available:false,switchTo:'domains',count:counts.domains,kind:'domains'};
  const kind=format==='domains'?'domains':format==='ips'?'IPs':hasDomains&&hasIPs?'entries':hasDomains?'domains':'IPs';
  const count=format==='domains'?counts.domains:format==='ips'?counts.ips:counts.domains+counts.ips;
  const path=format==='both'||!hasDomains||!hasIPs?`${name}.txt`:name==='all'?`${format}.txt`:`${name}.${format}.txt`;
  return {available:true,count,kind,path,url:new URL(path,location.href).href};
}
async function copyURL(button,value){
  clearTimeout(toastTimer);const status=$('copy-status');
  try{
    await navigator.clipboard.writeText(value.url);button.replaceChildren(icon('check'),document.createTextNode('Copied'));status.textContent=value.url;status.hidden=false;
    setTimeout(()=>{if(button.isConnected)button.replaceChildren(icon('copy'),document.createTextNode('Copy URL'));},2200);toastTimer=setTimeout(()=>{status.hidden=true;},2200);
  }catch{
    const input=el('input');input.value=value.url;input.readOnly=true;input.setAttribute('aria-label','Feed URL');status.replaceChildren(input);status.hidden=false;input.focus();input.select();
  }
}
function actions(name,counts,{bundle=false}={}){
  const value=selection(name,counts),box=el('div',undefined,bundle?'bundle-actions':'row-actions');
  const label=labelFor(name);
  if(!value.available){const button=el('button',`Use ${value.switchTo==='ips'?'IPs':'domains'}`,bundle?'button button-primary type-switch':'type-switch');button.type='button';button.addEventListener('click',()=>setFormat(value.switchTo));box.append(button);return box;}
  const copy=el('button',undefined,bundle?'button button-primary bundle-copy':'row-copy');copy.type='button';copy.setAttribute('aria-label',`Copy ${label} ${value.kind} URL`);copy.append(icon('copy'),document.createTextNode('Copy URL'));copy.addEventListener('click',()=>copyURL(copy,value));
  const download=safeLink(value.path,undefined);download.className=bundle?'button button-secondary bundle-download':'row-download';download.download=value.path.split('/').at(-1);download.setAttribute('aria-label',`Download ${label} ${value.kind} .txt`);download.title='Download .txt';download.append(icon('download'));if(bundle)download.append(document.createTextNode('.txt'));
  box.append(copy,download);return box;
}
function setFormat(value){format=value;try{localStorage.setItem('dns-ip-blocklist:format',value);}catch{}renderCollections();}
function searchMatch(name){
  const aliases={social:'facebook meta instagram tiktok twitter snapchat',tor:'tor nodes anonymizer',telemetry:'windows office microsoft telemetry','attacking-ips':'ip reputation attackers suspicious',adult:'porn pornography nsfw',violence:'gore violence nsfw'};
  const section=data.taxonomy.find(s=>s.id===data.categories[name]?.section)?.label||'';
  return `${labelFor(name)} ${name} ${section} ${aliases[name]||''} ${data.bundles.protection.categories.includes(name)?'protection':''}`.toLowerCase().includes(query);
}
function updateExpand(){const groups=[...$('category-catalog').querySelectorAll('.category-group')];$('expand-categories').textContent=groups.length&&groups.every(d=>d.open)?'Collapse all':'Expand all';}
function renderCollections(){
  if(!data)return;
  const all=Object.keys(data.categories).filter(name=>data.categories[name].total),matching=all.filter(searchMatch),container=$('category-catalog');container.replaceChildren();
  const definitions=[{id:'combined',label:'Combined feeds'},...data.taxonomy];let rendered=0;
  for(const section of definitions){
    const names=section.id==='combined'?['protection','all'].filter(name=>!query||labelFor(name).toLowerCase().includes(query)):matching.filter(name=>data.categories[name].section===section.id);
    if(!names.length)continue;rendered++;
    const details=el('details',undefined,'category-group');details.dataset.group=section.id;details.open=!!query||openGroups.get(section.id)===true;
    const summary=el('summary');summary.append(icon('chevron'),el('span',section.label));
    if(section.id!=='combined'&&names.every(n=>data.bundles.protection.categories.includes(n)))summary.append(el('span','Protection','protection-tag'));
    summary.append(el('span',number(names.length),'group-count'));summary.addEventListener('click',()=>{if(!query)openGroups.set(section.id,!details.open);});details.addEventListener('toggle',updateExpand);
    const list=el('ul',undefined,'category-list');
    const group=data.groups?.[section.id];
    if(group){const name=group.feed,value=selection(name,group),item=el('li',undefined,'category-item combined-item group-combined-item'),info=el('div',undefined,'row-info');item.dataset.category=name;info.append(el('div','Combined','category-name'),el('div',`${group.categories.length} categories · ${number(value.count)} ${value.kind}`,'category-meta'));item.append(info,actions(name,group));list.append(item);}
    for(const name of names){const combined=section.id==='combined',counts=combined?data.feeds[name]:data.categories[name],value=selection(name,counts),item=el('li',undefined,combined?'category-item combined-item':'category-item'),info=el('div',undefined,'row-info');item.dataset.category=name;
      const membership=combined?`${name==='protection'?data.bundles.protection.categories.length:all.length} categories · `:'';
      info.append(el('div',labelFor(name),'category-name'),el('div',`${membership}${number(value.count)} ${value.kind}`,'category-meta'));item.append(info,actions(name,counts));list.append(item);
    }
    details.append(summary,list);container.append(details);
  }
  $('catalog-count').textContent=`${query?matching.length+' / ':''}${all.length} categories`;$('catalog-empty').hidden=rendered>0;$('search-count').textContent=query?number(matching.length):'';
  for(const button of document.querySelectorAll('[data-format]'))button.setAttribute('aria-pressed',String(button.dataset.format===format));
  updateExpand();
}
function current(){const scope=$('category-scope').value;return scope==='all'?{sources:data.sources,matrix:data.matrix}:scopes.get(scope);}
function renderSources(){
  const detail=current(),body=$('sources-body');body.replaceChildren();if(!detail)return;const reports=new Map(data.sourceReports.map(s=>[s.id,s]));
  for(const [index,source]of data.sources.entries()){
    const counts=detail.sources[index],report=reports.get(source.id),row=el('tr'),name=el('td');name.append(safeLink(source.homepage||report?.homepage||'sources.json',source.name));row.append(name);
    for(const key of ['domains','ips','sharedDomains','sharedIPs','uniqueDomains','uniqueIPs'])row.append(el('td',number(counts[key])));
    row.append(el('td',report?.updatedAt?new Date(report.updatedAt).toISOString().slice(0,10):'—'));const file=el('td');file.append(safeLink(report?.normalizedFeed||`upstreams/${source.id}.txt`,'All .txt'));row.append(file);body.append(row);
  }
}
function renderPair(){const detail=current();if(!detail)return;const a=Number($('compare-a').value),b=Number($('compare-b').value),pair=detail.matrix?.[a]?.[b]||{domains:0,ips:0};$('pair-domains').textContent=number(pair.domains);$('pair-ips').textContent=number(pair.ips);}
async function loadScope(){
  if(!data)return;const scope=$('category-scope').value,generation=++scopeGeneration;
  if(scope!=='all'&&!scopes.has(scope)){const counts=scope.startsWith('groups/')?data.groups?.[scope.slice(7)]:data.categories[scope];const response=await fetch(counts.statisticsUrl);if(!response.ok)throw Error('Statistics unavailable');scopes.set(scope,await response.json());}
  if(generation===scopeGeneration){renderSources();renderPair();}
}
function scopeError(){$('sources-body').replaceChildren();$('pair-domains').textContent='—';$('pair-ips').textContent='—';}
function renderSourceOptions(){
  const preserved=$('category-scope').value,select=$('category-scope');select.replaceChildren(new Option('All categories','all'));
  for(const section of data.taxonomy){const options=document.createElement('optgroup');options.label=section.label;const group=data.groups?.[section.id];if(group?.statisticsUrl)options.append(new Option('Combined',group.feed));for(const [name,counts]of Object.entries(data.categories))if(counts.total&&counts.section===section.id)options.append(new Option(labelFor(name),name));if(options.children.length)select.append(options);}if(data.categories[preserved]?.total||preserved.startsWith('groups/')&&data.groups?.[preserved.slice(7)]?.statisticsUrl)select.value=preserved;
  for(const id of ['compare-a','compare-b']){const target=$(id),previous=target.value;target.replaceChildren();data.sources.forEach((s,i)=>target.add(new Option(s.name,i)));target.value=String(previous!==''?Math.min(Number(previous),data.sources.length-1):id==='compare-b'&&data.sources.length>1?1:0);}
}
async function refresh(){
  try{
    const response=await fetch('stats.json',{cache:'no-store'});if(!response.ok)throw Error('Statistics unavailable');const next=await response.json();if(next.schemaVersion!==2||!Array.isArray(next.sources)||!next.bundles||!next.taxonomy)throw Error('Invalid statistics');
    if(data?.publishedAt!==next.publishedAt)scopes.clear();data=next;
    const date=new Date(data.publishedAt),utc=date.toISOString();$('updated').textContent=`${utc.slice(0,10)} ${utc.slice(11,16)} UTC`;$('updated').dateTime=utc;$('updated').title=utc;
    $('source-count').textContent=number(data.sources.length);$('statistics-source-count').textContent=`${number(data.sources.length)} sources`;
    const totals=data.totals;$('domain-total').textContent=number(totals.domains);$('ip-total').textContent=number(totals.ips);$('shared-total').textContent=number(totals.sharedDomains+totals.sharedIPs);$('individual-total').textContent=number(totals.uniqueDomains+totals.uniqueIPs);
    renderSourceOptions();renderCollections();$('error').hidden=true;if($('statistics').open)await loadScope();
  }catch{$('error').hidden=false;$('error').replaceChildren(safeLink('protection.txt','Protection .txt'),document.createTextNode(' · '),safeLink('optional.txt','Optional .txt'));}
}
$('category-search').addEventListener('input',event=>{query=event.target.value.trim().toLowerCase();renderCollections();});
for(const button of document.querySelectorAll('[data-format]'))button.addEventListener('click',()=>setFormat(button.dataset.format));
$('expand-categories').addEventListener('click',()=>{const groups=[...$('category-catalog').querySelectorAll('.category-group')],open=!groups.every(g=>g.open);for(const group of groups){group.open=open;if(!query)openGroups.set(group.dataset.group,open);}updateExpand();});
$('statistics').addEventListener('toggle',()=>{if($('statistics').open)loadScope().catch(scopeError);});
document.querySelector('.source-nav').addEventListener('click',event=>{event.preventDefault();$('statistics').open=true;$('statistics').scrollIntoView({behavior:'smooth',block:'start'});$('statistics').querySelector('summary').focus({preventScroll:true});});
$('category-scope').addEventListener('change',()=>loadScope().catch(scopeError));
for(const id of ['compare-a','compare-b'])$(id).addEventListener('change',()=>data&&renderPair());
refresh();setInterval(refresh,300000);
