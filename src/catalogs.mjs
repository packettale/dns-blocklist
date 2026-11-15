import { sha256, jsonFile, writeJson } from './io.mjs';
import { join } from 'node:path';
import {categoryGroup} from './category-policy.mjs';

export const catalogDefinitions = [
  { id: 'adguard', name: 'AdGuard Hostlists Registry', url: 'https://github.com/AdguardTeam/HostlistsRegistry' },
  { id: 'firebog', name: 'Firebog', url: 'https://firebog.net/' },
  { id: 'safing', name: 'Safing / Portmaster', url: 'https://github.com/safing/intel-data/blob/master/lists/sources.yml' },
  { id: 'hagezi', name: 'HaGeZi', url: 'https://github.com/hagezi/dns-blocklists' },
  { id: 'shadow', name: 'ShadowWhisperer', url: 'https://github.com/ShadowWhisperer/BlockLists' },
  { id: 'blocklistproject', name: 'The Block List Project', url: 'https://github.com/blocklistproject/Lists' },
];

// Purpose mappings are reviewed independently of discovery. A new, unknown
// catalog item remains visible for review instead of silently becoming a block.
const registryPurposes = {
  1:'mixed',3:'mixed',4:'mixed',5:'mixed',6:'game-console-ads',7:'smart-tv',8:'cryptomining',9:'malware',
  10:'fraud',11:'malware',12:'malware',13:'regional-no',14:'regional-pl',15:'regional-ko',16:'regional-vn',
  17:'regional-sv',18:'phishing',19:'regional-ir',20:'regional-mk',21:'regional-zh',22:'regional-id',
  24:'mixed',25:'regional-ko',26:'regional-tr',27:'mixed',29:'regional-zh',30:'phishing',31:'stalkerware',
  33:'mixed',34:'mixed',35:'regional-hu',36:'regional-lt',37:'big-tech-google',39:'push-notifications',
  40:'regional-tr',41:'phishing',42:'malware-and-support',43:'regional-he',44:'security-threats',45:'referral-allowlist',
  46:'piracy',47:'gambling',48:'mixed',49:'mixed',50:'malware',51:'mixed',52:'bypass',54:'dynamic-dns',
  53:'ads',55:'badware-hosting',56:'abused-tlds',57:'dating',59:'popup-ads',60:'trackers-xiaomi',61:'trackers-samsung',
  62:'regional-ua',63:'trackers-microsoft',65:'trackers-vivo',66:'trackers-oppo-realme',67:'trackers-apple',
  68:'url-shorteners',69:'tracking',70:'mixed',71:'dns-rebind',72:'trackers-lg',73:'trackers-huawei',
};
export const isOptionalCategory = category => categoryGroup(category)==='optional';
export function githubPath(url) {
  try {
    const u = new URL(url);
    if (u.hostname === 'raw.githubusercontent.com') {
      const [owner,repo,branch,...path] = u.pathname.slice(1).split('/');
      if (!owner || !repo || !branch || !path.length) return null;
      return {repo:`${owner}/${repo}`,branch,path:decodeURIComponent(path.join('/'))};
    }
    if (u.hostname === 'cdn.jsdelivr.net' && u.pathname.startsWith('/gh/')) {
      const match=u.pathname.match(/^\/gh\/([^/]+)\/([^/@]+)@([^/]+)\/(.+)$/);
      if(match)return {repo:`${match[1]}/${match[2]}`,branch:match[3]==='latest'?undefined:match[3],path:decodeURIComponent(match[4])};
    }
  } catch {}
  return null;
}
const idFor = (catalog,url) => `${catalog}-${sha256(url).slice(0,12)}`;
const plainHagezi = path => path.startsWith('wildcard/') && path.endsWith('-onlydomains.txt') || path.startsWith('ips/') && path.endsWith('.txt');
export function hageziPurpose(path,repo='hagezi/dns-blocklists') {
  const name=path.split('/').at(-1).replace(/-onlydomains(?=\.txt$)/,'').replace(/\.txt$/,'');
  if (repo==='hagezi/nrd') return /^(nrd(?:7|14-8|21-15|28-22|35-29))$/.test(name)?'newly-registered-domains':/^dga(?:7|14|30)$/.test(name)?'dga':null;
  if (/^(light|multi|pro(?:\.mini|\.plus(?:\.mini)?)?|ultimate(?:\.mini)?)$/.test(name)) return 'mixed';
  const vendors={amazon:'amazon',apple:'apple',huawei:'huawei',lgwebos:'lg','oppo-realme':'oppo-realme',roku:'roku',samsung:'samsung',tiktok:'tiktok','tiktok.extended':'tiktok',vivo:'vivo',winoffice:'microsoft',xiaomi:'xiaomi'};
  if (name.startsWith('native.')) return vendors[name.slice(7)]?`trackers-${vendors[name.slice(7)]}`:null;
  const purposes={fake:'fraud',popupads:'popup-ads',tif:'security-threats','tif.medium':'security-threats','tif.mini':'security-threats',doh:'encrypted-dns','doh-vpn-proxy-bypass':'bypass',dyndns:'dynamic-dns',hoster:'badware-hosting',nosafesearch:'no-safesearch',urlshortener:'url-shorteners','anti.piracy':'piracy',gambling:'gambling','gambling.medium':'gambling','gambling.mini':'gambling',social:'social',nsfw:'adult','blocklist-referral':'referral-tracking','whitelist-referral':'referral-allowlist','spam-tlds':'abused-tlds','spam-tlds-allow':'tld-allowlist',nameserver:'nameserver-ips'};
  return purposes[name] || null;
}
const unhtml = s => s.replace(/<[^>]*>/g,'').replace(/&amp;/g,'&').replace(/&#39;/g,"'").trim();
export function parseFirebog(html) {
  const sources=[];
  for (const group of html.matchAll(/<ul class="bdUrlList\s+([^"]+)"[^>]*>([\s\S]*?)<\/ul>/g)) {
    for(const row of group[2].matchAll(/<li([^>]*)>([\s\S]*?)<\/li>/g)) {
      const links=[...row[2].matchAll(/<a\s+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/g)];
      if(links.length<2)continue;
      const name=unhtml(links[0][2]).replace(/:$/,'');
      const url=unhtml(links.at(-1)[1]);
      const specific=/adguard dns/i.test(name)?'mixed':/cryptojack/i.test(name)?'cryptomining':/phish/i.test(name)?'phishing':/stalker/i.test(name)?'stalkerware':/adult|porn/i.test(name)?'adult':/facebook/i.test(name)?'big-tech-meta':null;
      sources.push({id:idFor('firebog',url),name,provider:githubPath(url)?.repo||new URL(url).hostname,url,homepage:unhtml(links[0][1]),
        category:specific||({suspicious:'suspicious',advertising:'ads',tracking:'tracking',malicious:'malware',other:'mixed'}[group[1]]||'mixed'),
        catalog:'firebog',catalogEvidence:'https://firebog.net/',role:'supplement',license:'Original upstream terms apply; retain source attribution',
        reviewReason:row[1].includes('bdCross')?'Firebog marks this feed as not recommended':row[1].includes('bdTick')?null:'Not recommended by Firebog’s tick selection; producer review required',
        trustEvidence:row[1].includes('bdTick')?'Recommended (tick) entry in Firebog; original maintainer linked':null,
        provenance:unhtml(links[0][1]),githubPath:githubPath(url)});
    }
  }
  if(sources.length<20)throw Error('Firebog catalog schema changed or incomplete');
  return sources;
}
// Safing uses a small, stable YAML schema. Only the documented scalar fields
// and URL records are accepted here; YAML tags or executable constructs are
// never evaluated. A changed/missing schema fails this discovery adapter.
export function parseSafing(text) {
  if(!/^schemaVersion: "v2\.0\.0"/m.test(text))throw Error('Unsupported Safing catalog schema');
  const body=text.split(/^sources:\s*$/m)[1];if(!body)throw Error('Missing Safing source catalog');
  const sources=[];
  const map={ADS:'ads',ALYTC:'analytics',TELEM:'telemetry',TRACO:'tracking',BAD:'mixed',MAL:'malware',PHISH:'phishing',FRAUD:'fraud',PORN:'adult',VIOL:'violence',GAMBL:'gambling',NSFWM:'adult',UNBREAK:'unbreak-allowlist'};
  const scalar=(block,key)=>block.match(new RegExp(`^    ${key}: ?(?:"([^"\\n]*)"|([^\\n]+))$`,'m'))?.slice(1).find(x=>x!==undefined)?.trim();
  for(const block of body.split(/(?=^  - name:)/m).filter(x=>/^  - name:/m.test(x))){
    const name=block.match(/^  - name: "([^"]+)"/m)?.[1];const id=scalar(block,'id');if(!name||!id)throw Error('Invalid Safing source record');
    const code=scalar(block,'category');
    let category=map[code];
    if(id.startsWith('BT-')) category='big-tech-'+({'BT-META':'meta','BT-AMZN':'amazon','BT-GOOG':'google','BT-APPL':'apple','BT-MSFT':'microsoft','BT-MS':'microsoft'}[id]||(/Microsoft/.test(name)?'microsoft':id.toLowerCase()));
    if(id==='17-DNS')category='encrypted-dns';if(id==='17-P2P')category='p2p';
    if(code==='EXPERIMENTS')category=({'WSP':'trackers-microsoft','DCT':'tracking','SH-CRL':'certificate-crl','SH-OCSP':'certificate-ocsp'})[id];
    for(const match of block.matchAll(/^\s+- url: "([^"]+)"\s*\n\s+type: "([^"]+)"\s*\n\s+parser: "([^"]+)"/gm)){
      const url=match[1];sources.push({id:idFor('safing',url),name:`${name}${match[2]==='Domain'?'':` (${match[2]})`}`,provider:githubPath(url)?.repo||new URL(url).hostname,
        url,homepage:scalar(block,'website'),category:category||'unmapped',role:isOptionalCategory(category||'')?'optional':'supplement',
        format:category?.endsWith('allowlist')?'allowlist':undefined,license:scalar(block,'license')||'See original upstream terms',catalog:'safing',catalogEvidence:'https://github.com/safing/intel-data/blob/master/lists/sources.yml',
        trustEvidence:'Explicit source record in Safing/Portmaster’s maintained catalog; original producer linked',
        reviewReason:!category?'New source category requires review':null,provenance:scalar(block,'website'),githubPath:githubPath(url),minEntries:1});
    }
  }
  if(sources.length<25)throw Error('Safing catalog incomplete');return sources;
}

export async function discoverCatalogs({downloader,registry,existing}) {
  const specs=[],reports=[];
  const knownRegistry=new Map(existing.filter(s=>s.registryId).map(s=>[s.registryId,s]));
  for(const f of registry.filters){
    if(knownRegistry.has(f.filterId))continue;
    const category=registryPurposes[f.filterId];
    specs.push({id:`adguard-registry-${f.filterId}`,registryId:f.filterId,name:f.name,provider:githubPath(f.subscriptionUrl)?.repo||f.filterKey,
      category:category||'unmapped',role:isOptionalCategory(category||'')?'optional':'supplement',catalog:'adguard',catalogEvidence:catalogDefinitions[0].url,
      trustEvidence:'Accepted by AdGuard’s DNS hostlist registry with a published complaints and maintenance policy',
      reviewReason:!category?'New registry entry requires purpose and producer review':null,
      format:category?.endsWith('allowlist')?'allowlist':undefined,license:'Original upstream license and embedded attribution apply',provenance:f.homepage,
      minEntries:1,unsupportedReason:f.filterId===59?'DNS rewrite rules require a supported resolver; conversion to plain host blocks would change their behavior':['abused-tlds','dns-rebind'].includes(category)?'Requires TLD, wildcard, exclusion or DNS-response rules; plain domain/IP output cannot preserve its semantics':undefined});
  }
  reports.push({...catalogDefinitions[0],state:'current',discovered:registry.filters.length});
  async function catalog(id,task){
    const def=catalogDefinitions.find(c=>c.id===id),cachePath=join(downloader.cacheDir,`catalog-${id}.json`);
    try{const found=await task();specs.push(...found);await writeJson(cachePath,{acceptedAt:new Date().toISOString(),specs:found});reports.push({...def,state:'current',discovered:found.length});}
    catch(error){const old=await jsonFile(cachePath);const usable=old&&Date.now()-Date.parse(old.acceptedAt)<=86400000;if(usable)specs.push(...old.specs);reports.push({...def,state:usable?'cached':'failed',discovered:usable?old.specs.length:0,reason:error.message});}
  }
  await catalog('firebog',async()=>parseFirebog((await downloader.get('https://firebog.net/')).text));
  await catalog('safing',async()=>parseSafing((await downloader.get('https://raw.githubusercontent.com/safing/intel-data/master/lists/sources.yml')).text));
  async function tree(repo,branch){const r=await downloader.get(`https://api.github.com/repos/${repo}/git/trees/${branch}?recursive=1`,{maxBytes:10*1024*1024});const d=JSON.parse(r.text);if(d.truncated||!Array.isArray(d.tree))throw Error('Incomplete provider tree');return d.tree.filter(x=>x.type==='blob');}
  await catalog('hagezi',async()=>{
    const found=[];
    for(const [repo,branch]of [['hagezi/dns-blocklists','main'],['hagezi/nrd','main']]){
      for(const file of await tree(repo,branch)){
        if(repo.endsWith('/nrd')?!/^domains\/.*\.txt$/.test(file.path):!plainHagezi(file.path)&&file.path!=='adguard/dns-rebind-protection.txt')continue;
        const category=file.path==='adguard/dns-rebind-protection.txt'?'dns-rebind':hageziPurpose(file.path,repo);
        const url=`https://raw.githubusercontent.com/${repo}/${branch}/${file.path}`;
        const base=file.path.split('/').at(-1).replace('-onlydomains','');
        const registryRecord=repo.endsWith('/nrd')?null:registry.filters.find(f=>githubPath(f.subscriptionUrl)?.repo==='hagezi/dns-blocklists'&&githubPath(f.subscriptionUrl)?.path===`adblock/${base.replace(/\.mini(?=\.txt$)/,'')}`);
        const badTags=new Set(registry.tags.filter(t=>['problematic','obsolete'].includes(t.keyword)).map(t=>t.tagId));
        const blocked=registryRecord&&(registryRecord.disabled||registryRecord.deprecated||(registryRecord.tags||[]).some(t=>badTags.has(t)));
        found.push({id:`hagezi-${repo.endsWith('/nrd')?'nrd-':''}${base.replace(/\.txt$/,'').replace(/[^a-z0-9-]/g,'-')}${file.path.startsWith('ips/')?'-ips':''}`,name:`HaGeZi ${base.replace(/\.txt$/,'')}${file.path.startsWith('ips/')?' IPs':''}`,
          provider:'hagezi',category:category||'unmapped',role:isOptionalCategory(category||'')?'optional':'supplement',url,homepage:'https://github.com/'+repo,githubPath:{repo,branch,path:file.path},catalog:'hagezi',catalogEvidence:'https://github.com/hagezi/dns-blocklists/blob/main/CHEATSHEET.md',
          trustEvidence:'Official HaGeZi repository inventory and published category documentation',license:'GPL-3.0; original upstream terms also apply',provenance:'https://github.com/hagezi/dns-blocklists/blob/main/sources.md',minEntries:1,
          format:category?.endsWith('allowlist')?'allowlist':undefined,
          reviewReason:blocked?'AdGuard marks this logical list problematic, disabled or deprecated':!category||category==='nameserver-ips'?'Undocumented purpose or broad infrastructure block requires review':null,
          unsupportedReason:['abused-tlds','dns-rebind'].includes(category)?'Requires TLD, wildcard, exclusion or DNS-response rules; not representable faithfully as plain domains/IPs':undefined,
          logicalKey:repo==='hagezi/dns-blocklists'?`hagezi:${file.path.startsWith('ips/')?'ips:':''}${base}`:undefined,
          maxAgeDays:repo.endsWith('/nrd')?7:undefined});
      }
    }return found;
  });
  await catalog('shadow',async()=>{
    const map={AI:'ai',Ads:'ads',Adult:'adult',Apple:'apple-bloat',Chat:'chat-widgets',Cryptocurrency:'cryptocurrency',DNS:'dns-resolvers',Dating:'dating',Dynamic:'dynamic-dns',Fonts:'fonts',Free:'free-hosting',Gambling:'gambling',Junk:'junk',Malware:'malware-and-support',Marketing:'marketing',Microsoft:'microsoft-bloat',Remote:'remote-access',Risk:'risk',Scam:'fraud',Shock:'violence',Top_Level:'abused-tlds',Tracking:'tracking',Tunnels:'vpn-proxy',Typo:'typosquatting',UrlShortener:'url-shorteners'};
    return (await tree('ShadowWhisperer/BlockLists','master')).filter(f=>/^Lists\/[^/]+$/.test(f.path)&&!f.path.includes('/Wild_')).map(file=>{const name=file.path.split('/')[1],category=map[name],url=`https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/${file.path}`;return {id:`shadow-${name.toLowerCase()}`,name:`ShadowWhisperer ${name}`,provider:'shadowwhisperer',category:category||'unmapped',role:isOptionalCategory(category||'')?'optional':'supplement',url,homepage:'https://github.com/ShadowWhisperer/BlockLists',githubPath:{repo:'ShadowWhisperer/BlockLists',branch:'master',path:file.path},catalog:'shadow',catalogEvidence:'https://github.com/ShadowWhisperer/BlockLists',trustEvidence:'Existing registry-listed producer; official category definitions and public issue process',license:'See upstream repository and source header',minEntries:1,
      reviewReason:!category?'New category requires review':name==='Junk'?'Producer describes this as a personal list and declines breakage reports':null,
      unsupportedReason:category==='abused-tlds'?'Single-label TLD rules cannot be preserved in the requested domain/IP format':null};});
  });
  await catalog('blocklistproject',async()=>{
    const map={abuse:'abuse',ads:'ads',basic:'mixed',crypto:'cryptomining',drugs:'drugs',facebook:'big-tech-meta',fraud:'fraud',gambling:'gambling',malware:'malware',phishing:'phishing',piracy:'piracy',porn:'adult',ransomware:'ransomware',redirect:'redirects',scam:'fraud',smarttv:'smart-tv','smart-tv':'smart-tv',tiktok:'social-tiktok',torrent:'torrent',tracking:'tracking',twitter:'social-twitter',vaping:'vaping',whatsapp:'social-whatsapp',youtube:'social-youtube'};
    const found=(await tree('blocklistproject/Lists','main')).filter(f=>/^alt-version\/[^/]+-nl\.txt$/.test(f.path)).map(file=>{const name=file.path.split('/')[1].replace('-nl.txt',''),category=map[name],url=`https://raw.githubusercontent.com/blocklistproject/Lists/main/${file.path}`;return {id:`blocklistproject-${name}`,name:`Block List Project ${name}`,provider:'blocklistproject',category:category||'unmapped',role:'optional',url,homepage:'https://github.com/blocklistproject/Lists',githubPath:{repo:'blocklistproject/Lists',branch:'main',path:file.path},catalog:'blocklistproject',catalogEvidence:'https://github.com/blocklistproject/Lists#available-lists',trustEvidence:'Established categorized-list project with documented validation, public issue process, and source attribution',license:'Unlicense; retain original upstream notices',minEntries:1,reviewReason:!category?'New provider category requires purpose review':null};});
    if(found.length<10)throw Error('Provider list inventory changed; review required');return found;
  });
  return {specs,reports};
}

export function logicalSourceKey(source,registry){
  if(source.logicalKey)return source.logicalKey;
  const f=source.registryId?registry.filters.find(f=>f.filterId===source.registryId):null;
  const url=f?.subscriptionUrl||source.url;
  if(source.registryId===27||url==='https://big.oisd.nl/'||url==='https://dblw.oisd.nl/')return 'oisd-big';
  if(url==='https://nsfw-small.oisd.nl/'||url==='https://nsfw-small.oisd.nl/domainswild')return 'oisd-nsfw-small';
  if(url?.startsWith('https://pgl.yoyo.org/adservers/'))return 'peter-lowe-adservers';
  if(source.registryId===1||url==='https://v.firebog.net/hosts/AdguardDNS.txt')return 'adguard-dns';
  const p=githubPath(url);
  if(p?.repo==='hagezi/dns-blocklists')return `hagezi:${p.path.startsWith('ips/')?'ips:':''}${p.path.split('/').at(-1).replace('-onlydomains','')}`;
  return p?`${p.repo.toLowerCase()}:${p.path}`:url;
}
