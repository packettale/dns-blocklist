export const taxonomySections=Object.freeze([
  {id:'ads-tracking',label:'Ads & tracking'},
  {id:'threats',label:'Malware & threats'},
  {id:'device-trackers',label:'Device & app trackers'},
  {id:'regional',label:'Regional filters'},
  {id:'nsfw',label:'NSFW'},
  {id:'site-restrictions',label:'Site restrictions'},
  {id:'tor',label:'Tor'},
  {id:'services',label:'Internet services'},
  {id:'risk',label:'Domain & IP risk filters'},
  {id:'network-controls',label:'Network controls'},
  {id:'advanced',label:'Advanced blocking policies'},
  {id:'other',label:'Other filtering lists'},
]);
const rules={
  ads:['Ads','ads-tracking','tracking'],analytics:['Analytics','ads-tracking','tracking'],tracking:['Tracking','ads-tracking','tracking'],telemetry:['Telemetry','ads-tracking','tracking'],
  'popup-ads':['Pop-up ads','ads-tracking','tracking'],'cname-tracking':['CNAME-cloaked trackers','ads-tracking','tracking'],'cname-ads':['CNAME-cloaked ads','ads-tracking','tracking'],fingerprinting:['Fingerprinting','ads-tracking','tracking'],'email-tracking':['Email tracking','ads-tracking','tracking'],'session-replay':['Session replay','ads-tracking','tracking'],
  malware:['Malware','threats','threat'],phishing:['Phishing','threats','threat'],fraud:['Fraud & scams','threats','threat'],cryptomining:['Cryptojacking','threats','threat'],stalkerware:['Stalkerware','threats','threat'],'security-threats':['Threat intelligence','threats','threat'],'compromised-ips':['Compromised IPs','threats','threat'],'botnet-c2':['Botnet command & control','threats','threat'],ransomware:['Ransomware','threats','threat'],mixed:['Mixed ads, trackers & threats','threats','mixed'],suspicious:['Suspicious domains & spam','risk','risk'],
  'game-console-ads':['Game console ads','device-trackers','tracking'],'smart-tv':['Smart TV ads & tracking','device-trackers','tracking'],
  adult:['Pornography','nsfw','content'],violence:['Gore & violence','nsfw','content'],
  gambling:['Gambling','site-restrictions','content'],piracy:['Piracy','site-restrictions','content'],'no-safesearch':['Search without SafeSearch','site-restrictions','policy'],torrent:['Torrent sites','site-restrictions','content'],drugs:['Drugs','site-restrictions','content'],vaping:['Vaping','site-restrictions','content'],
  tor:['Tor nodes','tor','network-list'],
  social:['Social networks','services','service'],dating:['Dating services','services','service'],ai:['AI services','services','service'],cryptocurrency:['Cryptocurrency services','services','service'],fonts:['Web fonts','services','service'],'chat-widgets':['Chat widgets','services','service'],marketing:['Marketing services','services','service'],'remote-access':['Remote access','services','service'],'push-notifications':['Push notifications','services','service'],'url-shorteners':['URL shorteners','services','service'],'referral-tracking':['Referral & affiliate links','services','service'],'apple-bloat':['Apple apps & services','services','service'],'microsoft-bloat':['Microsoft apps & services','services','service'],'dns-resolvers':['DNS resolvers','services','service'],'encrypted-dns':['Encrypted DNS / DoH','services','service'],'vpn-proxy':['VPN & proxy services','services','service'],'dynamic-dns':['Dynamic DNS services','services','service'],'free-hosting':['Free hosting services','services','service'],p2p:['P2P infrastructure','services','service'],'certificate-crl':['Certificate revocation endpoints','services','service'],'certificate-ocsp':['Certificate status endpoints','services','service'],
  'newly-registered-domains':['Newly registered domains','risk','risk'],dga:['DGA / high-entropy new domains','risk','risk'],'attacking-ips':['IP reputation','risk','risk'],'threat-intelligence':['Additional IP/domain intelligence','risk','risk'],risk:['Monitoring & risk policies','risk','risk'],typosquatting:['Typosquatting','risk','risk'],'badware-hosting':['High-risk hosting policies','risk','policy'],abuse:['Abuse reputation','risk','risk'],
  bypass:['DNS / VPN / Tor / proxy bypass','network-controls','policy'],'dns-rebind':['DNS rebinding protection','network-controls','policy'],
  'malware-and-support':['Mixed security policies','advanced','policy'],'abused-tlds':['Abused TLD policies','advanced','policy'],'nameserver-ips':['Nameserver IP policies','advanced','policy'],junk:['Software blocking policies','advanced','policy'],redirects:['Redirect policies','advanced','policy'],
};
const vendors={amazon:'Amazon',apple:'Apple',huawei:'Huawei',lg:'LG webOS','oppo-realme':'OPPO / Realme',roku:'Roku',samsung:'Samsung',tiktok:'TikTok',vivo:'Vivo',microsoft:'Microsoft',xiaomi:'Xiaomi'};
const regions={no:'Nordic',pl:'Polish',ko:'Korean',vn:'Vietnamese',sv:'Swedish',ir:'Persian',mk:'Macedonian',zh:'Chinese',id:'Indonesian',tr:'Turkish',hu:'Hungarian',lt:'Lithuanian',he:'Hebrew',ua:'Ukrainian'};
const companies={amazon:'Amazon',apple:'Apple',google:'Google',meta:'Meta / Facebook',microsoft:'Microsoft'};
export function categoryInfo(id){
  let entry=rules[id];
  if(!entry&&id.startsWith('trackers-')&&vendors[id.slice(9)])entry=[vendors[id.slice(9)]+' trackers','device-trackers','tracking'];
  if(!entry&&id.startsWith('regional-')&&regions[id.slice(9)])entry=[regions[id.slice(9)]+' ads & tracking','regional','tracking'];
  if(!entry&&id.startsWith('big-tech-')&&companies[id.slice(9)])entry=[companies[id.slice(9)]+' services','services','service'];
  if(!entry&&id.startsWith('social-'))entry=[({tiktok:'TikTok',whatsapp:'WhatsApp',youtube:'YouTube',twitter:'Twitter / X'})[id.slice(7)]||id.slice(7),'services','service'];
  const [label,section,kind]=entry||[id.replaceAll('-',' '),'other','unclassified'];
  return {label,section,kind};
}
export function applyTaxonomy(snapshot){
  return {...snapshot,taxonomy:taxonomySections,categories:Object.fromEntries(Object.entries(snapshot.categories||{}).map(([id,c])=>[id,{...c,...categoryInfo(id)}]))};
}
