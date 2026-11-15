import {mkdir,readFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {atomicWrite,writeJson} from './io.mjs';
import {applyTaxonomy} from './category-taxonomy.mjs';

export const documentationFiles=Object.freeze({overview:'index.md',feeds:'feeds.md',sources:'sources.md',full:'full.md',aiIndex:'llms.txt',aiFull:'llms-full.txt'});
const text=value=>String(value??'—').replace(/[\r\n]+/g,' ').replace(/[\\`*_[\]<>|]/g,'\\$&');
function link(label,target){
  if(!target)return '—';
  try{const url=new URL(target,'https://relative.invalid/');if(!['https:','http:'].includes(url.protocol)||url.username||url.password)return '—';if([...url.searchParams.keys()].some(k=>/^(?:auth|api[_-]?key|token|secret|password)$/i.test(k)))return '—';}
  catch{return '—';}
  return `[${text(label)}](<${String(target).replaceAll('>','%3E').replaceAll('<','%3C').replace(/[\r\n]/g,'')}>)`;
}
function title(name,snapshot){
  if(snapshot?.categories[name]?.label)return snapshot.categories[name].label;
  const names={mixed:'Mixed ads / trackers / malware','security-threats':'Security threats','newly-registered-domains':'Newly registered domains',dga:'DGA / high-entropy new domains','attacking-ips':'Attacking / suspicious IPs','malware-and-support':'Malware / remote-support policy','cname-tracking':'CNAME-cloaked trackers','cname-ads':'CNAME-cloaked ads','dns-resolvers':'DNS resolvers','encrypted-dns':'Encrypted DNS / DoH',bypass:'DNS / VPN / Tor / proxy bypass'};
  return names[name]||name.replaceAll('-',' ').replace(/^./,c=>c.toUpperCase());
}
function downloads(name,feed){
  const items=[];
  if(feed.domains&&feed.ips)items.push(link('Domains + IPs',`${name}.txt`),link('Domains',name==='all'?'domains.txt':`${name}.domains.txt`),link('IPs',name==='all'?'ips.txt':`${name}.ips.txt`));
  else if(feed.domains)items.push(link('Domains',`${name}.txt`));else if(feed.ips)items.push(link('IPs',`${name}.txt`));
  return items.join(' · ')||'—';
}
const heading=(name,snapshot)=>[`# ${name}`,'',`Snapshot (UTC): ${text(snapshot.publishedAt)}`,''];

export function renderPublicDocumentation(input){
  const snapshot=applyTaxonomy(input);
  const accepted=new Map(snapshot.sources.map(s=>[s.id,s]));
  const seen=new Set();
  const sources=snapshot.sourceReports.filter(s=>s.selected!==false&&['current','cached'].includes(s.state)&&accepted.has(s.id)&&!seen.has(s.id)&&seen.add(s.id));
  const groups=[['protection','Default protection'],['optional','Additional filtering']];
  const overview=[...heading('packettale dns-blocklist',snapshot),'> Categorized, deduplicated domain and IP filtering feeds. Protection and optional service/content policies are separate.','',
    '| Metric | Count |','| --- | ---: |',`| Domains, all categories | ${snapshot.totals.domains} |`,`| IPs, all categories | ${snapshot.totals.ips} |`,`| Included upstream feeds | ${sources.length} |`,`| Populated categories | ${Object.values(snapshot.categories).filter(c=>c.total).length} |`,'',
    '## Bundles','','| Bundle | Categories | Domains | IPs | TXT feeds |','| --- | ---: | ---: | ---: | --- |'];
  for(const [key,name]of groups){const bundle=snapshot.bundles[key],feed=snapshot.feeds[key];overview.push(`| ${name} | ${bundle.categories.length} | ${feed.domains} | ${feed.ips} | ${downloads(key,feed)} |`);}
  overview.push('','Each bundle is the union of exactly the categories listed under its heading in the feed catalog. Optional categories are not automatically added to the protection bundle.','',
    '## Public data','',`- ${link('Category catalog and bundle membership','feeds.md')}`,`- ${link('Included sources, source dates and licenses','sources.md')}`,`- ${link('Snapshot statistics and checksums','stats.json')}`,`- ${link('Source metadata','sources.json')}`,`- ${link('Attribution and original data terms','NOTICE.md')}`,`- ${link('Complete Markdown reference','full.md')}`,'',
    '## Feed format','','Feed TXT downloads contain one normalized domain or IP address per line, sorted and deduplicated. They contain no hosts-file address prefixes, comments, URL paths, wildcards or CIDR ranges. Domain-only and IP-only files are separate where both types occur. Documentation files named llms.txt and llms-full.txt contain Markdown and are not filtering feeds.','',
    '## Counts and updates','','Global totals count distinct entries. Categories, bundles and upstream feeds can overlap, so their counts must not be summed to obtain a global total. Shared entries are exact normalized matches, not independent detection votes.','',
    `Configured source-check interval: ${snapshot.policy.updateIntervalMinutes} minutes. Provider-specific minimum fetch intervals, build time and device polling also affect delivery. The snapshot timestamp above identifies these data; it is not a guarantee of instantaneous upstream synchronization. Consumers refresh a complete snapshot at the same feed URL. Source dates describe upstream file revisions, not a per-entry verification date.`,'');

  const feedDoc=[...heading('packettale dns-blocklist feed catalog',snapshot)];
  for(const section of snapshot.taxonomy){
    const members=Object.keys(snapshot.categories).filter(id=>snapshot.categories[id].total&&snapshot.categories[id].section===section.id);if(!members.length)continue;
    feedDoc.push(`## ${section.label}`,'','| Category | ID | Domains | IPs | TXT feeds |','| --- | --- | ---: | ---: | --- |');
    const group=snapshot.groups?.[section.id];if(group)feedDoc.push(`| Combined ${text(section.label)} | ${text(group.feed)} | ${group.domains} | ${group.ips} | ${downloads(group.feed,snapshot.feeds[group.feed])} |`);
    for(const id of members){const c=snapshot.categories[id];feedDoc.push(`| ${text(title(id,snapshot))} | ${text(id)} | ${c.domains} | ${c.ips} | ${downloads(id,snapshot.feeds[id])} |`);}feedDoc.push('');
  }
  feedDoc.push('## Additional data files','','| Dataset | Domains | IPs | TXT feeds |','| --- | ---: | ---: | --- |',`| All protection and optional categories | ${snapshot.feeds.all.domains} | ${snapshot.feeds.all.ips} | ${downloads('all',snapshot.feeds.all)} |`,'',
    'The all-category files include optional service and content blocks. The combined.txt, combined.domains.txt and combined.ips.txt files are aliases of the corresponding protection files.','',
    'Mixed upstream data remains mixed. A tracking classification requiring browser third-party context is not widened into a whole-service DNS block when that host is also explicitly classified as a social service. Whole-service social blocks remain optional.','',`- ${link('Snapshot metadata, file sizes and SHA-256 checksums','stats.json')}`,`- ${link('Included upstream sources','sources.md')}`,'');

  const sourceDoc=[...heading('packettale dns-blocklist included sources',snapshot),`Included feeds: ${sources.length}`,'','| Source | Category | Domains | IPs | Source updated | State | Normalized TXT | Original | Terms |','| --- | --- | ---: | ---: | --- | --- | --- | --- | --- |'];
  for(const s of sources){const counts=accepted.get(s.id);sourceDoc.push(`| ${link(s.name,s.homepage)} | ${text(s.category==='categorized'?'Multiple categories':title(s.category,snapshot))} | ${counts.domains} | ${counts.ips} | ${text(s.updatedAt)} | ${text(s.state)} | ${link('TXT',s.normalizedFeed)} | ${link('Upstream',s.upstreamUrl)} | ${text(s.license)} |`);}
  sourceDoc.push('',`- ${link('Public source metadata','sources.json')}`,`- ${link('Attribution and original notices','NOTICE.md')}`,'');
  const index=['# packettale dns-blocklist','', '> Plain domain and IP blocklists with separate protection and optional service/content bundles.', '',
    `Snapshot (UTC): ${snapshot.publishedAt}. Included feeds: ${sources.length}. Domains: ${snapshot.totals.domains}. IPs: ${snapshot.totals.ips}.`,'',
    '## Documentation','',`- ${link('Overview','index.md')}: totals, bundle definitions, formats and update metadata.`,`- ${link('Feed catalog','feeds.md')}: every populated category, exact bundle membership and TXT download links.`,`- ${link('Included sources','sources.md')}: upstream names, counts, revision dates and data licenses.`,`- ${link('Complete reference','full.md')}: overview, feed catalog and source catalog in one Markdown file.`,'',
    '## Structured data','',`- ${link('Statistics','stats.json')}: counts, overlaps, category groups, bundle membership, feed paths and SHA-256 checksums.`,`- ${link('Sources','sources.json')}: included-source metadata.`,`- ${link('Data terms','NOTICE.md')}: original attribution and notices.`,''];
  const full=[overview.join('\n'),'---','',feedDoc.join('\n'),'---','',sourceDoc.join('\n')].join('\n');
  return {'index.md':overview.join('\n'),'feeds.md':feedDoc.join('\n'),'sources.md':sourceDoc.join('\n'),'full.md':full,'llms.txt':index.join('\n'),'llms-full.txt':full};
}

export async function writePublicDocumentation(directory,snapshot){
  await mkdir(directory,{recursive:true});
  for(const [name,content]of Object.entries(renderPublicDocumentation(snapshot)))await atomicWrite(join(directory,name),content);
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const directory=resolve(process.argv[2]||'dist'),snapshot=applyTaxonomy(JSON.parse(await readFile(join(directory,'stats.json'),'utf8')));
  snapshot.documentation=documentationFiles;await writePublicDocumentation(directory,snapshot);await writeJson(join(directory,'stats.json'),snapshot);
  console.log('Generated public Markdown reference and AI indexes from the existing snapshot.');
}
