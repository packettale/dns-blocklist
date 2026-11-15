import { readFile, mkdir, copyFile, readdir, rm } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Downloader, atomicWrite, writeJson, jsonFile, parallelMap, sha256 } from './io.mjs';
import { parseText, parseLine, normalize, parseDisconnect, publicSuffixes } from './parser.mjs';
import { candidates, supplements, categories, registryUrl, registryHomepage, settings } from './sources.mjs';
import { readUrlhausKey, getUrlhausExport } from './urlhaus-client.mjs';
import { discoverCatalogs, logicalSourceKey } from './catalogs.mjs';
import { consolidate } from './consolidate.mjs';
import { pruneFeeds, hostingReport } from './verify-output.mjs';
import {publicManifest} from './public-data.mjs';
import {categoryGroup} from './category-policy.mjs';
import {documentationFiles,writePublicDocumentation} from './public-docs.mjs';
import {writeCategoryGroupFeeds} from './category-group-feeds.mjs';
import {ensureBuildSpace} from './disk-space.mjs';
import {parseTorSummary} from './tor-source.mjs';
import {normalizedDigest,buildFingerprint} from './build-inputs.mjs';
import {createGitHubEligibility} from './github-source.mjs';

const project=resolve(fileURLToPath(new URL('..',import.meta.url)));
export const ageDays=(date,now=Date.now())=>(now-new Date(date).getTime())/86400000;
export function registryEligibility(source,registry,now=Date.now()){
  const f=registry.filters.find(f=>f.filterId===source.registryId);
  if(!f)return {eligible:false,reason:'Missing from active registry'};
  const bad=new Set(registry.tags.filter(t=>['problematic','obsolete'].includes(t.keyword)).map(t=>t.tagId));
  if(f.disabled||f.deprecated||(f.tags||[]).some(t=>bad.has(t)))return {eligible:false,reason:'Disabled, deprecated, or problematic in registry'};
  const days=ageDays(f.timeUpdated,now);
  if(!Number.isFinite(days)||days < -1||days>(source.maxAgeDays||settings.maxAgeDays))return {eligible:false,reason:`Stale or unverified update timestamp: ${f.timeUpdated||'missing'}`};
  return {eligible:true,...source,name:f.name,url:f.downloadUrl,upstreamUrl:f.subscriptionUrl,homepage:f.homepage,updatedAt:f.timeUpdated,version:f.version,activeEvidence:registryHomepage,statusPolicy:'Active registry entry, not marked problematic, with a recent feed revision'};
}

export async function run({root=project,outputDir,baselineDir,fetchImpl=fetch,env=process.env,discovery=true}={}){
  const dist=outputDir||join(root,'dist'),cache=join(root,'.cache'),reportDir=join(root,'reports');
  await Promise.all([mkdir(dist,{recursive:true}),mkdir(cache,{recursive:true}),mkdir(reportDir,{recursive:true})]);
  const downloader=new Downloader(join(cache,'http'),settings,fetchImpl);
  const parserRevisions={text:sha256(parseText.toString()+parseLine.toString()+normalize.toString()),disconnect:sha256(parseDisconnect.toString()+normalize.toString()),'tor-summary':sha256(parseTorSummary.toString()+normalize.toString())};
  const legacyTextRevision='1cd9f1dbeb808a843c15d1b8f9d7d2e91db5b032326a8991442e2fc8da163a60';
  const registry=JSON.parse((await downloader.get(registryUrl)).text);
  if(!Array.isArray(registry.filters)||!Array.isArray(registry.tags)||registry.filters.length<10)throw Error('Registry is invalid; no feeds published');
  const suffixResponse=await downloader.get('https://publicsuffix.org/list/public_suffix_list.dat');
  const isPublicSuffix=publicSuffixes(suffixResponse.text);
  const now=Date.now(),checkedAt=new Date(now).toISOString(),audits=[],prefetched=new Map();
  const urlhausKey=await readUrlhausKey(env);
  const officialUrlhaus=urlhausKey?[{id:'urlhaus-official',name:'URLhaus official DNS hostfile',provider:'urlhaus',category:'malware',role:'supplement',authExport:'hostfile.txt',maxAgeDays:2,homepage:'https://urlhaus.abuse.ch/',url:'https://urlhaus.abuse.ch/api/',license:'abuse.ch fair-use terms; original data terms apply',provenance:'https://urlhaus.abuse.ch/api/',trustEvidence:'Authenticated DNS-specific export from the official provider',minEntries:1}]:[];
  const discovered=discovery?await discoverCatalogs({downloader,registry,existing:[...candidates,...supplements]}):{specs:[],reports:[]};
  const specifications=[],seen=new Map();
  for(const original of [...candidates,...supplements,...officialUrlhaus,...discovered.specs]){
    const spec={...original};
    spec.trustEvidence ||= spec.registryId?'Established producer accepted by AdGuard’s DNS hostlist registry':'Previously reviewed official producer endpoint; see source review and provenance';
    if(spec.id.startsWith('cglabs-'))spec.reviewReason='Upstream provenance and redistribution terms are not established; producer review required';
    if(spec.registryId===63)spec.additionalCategories=['trackers-microsoft'];
    const key=logicalSourceKey(spec,registry);
    if(key&&seen.has(key)){
      const target=seen.get(key);target.catalogs=[...new Set([...(target.catalogs||[]),spec.catalog].filter(Boolean))];
      if(spec.reviewReason?.includes('problematic')||spec.reviewReason?.includes('marks this feed as not recommended'))target.reviewReason=spec.reviewReason;
      audits.push({...spec,id:`alias-${spec.catalog||'manual'}-${spec.id}`,eligible:false,duplicateOf:target.id,reason:`Same logical feed as ${target.id}; counted once`});
    }else{spec.catalogs=[spec.catalog].filter(Boolean);specifications.push(spec);if(key)seen.set(key,spec);}
  }
  const repositoryChecks=new Map();
  function checkRepository(repo){if(!repositoryChecks.has(repo))repositoryChecks.set(repo,downloader.get(`https://api.github.com/repos/${repo}`,{maxBytes:1000000}).then(r=>JSON.parse(r.text)));return repositoryChecks.get(repo);}
  const githubEligibility=createGitHubEligibility({downloader,checkRepository,now,maxAgeDays:settings.maxAgeDays});
  const checked=await parallelMap(specifications,4,async spec=>{
    try{
      if(spec.reviewReason)throw Error(spec.reviewReason);
      if(spec.unsupportedReason)throw Error(spec.unsupportedReason);
      if(spec.format==='allowlist')throw Error('Allowlist, not a blocklist; use its original provider URL for exceptions, never as blocks');
      if(spec.authExport){
        const result=await getUrlhausExport({key:urlhausKey,exportName:spec.authExport,cacheDir:join(cache,'urlhaus-auth'),fetchImpl,timeoutMs:settings.timeoutMs,maxBytes:settings.maxBytes});prefetched.set(spec.id,result);
        const days=ageDays(result.lastModified,now);if(!result.lastModified||!Number.isFinite(days)||days < -1||days>spec.maxAgeDays)throw Error('Official URLhaus export lacks recent timestamp evidence');
        return {...spec,eligible:true,updatedAt:result.lastModified,version:result.sha256,activeEvidence:spec.provenance,statusPolicy:'Authenticated official DNS export with recent Last-Modified evidence'};
      }
      if(spec.registryId)return {...spec,...registryEligibility(spec,registry,now)};
      if(spec.githubPath){
        return await githubEligibility(spec);
      }
      const result=await downloader.get(spec.url,{minIntervalMs:(spec.minFetchMinutes||0)*60000});prefetched.set(spec.id,result);
      if(spec.format==='tor-summary'){const parsed=parseTorSummary(result.text),days=ageDays(parsed.publishedAt,now);if(days<0||days>spec.maxAgeDays)throw Error('Official Tor consensus is stale or in the future');return {...spec,eligible:true,updatedAt:parsed.publishedAt,version:result.sha256,activeEvidence:spec.homepage,statusPolicy:'Official Tor Project response with a recent relay consensus timestamp; only running public relay IPs'};}
      const days=ageDays(result.lastModified,now);if(!result.lastModified||!Number.isFinite(days)||days < -1||days>(spec.maxAgeDays||settings.maxAgeDays))throw Error(`No recent Last-Modified evidence: ${result.lastModified||'missing'}`);
      return {...spec,eligible:true,updatedAt:result.lastModified,version:result.sha256,activeEvidence:spec.url,statusPolicy:'Official response with recent Last-Modified evidence; entry accuracy is not independently established'};
    }catch(error){return {...spec,eligible:false,reason:error.message};}
  });
  audits.push(...checked);
  // There is no ranking cap: every eligible, reviewed source is requested.
  const primary=checked.filter(s=>s.eligible&&s.rank).sort((a,b)=>a.rank-b.rank).map(s=>({...s,role:'primary'}));
  const requested=[...primary,...checked.filter(s=>s.eligible&&!s.rank)];
  console.log(`Catalog review: ${audits.length} records; ${requested.length} eligible feeds; no top-N cap.`);
  const outcomes=await parallelMap(requested,settings.concurrency,async source=>{
    const acceptedPath=join(cache,'accepted',`${source.id}.json`),metaPath=join(cache,'accepted',`${source.id}.meta.json`);
    let old=await jsonFile(metaPath);
    if(!old){const previous=await jsonFile(acceptedPath);if(previous){const {parsed,...meta}=previous;old={...meta,acceptedEntries:parsed.block.length,ignoredLines:parsed.rejected||0,licenseText:parsed.licenseText||null};}}
    const parserRevision=parserRevisions[source.format]||parserRevisions.text;
    const sameParser=(old?.parserRevision||(source.format?null:legacyTextRevision))===parserRevision;
    if(old&&sameParser&&!old.normalizedHash){const previous=await jsonFile(acceptedPath);if(previous?.parsed){old={...old,normalizedHash:normalizedDigest(previous.parsed),normalizedCategories:Object.keys(previous.parsed.categories||{}).sort()};await writeJson(metaPath,old);}}
    try{
      // Exact GitHub file revisions are content-addressed. When unchanged,
      // re-use the accepted data after the live activity check above.
      if(source.githubPath&&old?.version===source.version&&sameParser){const value={...old,parserRevision,acceptedAt:checkedAt};await writeJson(metaPath,value);return {source,acceptedPath,...value,state:'current'};}
      const revisionUrl=source.githubPath&&new URL(source.url).hostname==='raw.githubusercontent.com'?`https://raw.githubusercontent.com/${source.githubPath.repo}/${source.version}/${source.githubPath.path.split('/').map(encodeURIComponent).join('/')}`:source.url;
      const response=prefetched.get(source.id)||await downloader.get(source.url,{force:!!old&&old.version!==source.version,requestUrl:revisionUrl});
      if(/text\/html/i.test(response.contentType||''))throw Error('HTML response instead of a feed');
      if(source.registryId){const version=response.text.match(/^!\s*Version:\s*(\S+)/im)?.[1];if(version&&version!==source.version)throw Error('Body version differs from active registry revision; retry next run');}
      let value;
      if(old?.responseHash===response.sha256&&sameParser)value={...old,parserRevision,version:source.version,updatedAt:source.updatedAt,acceptedAt:checkedAt};
      else{
        const parsed=source.format==='disconnect'?parseDisconnect(response.text):source.format==='tor-summary'?parseTorSummary(response.text):parseText(response.text);
        if(parsed.block.length<(source.minEntries||1))throw Error(`Only ${parsed.block.length} valid entries; feed rejected`);
        if(old&&parsed.block.length<old.acceptedEntries*(1-settings.maxDropFraction))throw Error('More than half the entries disappeared; new snapshot quarantined');
        value={version:source.version,parserRevision,updatedAt:source.updatedAt,acceptedAt:checkedAt,responseHash:response.sha256,normalizedHash:normalizedDigest(parsed),normalizedCategories:Object.keys(parsed.categories||{}).sort(),acceptedEntries:parsed.block.length,ignoredLines:parsed.rejected||0,licenseText:parsed.licenseText||null,headers:response.text.split(/\r?\n/).filter(l=>/^[#!]/.test(l)).slice(0,100)};
        await writeJson(acceptedPath,{parsed,...value});
      }
      await writeJson(metaPath,value);console.log(`Accepted ${source.id}: ${value.acceptedEntries.toLocaleString()} entries`);
      return {source,acceptedPath,...value,state:'current'};
    }catch(error){
      if(old&&sameParser&&ageDays(old.acceptedAt,now)<=settings.maxCachedHours/24&&ageDays(old.updatedAt,now)<=(source.maxAgeDays||settings.maxAgeDays))return {source,acceptedPath,...old,state:'cached',error:error.message};
      return {source,state:'excluded',error:error.message};
    }
  });
  const loaded=outcomes.filter(x=>x.acceptedPath),healthyPrimary=loaded.filter(x=>x.source.role==='primary'&&x.state==='current');
  if(healthyPrimary.length<settings.minPrimarySources){await writeJson(join(reportDir,'failed-check.json'),{checkedAt,catalogs:discovered.reports,audits,sources:outcomes});throw Error(`Only ${healthyPrimary.length} current primary sources; keeping published feeds unchanged`);}
  const localAllowText=await readFile(join(root,'allowlist.txt'),'utf8'),localAllows=localAllowText.split(/\r?\n/).map(x=>x.split('#',1)[0].trim()).filter(Boolean);
  const inputFingerprint=buildFingerprint({loaded,localAllows,suffixText:suffixResponse.text});
  let baseline=baselineDir;
  if(!baseline){const pointer=await jsonFile(join(cache,'snapshots','active.json'));if(pointer){if(!['a','b'].includes(pointer.slot))throw Error('Invalid published snapshot pointer');baseline=join(cache,'snapshots',pointer.slot);}else baseline=dist;}
  const previousManifest=await jsonFile(join(baseline,'stats.json'));
  const seeded=await jsonFile(join(cache,'published-inputs.json'));
  const previousFingerprint=previousManifest?.dataFingerprint||(seeded?.publicationFingerprint===previousManifest?.inputFingerprint?seeded?.dataFingerprint:null);
  if(previousFingerprint===inputFingerprint){
    const {access}=await import('node:fs/promises');
    const present=await Promise.allSettled(Object.keys(previousManifest.feeds).map(f=>access(join(baseline,`${f}.txt`))));
    if(present.every(r=>r.status==='fulfilled')){
      const privateCheck=await jsonFile(join(reportDir,'latest-check.json'),{});
      await writeJson(join(reportDir,'latest-check.json'),{...privateCheck,checkedAt,changed:false,totals:previousManifest.totals});
      await writeJson(join(cache,'public-check.json'),{checkedAt,publishedAt:previousManifest.publishedAt,changed:false,totals:previousManifest.totals,acceptedSources:previousManifest.sources.length});
      console.log(`Checked ${checkedAt}; normalized upstream data unchanged. Full rebuild skipped; published feeds and timestamp preserved.`);
      return {...previousManifest,_unchanged:true};
    }
  }
  await ensureBuildSpace(cache,previousManifest);
  const categoryNames=[...new Set([...categories,...audits.flatMap(a=>[a.category,...(a.additionalCategories||[])])].filter(n=>n&&!['categorized','unmapped'].includes(n)&&!n.endsWith('allowlist')))];
  const {stats,feeds,sourceCounts}=await consolidate({loaded,categoryNames,dist,cache,isPublicSuffix,localAllows,includeEveryday:(_source,category)=>categoryGroup(category)==='protection'});
  const groupFeeds=await writeCategoryGroupFeeds({directory:dist,categories:stats.categories,feeds});
  stats.groups=Object.fromEntries(Object.entries(groupFeeds).map(([id,group])=>[id,{...stats.groups[id],...group}]));
  await pruneFeeds(dist,feeds);
  const sourceReports=audits.map(a=>{
    const item=a.duplicateOf?undefined:outcomes.find(o=>o.source.id===a.id),index=loaded.indexOf(item);
    return {id:a.id,name:a.name||a.id,provider:a.provider||null,role:a.rank?'primary':a.role,eligible:a.eligible,selected:!!item?.acceptedPath,
      category:a.category||'categorized',additionalCategories:a.additionalCategories||[],state:a.duplicateOf?'duplicate':item?.state||(a.eligible?'not-selected':'excluded'),duplicateOf:a.duplicateOf||null,
      reason:item?.error||a.reason||null,updatedAt:item?.updatedAt||a.updatedAt||null,version:item?.version||a.version||null,url:a.url||null,upstreamUrl:a.upstreamUrl||a.url||null,homepage:a.homepage||null,license:a.license,provenance:a.provenance||a.homepage,
      catalogs:a.catalogs||[a.catalog].filter(Boolean),catalogEvidence:a.catalogEvidence||null,trustEvidence:a.trustEvidence||null,statusPolicy:a.statusPolicy||null,note:a.note||null,
      validation:a.validation||'Upstream classification; no independent per-entry accuracy claim',independence:a.independence||'May reuse other feeds; matching entries do not prove independent confirmation',
      acceptedEntries:item?.acceptedEntries||0,effectiveEntries:index>=0?sourceCounts[index]:0,ignoredLines:item?.ignoredLines||0,originalHeaders:item?.headers||[],licenseText:item?.licenseText||null,
      normalizedFeed:item?.acceptedPath?`upstreams/${a.id}.txt`:null};
  });
  const coverage={catalogs:discovered.reports,discoveredRecords:sourceReports.length,distinctFeeds:sourceReports.filter(s=>!s.duplicateOf).length,included:loaded.length,excluded:sourceReports.filter(s=>s.state==='excluded').length,duplicates:sourceReports.filter(s=>s.duplicateOf).length,
    scope:'Reviewed public catalogs and official producer inventories; not a claim of exhaustive internet coverage'};
  const snapshot=publicManifest({schemaVersion:2,inputFingerprint,dataFingerprint:inputFingerprint,policy:{maxAgeDays:settings.maxAgeDays,updateIntervalMinutes:settings.updateIntervalMinutes,selectedPrimary:primary.length},coverage,
    totals:{total:stats.total,domains:stats.domains,ips:stats.ips,uniqueDomains:stats.uniqueDomains,uniqueIPs:stats.uniqueIPs,sharedDomains:stats.sharedDomains,sharedIPs:stats.sharedIPs},categories:stats.categories,groups:stats.groups,bundles:stats.bundles,sources:stats.sources,matrix:stats.matrix,histogram:stats.histogram,feeds,documentation:documentationFiles,sourceReports});
  const oldManifest=await jsonFile(join(dist,'stats.json')),oldSnapshot=oldManifest?Object.fromEntries(Object.entries(oldManifest).filter(([k])=>k!=='publishedAt')):null;
  const changed=JSON.stringify(oldSnapshot)!==JSON.stringify(snapshot),manifest={...snapshot,publishedAt:changed?new Date().toISOString():oldManifest.publishedAt};
  await writeJson(join(dist,'stats.json'),manifest);await writeJson(join(dist,'sources.json'),snapshot.sourceReports);await rm(join(dist,'coverage.json'),{force:true});
  const notice=['# Upstream attribution and data terms','','Normalized domain/IP subsets preserve upstream data terms. Code licensing does not relicense upstream data.','','Plain feeds omit comments; source headers and attribution are retained below.',''];
  for(const s of sourceReports.filter(s=>s.selected)){notice.push(`## ${s.name}`,'',`- Original: ${s.upstreamUrl}`,`- Project: ${s.homepage}`,`- Terms: ${s.license}`,`- Provenance: ${s.provenance}`,'');if(s.licenseText)notice.push(s.licenseText,'');if(s.originalHeaders.length)notice.push('```text',...s.originalHeaders,'```','');}
  await atomicWrite(join(dist,'NOTICE.md'),notice.join('\n'));
  await writePublicDocumentation(dist,manifest);
  for(const file of await readdir(join(root,'web')))await copyFile(join(root,'web',file),join(dist,file));await atomicWrite(join(dist,'.nojekyll'),'');
  await writeJson(join(reportDir,'hosting-capacity.json'),await hostingReport(dist));
  // Incremental scan avoids loading very large public feeds into memory.
  if(urlhausKey){const {scanPublicSecret}=await import('./verify-output.mjs');await scanPublicSecret(dist,urlhausKey);}
  await writeJson(join(reportDir,'latest-check.json'),{checkedAt,changed,coverage,totals:manifest.totals,sourceReports});
  await writeJson(join(cache,'public-check.json'),{checkedAt,publishedAt:manifest.publishedAt,changed,totals:manifest.totals,acceptedSources:manifest.sources.length});
  console.log(`Checked ${checkedAt}\n${stats.domains.toLocaleString()} domains; ${stats.ips.toLocaleString()} IPs\n${healthyPrimary.length}/${primary.length} current primary feeds; ${loaded.length} total accepted feeds\n${changed?'Publication changed':'No publication changes'}`);
  if(process.env.GITHUB_STEP_SUMMARY)await atomicWrite(process.env.GITHUB_STEP_SUMMARY,`## Feed update\n\n${loaded.length} feeds.\n\n${stats.domains.toLocaleString()} domains; ${stats.ips.toLocaleString()} IPs.\n`);
  return manifest;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))run().catch(error=>{console.error(error.message);process.exitCode=1;});
