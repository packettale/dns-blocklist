import { createReadStream } from 'node:fs';
import { mkdir, mkdtemp, appendFile, rm, readFile, open, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { allowMatcher } from './parser.mjs';
import { writeJson } from './io.mjs';
import {categoryGroup} from './category-policy.mjs';
import {categoryInfo,taxonomySections} from './category-taxonomy.mjs';

function summarize(masks, sources) {
  const result={total:0,domains:0,ips:0,uniqueDomains:0,uniqueIPs:0,sharedDomains:0,sharedIPs:0,histogram:{},
    sources:sources.map(({source})=>({id:source.id,name:source.name,role:source.role,homepage:source.homepage,category:source.category||'categorized',domains:0,ips:0,total:0,uniqueDomains:0,uniqueIPs:0,sharedDomains:0,sharedIPs:0})),
    matrix:sources.map(()=>sources.map(()=>({domains:0,ips:0})))};
  for(const [mask,counts]of masks){
    const members=[];let remaining=mask,index=0;
    while(remaining){if(remaining&1n)members.push(index);remaining>>=1n;index++;}
    const shared=members.length>1;
    result.domains+=counts.domains;result.ips+=counts.ips;
    result[shared?'sharedDomains':'uniqueDomains']+=counts.domains;
    result[shared?'sharedIPs':'uniqueIPs']+=counts.ips;
    result.histogram[members.length]||={domains:0,ips:0};result.histogram[members.length].domains+=counts.domains;result.histogram[members.length].ips+=counts.ips;
    for(const i of members){const s=result.sources[i];s.domains+=counts.domains;s.ips+=counts.ips;s[shared?'sharedDomains':'uniqueDomains']+=counts.domains;s[shared?'sharedIPs':'uniqueIPs']+=counts.ips;
      for(const j of members){result.matrix[i][j].domains+=counts.domains;result.matrix[i][j].ips+=counts.ips;}}
  }
  result.total=result.domains+result.ips;for(const s of result.sources)s.total=s.domains+s.ips;
  return result;
}
function addMask(map,mask,kind){let group=map.get(mask);if(!group){group={domains:0,ips:0};map.set(mask,group);}group[kind]++;}

// Partition by the first ASCII character. Each partition fits in memory, and
// processing characters in lexical order produces globally sorted feeds.
// Source bodies and normalized arrays are released between inputs; the full
// NRD/DGA collection need not fit in the JavaScript heap at once.
export async function consolidate({loaded,categoryNames,dist,cache,isPublicSuffix,localAllows,includeEveryday}) {
  const temp=await mkdtemp(join(cache,'consolidation-'));
  const names=[...new Set(categoryNames)],categoryIndex=new Map(names.map((n,i)=>[n,i]));
  const indexFor=name=>{if(!categoryIndex.has(name)){categoryIndex.set(name,names.length);names.push(name);}return categoryIndex.get(name);};
  const chars=new Set();const sourceCounts=[];
  const files=new Map();
  async function output(name,lines){
    if(!files.has(name)){const path=join(dist,`${name}.txt`);await mkdir(join(path,'..'),{recursive:true});files.set(name,{path,temp:`${path}.tmp`,handle:await open(`${path}.tmp`,'w'),hash:createHash('sha256'),count:0,domains:0,ips:0,bytes:0});}
    const file=files.get(name);if(!lines.length)return;
    const text=lines.join('\n')+'\n';file.hash.update(text);file.bytes+=Buffer.byteLength(text);file.count+=lines.length;
    for(const value of lines)isIP(value)?file.ips++:file.domains++;
    await file.handle.writeFile(text);
  }
  try{
    for(const [sourceIndex,item]of loaded.entries()){
      const {parsed}=JSON.parse(await readFile(item.acceptedPath,'utf8'));
      const allowed=allowMatcher([...localAllows,...parsed.allow]);
      const groups=parsed.categories||{[item.source.category]:parsed.block};
      const buckets=new Map(),effective=new Set();
      for(const [category,values]of Object.entries(groups)){
        const targets=[category,...(item.source.additionalCategories||[])];
        const mask=targets.reduce((m,c)=>m|(1n<<BigInt(indexFor(c))),0n);
        const everyday=includeEveryday(item.source,category)?1:0;
        for(const entry of values){
          if(isPublicSuffix(entry)||allowed(entry))continue;
          effective.add(entry);const char=entry[0];chars.add(char);
          if(!buckets.has(char))buckets.set(char,[]);
          buckets.get(char).push(`${entry}\t${sourceIndex}\t${mask.toString(16)}\t${everyday}\n`);
        }
      }
      // Exact, normalized per-upstream feeds make catalog inclusion auditable.
      await output(`upstreams/${item.source.id}`,[...effective].sort());
      sourceCounts.push(effective.size);
      for(const [char,rows]of buckets)await appendFile(join(temp,`${char}.tsv`),rows.join(''));
    }
    const masks=new Map(),categoryMasks=Object.fromEntries(names.map(n=>[n,new Map()])),categoryMembers=new Map(),bundleMasks={protection:new Map(),optional:new Map()},sectionMasks=Object.fromEntries(taxonomySections.map(section=>[section.id,new Map()])),sectionMembers=new Map();
    for(const char of [...chars].sort()){
      const entries=new Map();
      const reader=createInterface({input:createReadStream(join(temp,`${char}.tsv`)),crlfDelay:Infinity});
      for await(const line of reader){
        const [entry,index,category,everyday]=line.split('\t');
        let value=entries.get(entry);if(!value){value={sources:0n,categories:0n,everyday:false};entries.set(entry,value);}
        value.sources|=1n<<BigInt(index);value.categories|=BigInt('0x'+category);value.everyday||=everyday==='1';
      }
      const rows=new Map();const push=(name,entry)=>{if(!rows.has(name))rows.set(name,[]);rows.get(name).push(entry);};
      for(const entry of [...entries.keys()].sort()){
        const value=entries.get(entry),kind=isIP(entry)?'ips':'domains';
        addMask(masks,value.sources,kind);push('all',entry);push(kind,entry);
        if(value.everyday){push('combined',entry);push(`combined.${kind}`,entry);}
        let members=categoryMembers.get(value.categories);
        if(!members){members=[];let mask=value.categories,i=0;while(mask){if(mask&1n)members.push(names[i]);mask>>=1n;i++;}categoryMembers.set(value.categories,members);}
        for(const name of members){addMask(categoryMasks[name],value.sources,kind);push(name,entry);push(`${name}.${kind}`,entry);}
        let sections=sectionMembers.get(value.categories);if(!sections){sections=[...new Set(members.map(name=>categoryInfo(name).section))];sectionMembers.set(value.categories,sections);}for(const section of sections)addMask(sectionMasks[section],value.sources,kind);
        for(const group of ['protection','optional'])if(members.some(name=>categoryGroup(name)===group)){addMask(bundleMasks[group],value.sources,kind);push(group,entry);push(`${group}.${kind}`,entry);}
      }
      for(const [name,values]of rows)await output(name,values);
    }
    // Keep empty, documented category endpoints valid for existing consumers.
    for(const name of names)for(const suffix of ['', '.domains','.ips'])await output(name+suffix,[]);
    for(const name of ['all','domains','ips','combined','combined.domains','combined.ips','protection','protection.domains','protection.ips','optional','optional.domains','optional.ips'])await output(name,[]);
    const feeds={};
    for(const [name,file]of files){await file.handle.close();file.handle=null;await rename(file.temp,file.path);feeds[name]={count:file.count,domains:file.domains,ips:file.ips,bytes:file.bytes,sha256:file.hash.digest('hex'),url:`${name}.txt`};}
    const stats=summarize(masks,loaded);stats.categories={};
    await mkdir(join(dist,'statistics'),{recursive:true});
    for(const name of names){
      const {total,domains,ips,uniqueDomains,uniqueIPs,sharedDomains,sharedIPs,sources,matrix}=summarize(categoryMasks[name],loaded);
      stats.categories[name]={total,domains,ips,uniqueDomains,uniqueIPs,sharedDomains,sharedIPs,group:categoryGroup(name),statisticsUrl:`statistics/${name}.json`};
      await writeJson(join(dist,'statistics',`${name}.json`),{sources,matrix});
    }
    stats.bundles={};
    stats.groups={};await mkdir(join(dist,'statistics','groups'),{recursive:true});
    for(const section of taxonomySections){const members=names.filter(name=>stats.categories[name].total&&categoryInfo(name).section===section.id);if(members.length<2)continue;const {sources,matrix,...counts}=summarize(sectionMasks[section.id],loaded);stats.groups[section.id]={label:section.label,feed:`groups/${section.id}`,categories:members,...counts,statisticsUrl:`statistics/groups/${section.id}.json`};await writeJson(join(dist,'statistics','groups',section.id+'.json'),{sources,matrix});}
    for(const group of ['protection','optional']){const {sources,matrix,...counts}=summarize(bundleMasks[group],loaded);const members=names.filter(n=>categoryGroup(n)===group&&stats.categories[n].total);stats.bundles[group]={feed:group,categories:members,...counts,statisticsUrl:`statistics/${group}.json`};feeds[group].categories=members;for(const kind of ['domains','ips'])feeds[`${group}.${kind}`].categories=members.filter(n=>stats.categories[n][kind]>0);await writeJson(join(dist,'statistics',`${group}.json`),{sources,matrix});}
    for(const suffix of ['', '.domains','.ips'])feeds['combined'+suffix].categories=feeds['protection'+suffix].categories;
    return {stats,feeds,sourceCounts};
  }finally{
    for(const file of files.values())if(file.handle)await file.handle.close();
    await rm(temp,{recursive:true,force:true});
  }
}
