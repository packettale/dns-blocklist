import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {parseFirebog,parseSafing,hageziPurpose,logicalSourceKey,githubPath} from '../src/catalogs.mjs';
import {consolidate} from '../src/consolidate.mjs';
import {calculateStatistics} from '../src/statistics.mjs';
import {scanPublicSecret,pruneFeeds} from '../src/verify-output.mjs';

test('catalogs keep negative recommendations, allowlists and unconvertible policies distinct',()=>{
  assert.equal(hageziPurpose('wildcard/native.apple-onlydomains.txt'),'trackers-apple');
  assert.equal(hageziPurpose('wildcard/native.tiktok.extended-onlydomains.txt'),'trackers-tiktok');
  assert.equal(hageziPurpose('wildcard/whitelist-referral-onlydomains.txt'),'referral-allowlist');
  assert.equal(hageziPurpose('wildcard/spam-tlds-onlydomains.txt'),'abused-tlds');
  assert.equal(hageziPurpose('domains/nrd35-29.txt','hagezi/nrd'),'newly-registered-domains');
  assert.equal(hageziPurpose('domains/dga30.txt','hagezi/nrd'),'dga');
  assert.equal(hageziPurpose('wildcard/new-unknown-onlydomains.txt'),null);
  const registry={filters:[{filterId:44,subscriptionUrl:'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt'}]};
  assert.equal(logicalSourceKey({registryId:44},registry),logicalSourceKey({url:'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt'},registry));
  assert.notEqual(logicalSourceKey({registryId:44},registry),logicalSourceKey({url:'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/tif.txt'},registry));
  assert.equal(githubPath('https://example.org/file.txt'),null);
  const rows=Array.from({length:21},(_,i)=>`<li class="${i===0?'bdCross':i===1?'':'bdTick'}"><a href="https://example.org">Producer ${i}:</a><a href="https://example.org/${i}.txt">feed</a></li>`).join('');
  const found=parseFirebog(`<ul class="bdUrlList malicious">${rows}</ul>`);
  assert.match(found[0].reviewReason,/not recommended/);assert.match(found[1].reviewReason,/review required/);assert.equal(found[2].reviewReason,null);
  assert.throws(()=>parseFirebog('<html>Unavailable</html>'),/incomplete/);
  assert.throws(()=>parseSafing('schemaVersion: "v3.0.0"\nsources: []'),/Unsupported/);
});

test('partitioned consolidation matches exact overlaps and keeps source exceptions local',async t=>{
  const root=await mkdtemp(join(tmpdir(),'blocklist-partitions-'));t.after(()=>rm(root,{recursive:true,force:true}));
  const dist=join(root,'dist'),cache=join(root,'cache');await mkdir(dist);await mkdir(cache);
  const inputs=[
    {source:{id:'ads',name:'Ads',category:'ads',role:'supplement'},parsed:{block:['a.com','shared.com','8.8.8.8','login.com','pages.dev'],allow:['login.com']}},
    {source:{id:'policy',name:'Policy',category:'adult',role:'optional'},parsed:{block:['z.com','shared.com','8.8.8.8','login.com'],allow:[]}},
    {source:{id:'categorized',name:'Categorized',role:'supplement'},parsed:{block:['shared.com','b.com','z.com','allow.com'],allow:[],categories:{ads:['shared.com','b.com','allow.com'],tracking:['z.com']}}},
  ];
  const loaded=[];for(const [i,input]of inputs.entries()){const acceptedPath=join(cache,`${i}.json`);await writeFile(acceptedPath,JSON.stringify({parsed:input.parsed}));loaded.push({source:input.source,acceptedPath});}
  const result=await consolidate({loaded,categoryNames:['ads','adult','tracking'],dist,cache,isPublicSuffix:x=>x==='pages.dev',localAllows:['allow.com'],includeEveryday:s=>s.role!=='optional'});
  const expected=calculateStatistics([{source:inputs[0].source,entries:['a.com','shared.com','8.8.8.8']},{source:inputs[1].source,entries:['z.com','shared.com','8.8.8.8','login.com']},{source:inputs[2].source,entries:['shared.com','b.com','z.com']}],{ads:['a.com','b.com','shared.com','8.8.8.8'],adult:['z.com','shared.com','8.8.8.8','login.com'],tracking:['z.com']});
  for(const key of ['domains','ips','uniqueDomains','uniqueIPs','sharedDomains','sharedIPs','matrix','histogram'])assert.deepEqual(result.stats[key],expected[key],key);
  for(const name of ['ads','adult','tracking']){const detail=JSON.parse(await readFile(join(dist,'statistics',`${name}.json`),'utf8'));assert.deepEqual(detail.matrix,expected.categories[name].matrix);assert.deepEqual(detail.sources,JSON.parse(JSON.stringify(expected.categories[name].sources)));}
  assert.equal(await readFile(join(dist,'all.txt'),'utf8'),'8.8.8.8\na.com\nb.com\nlogin.com\nshared.com\nz.com\n');
  assert(!(await readFile(join(dist,'combined.txt'),'utf8')).includes('login.com'));
  assert.equal(result.feeds['upstreams/policy'].count,4);
  const group=result.stats.groups['ads-tracking'];assert.deepEqual(group.categories,['ads','tracking']);assert.equal(group.domains,4);assert.equal(group.ips,1);assert.equal(group.sharedDomains,2);assert.equal(group.uniqueDomains,2);
  const combinedStats=JSON.parse(await readFile(join(dist,group.statisticsUrl),'utf8'));assert.deepEqual(combinedStats.matrix[0][1],{domains:1,ips:1});assert.deepEqual(combinedStats.matrix[1][2],{domains:2,ips:0});assert(!result.stats.groups.nsfw);
  await writeFile(join(dist,'removed.txt'),'old.com\n');await pruneFeeds(dist,result.feeds);await assert.rejects(()=>readFile(join(dist,'removed.txt')),/ENOENT/);
});

test('public secret scan is recursive and detects a secret across stream chunks',async t=>{
  const root=await mkdtemp(join(tmpdir(),'blocklist-public-scan-'));t.after(()=>rm(root,{recursive:true,force:true}));await mkdir(join(root,'upstreams'));
  const secret='sensitive-test-value-123456';await writeFile(join(root,'upstreams','feed.txt'),'x'.repeat(65530)+secret+'\n');
  await assert.rejects(()=>scanPublicSecret(root,secret),/secret check/);await scanPublicSecret(root,'not-present-in-any-file');
});

test('overlap membership stays exact beyond 64 upstream feeds',async t=>{
  const root=await mkdtemp(join(tmpdir(),'blocklist-many-sources-'));t.after(()=>rm(root,{recursive:true,force:true}));const dist=join(root,'dist'),cache=join(root,'cache');await mkdir(dist);await mkdir(cache);
  const loaded=[];for(let i=0;i<130;i++){const acceptedPath=join(cache,`${i}.json`);await writeFile(acceptedPath,JSON.stringify({parsed:{block:[`unique${i}.com`,'shared.com',...([0,129].includes(i)?['8.8.8.8']:[])],allow:[]}}));loaded.push({source:{id:`source-${i}`,name:`Source ${i}`,category:'ads',role:'supplement'},acceptedPath});}
  const {stats}=await consolidate({loaded,categoryNames:['ads'],dist,cache,isPublicSuffix:()=>false,localAllows:[],includeEveryday:()=>true});
  assert.equal(stats.domains,131);assert.equal(stats.ips,1);assert.equal(stats.uniqueDomains,130);assert.equal(stats.sharedDomains,1);assert.equal(stats.sharedIPs,1);
  assert.deepEqual(stats.matrix[0][129],{domains:1,ips:1});assert.deepEqual(stats.matrix[64][65],{domains:1,ips:0});assert.equal(stats.sources[129].uniqueDomains,1);assert.equal(stats.histogram[130].domains,1);
});
