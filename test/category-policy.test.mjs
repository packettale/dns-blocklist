import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {categoryGroup} from '../src/category-policy.mjs';
import {consolidate} from '../src/consolidate.mjs';
test('normal service and content policies are separate from ads, trackers and threats',()=>{
  for(const name of ['ads','tracking','malware','phishing','telemetry','cname-tracking','trackers-apple','regional-pl'])assert.equal(categoryGroup(name),'protection',name);
  for(const name of ['social','adult','gambling','tor','bypass','encrypted-dns','dynamic-dns','free-hosting','badware-hosting','url-shorteners','referral-tracking','newly-registered-domains','dga','ai','cryptocurrency','remote-access','malware-and-support','big-tech-google','fonts','chat-widgets','apple-bloat','attacking-ips','unknown-new-policy'])assert.equal(categoryGroup(name),'optional',name);
});
test('protection contains exactly its listed categories and never adds optional-only hosts',async t=>{
  const root=await mkdtemp(join(tmpdir(),'blocklist-groups-'));t.after(()=>rm(root,{recursive:true,force:true}));const dist=join(root,'dist'),cache=join(root,'cache');await mkdir(dist);await mkdir(cache);
  const source={id:'categorized',name:'Categorized'},categories={ads:['advertising.com','shared.com'],tracking:['tracker.com'],social:['normal-social.com','shared.com'],tor:['8.8.8.8']},acceptedPath=join(cache,'feed.json');await writeFile(acceptedPath,JSON.stringify({parsed:{block:Object.values(categories).flat(),categories,allow:[]}}));
  const {stats,feeds}=await consolidate({loaded:[{source,acceptedPath}],categoryNames:Object.keys(categories),dist,cache,isPublicSuffix:()=>false,localAllows:[],includeEveryday:(_s,c)=>categoryGroup(c)==='protection'});
  assert.equal(await readFile(join(dist,'protection.txt'),'utf8'),'advertising.com\nshared.com\ntracker.com\n');
  assert.equal(await readFile(join(dist,'optional.txt'),'utf8'),'8.8.8.8\nnormal-social.com\nshared.com\n');
  assert.deepEqual(stats.bundles.protection.categories,['ads','tracking']);assert.deepEqual(stats.bundles.optional.categories,['social','tor']);assert.equal(feeds.combined.sha256,feeds.protection.sha256);
});
