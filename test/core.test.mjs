import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { normalize, parseLine, parseText, parseDisconnect, allowMatcher, publicSuffixes } from '../src/parser.mjs';
import { Downloader } from '../src/io.mjs';
import { calculateStatistics } from '../src/statistics.mjs';
import { registryEligibility, run } from '../src/update.mjs';
import { candidates, supplements, registryUrl, settings } from '../src/sources.mjs';
import { validate } from '../src/validate.mjs';

test('canonical domains and global IPs survive; malformed and local entries do not', () => {
  assert.equal(normalize(' TRACKER.COM. '), 'tracker.com');
  assert.equal(normalize('bücher.de'), 'xn--bcher-kva.de');
  assert.equal(normalize('8.8.8.8'), '8.8.8.8');
  assert.equal(normalize('2606:4700:4700:0:0:0:0:1111'), '2606:4700:4700::1111');
  for (const bad of ['0.0.0.0','127.0.0.1','::1','10.0.0.1','192.168.1.1','2001:db8::1','999.1.1.1','localhost','host.local','co_m.com','-bad.com','*.tracker.com','8.8.8.0/24','https://tracker.com/a','tracker.com:443','foo..com']) assert.equal(normalize(bad), null, bad);
});

test('hosts prefixes are discarded, true IP indicators survive, and aliases are handled', () => {
  assert.deepEqual(parseLine('0.0.0.0 ADS.COM tracker.com # reason').block, ['ads.com','tracker.com']);
  assert.equal(parseLine('127.0.0.1 localhost'), null);
  assert.deepEqual(parseLine('8.8.8.8').block, ['8.8.8.8']);
  assert.deepEqual(parseLine('::1 tracker.com').block, ['tracker.com']);
});

test('scoped browser rules and URL paths never become whole-domain blocks', () => {
  for (const line of ['||tracker.com^$third-party','||tracker.com/pixel','https://sharedhost.com/malware','||tracker.com^$dnsrewrite=127.0.0.1','##.ad','/tracker[0-9]+/','*.tracker.com']) assert.equal(parseLine(line), null, line);
  assert.deepEqual(parseLine('||tracker.com^').block, ['tracker.com']);
  assert.deepEqual(parseLine('@@||login.site.com^$domain=site.com').allow, ['login.site.com']);
  assert.deepEqual(parseLine('||tracker.com^$badfilter').allow, ['tracker.com']);
});

test('parser rejects error pages and deduplicates normalized text', () => {
  assert.throws(() => parseText('<html><body>Error</body></html>'), /error document/);
  const result = parseText('# Comment\n0.0.0.0 ad.site.com\nad.site.com\n! ignored\n8.8.8.8\nhttp://site.com/path\n');
  assert.deepEqual(result.block, ['8.8.8.8','ad.site.com']);
  assert.equal(result.rejected, 1);
});

test('Disconnect preserves categories and excludes functional Content domains', () => {
  const result = parseDisconnect(JSON.stringify({ license:'Original terms', categories:{
    Advertising:[{Vendor:{'https://vendor.com':['ads.vendor.com','ads.vendor.com','vendor.com/path']}}],
    Analytics:[{Vendor:{'https://vendor.com':['analytics.vendor.com']}}],
    FingerprintingGeneral:[{Vendor:{'https://vendor.com':['fp.vendor.com']}}],
    Content:[{Vendor:{'https://vendor.com':['functional.vendor.com']}}],
    'Anti-fraud':[{Vendor:{'https://vendor.com':['fraud-check.vendor.com']}}]
  }}));
  assert.deepEqual(result.categories.ads, ['ads.vendor.com']);
  assert.deepEqual(result.categories.analytics, ['analytics.vendor.com']);
  assert.deepEqual(result.categories.fingerprinting, ['fp.vendor.com']);
  assert(!result.block.includes('vendor.com'));
  assert(!result.block.includes('functional.vendor.com'));
  assert(!result.block.includes('fraud-check.vendor.com'));
});

test('whole social-service hosts stay optional when also listed as third-party trackers',()=>{
  const data={categories:{Advertising:[{A:{'https://social.com':['social.com','ads.social.com']}}],FingerprintingGeneral:[{A:{'https://social.com':['social.com']}}],Social:[{A:{'https://social.com':['social.com']}}]}};
  const result=parseDisconnect(JSON.stringify(data));
  assert.deepEqual(result.categories.social,['social.com']);assert.deepEqual(result.categories.ads,['ads.social.com']);assert.deepEqual(result.categories.fingerprinting,[]);assert(result.block.includes('social.com'));
});

test('exceptions protect descendants and block rules that swallow an allowed child', () => {
  const allowed = allowMatcher(['login.shop.com','=exact.com','8.8.8.8']);
  assert(allowed('login.shop.com')); assert(allowed('sso.login.shop.com')); assert(allowed('shop.com'));
  assert(!allowed('ads.shop.com')); assert(allowed('exact.com')); assert(!allowed('ad.exact.com'));
  assert(allowed('8.8.8.8')); assert(!allowed('1.1.1.1'));
});

test('public suffix protection includes private hosting and wildcard exceptions', () => {
  const psl = Array.from({length:1001},(_,i)=>`suffix${i}`).join('\n')+'\ncom\nco.uk\npages.dev\n*.ck\n!www.ck\n';
  const isSuffix = publicSuffixes(psl);
  assert(isSuffix('co.uk')); assert(isSuffix('pages.dev')); assert(isSuffix('a.ck'));
  assert(!isSuffix('www.ck')); assert(!isSuffix('malicious.pages.dev'));
  assert.throws(()=>publicSuffixes('com\norg'), /incomplete/);
});

test('source eligibility requires current revisions and rejects problematic, disabled and missing feeds', () => {
  const now=Date.now(); const registry={filters:[{filterId:1,name:'Test',timeUpdated:new Date(now-86400000).toISOString(),tags:[],downloadUrl:'https://feed.test/a'}],tags:[{tagId:111,keyword:'problematic'}]};
  const source={registryId:1}; assert(registryEligibility(source,registry,now).eligible);
  registry.filters[0].tags=[111]; assert(!registryEligibility(source,registry,now).eligible);
  registry.filters[0].tags=[]; registry.filters[0].disabled=true; assert(!registryEligibility(source,registry,now).eligible);
  registry.filters[0].disabled=false; registry.filters[0].timeUpdated=new Date(now-40*86400000).toISOString(); assert(!registryEligibility(source,registry,now).eligible);
  assert(!registryEligibility({registryId:99},registry,now).eligible);
});

test('overlap counts reconcile for domains, IPs, duplicates and category intersections', () => {
  const a={id:'a',name:'A'},b={id:'b',name:'B'},c={id:'c',name:'C'};
  const s=calculateStatistics([{source:a,entries:['a.com','shared.com','8.8.8.8','a.com']},{source:b,entries:['b.com','shared.com','8.8.8.8']},{source:c,entries:['shared.com']}],{ads:['shared.com','a.com']});
  assert.equal(s.domains,3);assert.equal(s.ips,1);assert.equal(s.sharedDomains,1);assert.equal(s.uniqueDomains,2);assert.equal(s.sharedIPs,1);
  assert.deepEqual(s.matrix[0][1],{domains:1,ips:1}); assert.deepEqual(s.matrix[1][0],s.matrix[0][1]);
  assert.equal(s.sources[0].uniqueDomains,1);assert.equal(s.sources[2].sharedDomains,1);
  assert.equal(s.categories.ads.sources[0].domains,2);assert.equal(s.categories.ads.sources[1].domains,1);
  assert.deepEqual(s.categories.ads.matrix[0][1],{domains:1,ips:0});
});

test('conditional requests reuse validated bodies and a failed fetch does not overwrite them', async t => {
  const dir=await mkdtemp(join(tmpdir(),'clearlist-http-'));t.after(()=>rm(dir,{recursive:true,force:true}));
  let mode=0, calls=0;
  const downloader=new Downloader(dir,settings,async (_url,options)=>{
    calls++;
    if(mode===0)return new Response('ads.site.com\n',{headers:{etag:'"v1"','last-modified':'Sat, 14 Nov 2026 00:00:00 GMT'}});
    assert.equal(options.headers['If-None-Match'],'"v1"');
    if(mode===1)return new Response(null,{status:304});
    return new Response('Server unavailable',{status:503});
  });
  const first=await downloader.get('https://feed.test/list');mode=1;
  const second=await downloader.get('https://feed.test/list');assert.equal(second.text,first.text);assert.equal(second.status,304);
  mode=2;await assert.rejects(()=>downloader.get('https://feed.test/list'),/HTTP 503/);
  const cached=await downloader.get('https://feed.test/list',{minIntervalMs:3600000});assert.equal(cached.text,first.text);assert.equal(calls,3);
});

test('end-to-end builds plain feeds, counts overlap, removes upstream deletions, and preserves publication on outage', async t => {
  const root=await mkdtemp(join(tmpdir(),'clearlist-build-'));t.after(()=>rm(root,{recursive:true,force:true}));
  await mkdir(join(root,'web'));await writeFile(join(root,'web','index.html'),'<html lang="en"><title>Test</title></html>');await writeFile(join(root,'allowlist.txt'),'allow.demo.com\n');
  const now=new Date(Date.now()-3600000).toISOString();
  const ids=[...new Set([...candidates,...supplements].filter(s=>s.registryId).map(s=>s.registryId))];
  const registry={filters:ids.map(id=>({filterId:id,name:`Feed ${id}`,tags:[],deprecated:false,timeUpdated:now,version:'1',homepage:'https://feed.test/',downloadUrl:`https://feed.test/${id}`,subscriptionUrl:`https://original.test/${id}`})),tags:[]};
  let mode=0;
  const suffix=Array.from({length:1001},(_,i)=>`suffix${i}`).join('\n')+'\ncom\npages.dev\n';
  const fakeFetch=async url=>{
    if(url===registryUrl)return new Response(JSON.stringify(registry));
    if(url.includes('publicsuffix.org'))return new Response(suffix);
    if(url.includes('api.github.com')&&url.includes('/commits?'))return new Response(JSON.stringify([{sha:'123',html_url:'https://github.com/example/commit/123',commit:{committer:{date:now}}}]));
    if(url.includes('api.github.com'))return new Response(JSON.stringify({archived:false,disabled:false}));
    if(mode===3)return new Response('Unavailable',{status:503});
    if(url.includes('services.json'))return mode===2?new Response('Unavailable',{status:503}):new Response(JSON.stringify({license:'test',categories:{Advertising:[{A:{'https://a.com':Array.from({length:20},(_,i)=>`disc${i}.demo.com`)}}]}}));
    const unique=new URL(url).pathname.replace(/[^a-z0-9]/gi,'').slice(-30)||'root';
    const lines=Array.from({length:20},(_,i)=>`shared${i}.demo.com`);
    lines.push(`${unique}.demo.com`,'8.8.8.8','allow.demo.com','pages.dev');
    if(mode===0 && url==='https://feed.test/1')lines.push('removed.demo.com');
    return new Response(lines.join('\n'),{headers:{'content-type':'text/plain','last-modified':new Date(now).toUTCString()}});
  };
  const initial=await run({root,fetchImpl:fakeFetch,discovery:false});assert.equal(initial.policy.selectedPrimary,candidates.length);
  const first=await readFile(join(root,'dist','all.txt'),'utf8');assert(first.includes('removed.demo.com'));assert(!first.includes('allow.demo.com'));assert(!first.split('\n').includes('pages.dev'));assert(!first.includes('0.0.0.0'));
  await validate(join(root,'dist'));
  mode=1;await run({root,fetchImpl:fakeFetch,discovery:false});const second=await readFile(join(root,'dist','all.txt'),'utf8');assert(!second.includes('removed.demo.com'));await validate(join(root,'dist'));
  const stable=await readFile(join(root,'dist','stats.json'),'utf8');await run({root,fetchImpl:fakeFetch,discovery:false});assert.equal(await readFile(join(root,'dist','stats.json'),'utf8'),stable);
  const disconnectMetaPath=join(root,'.cache','accepted','disconnect.meta.json'),disconnectMeta=JSON.parse(await readFile(disconnectMetaPath,'utf8'));
  disconnectMeta.parserRevision='obsolete-parser';await writeFile(disconnectMetaPath,JSON.stringify(disconnectMeta));mode=2;
  const parserUpgrade=await run({root,fetchImpl:fakeFetch,discovery:false});assert(!parserUpgrade.sourceReports.some(s=>s.id==='disconnect'));
  const afterUpgrade=await readFile(join(root,'dist','all.txt'),'utf8');assert(!afterUpgrade.includes('disc0.demo.com'));
  const before=await readFile(join(root,'dist','stats.json'),'utf8');mode=3;await assert.rejects(()=>run({root,fetchImpl:fakeFetch,discovery:false}),/current primary sources/);
  assert.equal(await readFile(join(root,'dist','stats.json'),'utf8'),before);assert.equal(await readFile(join(root,'dist','all.txt'),'utf8'),afterUpgrade);
});
