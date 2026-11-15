import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {renderPublicDocumentation,writePublicDocumentation,documentationFiles} from '../src/public-docs.mjs';

function snapshot(){return {
  publishedAt:'2026-11-14T12:00:00.000Z',policy:{updateIntervalMinutes:5},totals:{domains:2,ips:0},
  categories:{ads:{total:1,domains:1,ips:0,group:'protection'},social:{total:1,domains:1,ips:0,group:'optional'}},
  bundles:{protection:{categories:['ads']},optional:{categories:['social']}},
  feeds:{protection:{domains:1,ips:0},optional:{domains:1,ips:0},ads:{domains:1,ips:0},social:{domains:1,ips:0},all:{domains:2,ips:0}},
  sources:[{id:'included',domains:2,ips:0}],sourceReports:[
    {id:'included',name:'Maintainer | Network',category:'categorized',state:'current',updatedAt:'2026-11-14T11:00:00Z',homepage:'https://example.org/',upstreamUrl:'https://example.org/feed',license:'MIT',normalizedFeed:'upstreams/included.txt',note:'private-review-canary',reason:'private-review-canary'},
    {id:'rejected-private-source',name:'private-review-canary',selected:false,state:'excluded',reason:'private-review-canary'},
  ]};}
test('Markdown publishes exact bundle membership and included-source facts without private reviews',()=>{
  const docs=renderPublicDocumentation(snapshot());assert.deepEqual(Object.keys(docs).sort(),Object.values(documentationFiles).sort());
  const all=Object.values(docs).join('\n');assert(!all.includes('private-review-canary'));assert(!all.includes('rejected-private-source'));
  assert(docs['index.md'].includes('| Included upstream feeds | 1 |'));
  const [protection,services]=docs['feeds.md'].split('## Internet services');assert(protection.includes('| Ads | ads | 1 | 0 |'));assert(!protection.includes('| Social networks |'));assert(services.includes('| Social networks | social | 1 | 0 |'));
  assert(docs['sources.md'].includes('Maintainer \\| Network'));assert(docs['llms.txt'].startsWith('# packettale dns-blocklist\n\n>'));
  assert(docs['llms.txt'].includes('[Complete reference](<full.md>)'));assert.equal(docs['full.md'],docs['llms-full.txt']);
});
test('regenerating Markdown updates snapshot facts and counts rather than retaining stale documentation',async t=>{
  const dir=await mkdtemp(join(tmpdir(),'blocklist-docs-'));t.after(()=>rm(dir,{recursive:true,force:true}));
  const before=snapshot();await writePublicDocumentation(dir,before);
  const after=snapshot();after.publishedAt='2026-11-15T12:00:00.000Z';after.totals.domains=3;after.feeds.protection.domains=2;after.categories.ads.domains=2;after.categories.ads.total=2;
  await writePublicDocumentation(dir,after);const overview=await readFile(join(dir,'index.md'),'utf8'),feeds=await readFile(join(dir,'feeds.md'),'utf8');
  assert(overview.includes(after.publishedAt));assert(!overview.includes(before.publishedAt));assert(overview.includes('| Domains, all categories | 3 |'));assert(feeds.includes('| Ads | ads | 2 | 0 |'));
});
