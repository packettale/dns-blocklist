import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {once} from 'node:events';
import {FeedRateLimit,clientAddress} from '../src/feed-rate-limit.mjs';
import {createFeedServer} from '../src/http-server.mjs';
import {get} from 'node:http';

test('feed refresh windows distinguish clients, files and HEAD preflight, and expire after five minutes',()=>{
  let now=0;const limit=new FeedRateLimit({seconds:300,now:()=>now});
  assert.equal(limit.check('1.1.1.1','ads.txt','HEAD').allowed,true);assert.equal(limit.check('1.1.1.1','ads.txt','GET').allowed,true);
  assert.equal(limit.check('1.1.1.1','ads.txt','GET').allowed,false);assert.equal(limit.check('1.1.1.1','ads.txt','HEAD').allowed,false);
  assert.equal(limit.check('1.1.1.1','malware.txt','GET').allowed,true);assert.equal(limit.check('8.8.8.8','ads.txt','GET').allowed,true);
  now=60000;assert.equal(limit.check('1.1.1.1','ads.txt','GET').retryAfter,240);now=300000;assert.equal(limit.check('1.1.1.1','ads.txt','GET').allowed,true);
  const req=(remoteAddress,forwarded)=>({socket:{remoteAddress},headers:{'cf-connecting-ip':forwarded}});
  assert.equal(clientAddress(req('127.0.0.1','8.8.8.8')),'8.8.8.8');assert.equal(clientAddress(req('9.9.9.9','8.8.8.8')),'9.9.9.9');assert.equal(clientAddress(req('::ffff:9.9.9.9','bad')),'9.9.9.9');
  const bounded=new FeedRateLimit({seconds:300,maxEntries:2});for(let i=0;i<10;i++)bounded.check(String(i),'ads.txt','GET');assert.equal(bounded.entries.size,2);
});

test('browser navigations, refreshes and download links remain available while automated polling is throttled',async t=>{
  const root=await mkdtemp(join(tmpdir(),'blocklist-browser-rate-'));t.after(()=>rm(root,{recursive:true,force:true}));await writeFile(join(root,'ads.txt'),'ads.domain.com\n');
  const server=createFeedServer({getSnapshot:()=>({directory:root,manifest:{feeds:{ads:{sha256:'ads'}},categories:{}}}),feedRefreshSeconds:300});server.listen(0,'127.0.0.1');await once(server,'listening');t.after(()=>new Promise(resolve=>server.close(resolve)));
  const url=`http://127.0.0.1:${server.address().port}/ads.txt`;
  const request=headers=>new Promise((resolve,reject)=>{get(url,{headers},response=>{response.resume();response.on('end',()=>resolve(response.statusCode));}).on('error',reject);});
  const browser={'Sec-Fetch-Mode':'navigate','Sec-Fetch-Dest':'document'};
  for(let i=0;i<4;i++)assert.equal(await request(browser),200);
  assert.equal(await request({}),200);assert.equal(await request({}),429);
  assert.equal(await request(browser),200);assert.equal(await request({'Sec-Fetch-Mode':'navigate','Sec-Fetch-Dest':'empty'}),200);
  assert.equal(await request({'Sec-Fetch-Mode':'cors','Sec-Fetch-Dest':'empty'}),429);
});

test('HTTP feed polling returns 429 and Retry-After without limiting other categories, metadata or different clients',async t=>{
  const root=await mkdtemp(join(tmpdir(),'blocklist-rate-'));t.after(()=>rm(root,{recursive:true,force:true}));
  for(const name of ['ads.txt','malware.txt'])await writeFile(join(root,name),'ad.domain.com\n');await writeFile(join(root,'stats.json'),'{}');
  const server=createFeedServer({getSnapshot:()=>({directory:root,manifest:{feeds:{ads:{sha256:'ads'},malware:{sha256:'malware'}},categories:{}}}),feedRefreshSeconds:300});server.listen(0,'127.0.0.1');await once(server,'listening');t.after(()=>new Promise(resolve=>server.close(resolve)));
  const url=`http://127.0.0.1:${server.address().port}`,headers={'CF-Connecting-IP':'1.1.1.1'};
  assert.equal((await fetch(url+'/ads.txt',{method:'HEAD',headers})).status,200);const initial=await fetch(url+'/ads.txt',{headers});assert.equal(initial.status,200);await initial.text();
  const repeated=await fetch(url+'/ads.txt?bypass=1',{headers});assert.equal(repeated.status,429);assert(Number(repeated.headers.get('retry-after'))<=300);assert.equal(repeated.headers.get('cache-control'),'private, no-store');
  assert.equal((await fetch(url+'/ads.txt',{headers:{...headers,'If-None-Match':'"ads"'}})).status,429);
  assert.equal((await fetch(url+'/ads.txt',{headers:{'CF-Connecting-IP':'8.8.8.8','If-None-Match':'"ads"'}})).status,304);
  assert.equal((await fetch(url+'/malware.txt',{headers})).status,200);
  for(let i=0;i<3;i++)assert.equal((await fetch(url+'/stats.json',{headers})).status,200);
});
