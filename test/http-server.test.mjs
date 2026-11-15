import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {once} from 'node:events';
import {createFeedServer} from '../src/http-server.mjs';
import {sha256} from '../src/io.mjs';
import {documentationFiles} from '../src/public-docs.mjs';

test('feed server handles conditional refresh, snapshot changes and private-path rejection',async t=>{
  const root=await mkdtemp(join(tmpdir(),'blocklist-http-'));t.after(()=>rm(root,{recursive:true,force:true}));
  const a=join(root,'a'),b=join(root,'b');await mkdir(a);await mkdir(b);
  for(const [directory,text]of [[a,'alpha.com\n'],[b,'beta.com\n']]){await writeFile(join(directory,'ads.txt'),text);await writeFile(join(directory,'private.key'),'not-public');}
  let snapshot={directory:a,manifest:{feeds:{ads:{sha256:sha256('alpha.com\n')}},categories:{}}};
  const server=createFeedServer({getSnapshot:()=>snapshot});server.listen(0,'127.0.0.1');await once(server,'listening');t.after(()=>new Promise(resolve=>server.close(resolve)));
  const url=`http://127.0.0.1:${server.address().port}`;
  const initial=await fetch(url+'/ads.txt');assert.equal(initial.status,200);assert.equal(await initial.text(),'alpha.com\n');const etag=initial.headers.get('etag');assert(etag);
  const unchanged=await fetch(url+'/ads.txt',{headers:{'If-None-Match':etag}});assert.equal(unchanged.status,304);assert.equal(await unchanged.text(),'');
  const head=await fetch(url+'/ads.txt',{method:'HEAD'});assert.equal(head.status,200);assert.equal(head.headers.get('content-length'),'10');assert.equal(await head.text(),'');
  for(const path of ['/private.key','/.cache/private.key','/%2e%2e/private.key','/ads.txt.tmp'])assert.equal((await fetch(url+path)).status,404,path);
  assert.equal((await fetch(url+'/ads.txt',{method:'POST'})).status,405);
  await writeFile(join(a,'index.md'),'# Public data\n');await writeFile(join(a,'llms.txt'),'# DNS-IP-Blocklist\n');await writeFile(join(a,'index.html'),'<title>Public data</title>');await writeFile(join(a,'private-review.md'),'private');
  await mkdir(join(a,'statistics'));await writeFile(join(a,'statistics','protection.json'),'{}');snapshot.manifest.documentation=documentationFiles;snapshot.manifest.bundles={protection:{}};
  const markdown=await fetch(url+'/index.md');assert.equal(markdown.status,200);assert.equal(markdown.headers.get('content-type'),'text/markdown; charset=utf-8');assert.equal(await markdown.text(),'# Public data\n');assert(markdown.headers.get('link').includes('llms.txt'));
  assert.equal((await fetch(url+'/llms.txt')).status,200);assert.equal((await fetch(url+'/private-review.md')).status,404);
  const html=await fetch(url+'/');assert(html.headers.get('link').includes('rel="alternate"; type="text/markdown"'));
  const bundleStats=await fetch(url+'/statistics/protection.json');assert.equal(bundleStats.status,200);assert(bundleStats.headers.get('link').includes('../llms.txt'));
  snapshot={directory:b,manifest:{feeds:{ads:{sha256:sha256('beta.com\n')}},categories:{}}};
  const changed=await fetch(url+'/ads.txt',{headers:{'If-None-Match':etag}});assert.equal(changed.status,200);assert.notEqual(changed.headers.get('etag'),etag);assert.equal(await changed.text(),'beta.com\n');
});

test('tunnel origin enforces HTTPS, prevents redirect injection, and supplies browser security headers',async t=>{
  const root=await mkdtemp(join(tmpdir(),'blocklist-secure-'));t.after(()=>rm(root,{recursive:true,force:true}));
  await writeFile(join(root,'index.html'),'<h1>packettale dns-blocklist</h1>');
  const server=createFeedServer({getSnapshot:()=>({directory:root,manifest:{feeds:{},categories:{}}}),publicHostname:'blocklist.packettale.com',requireHttps:true});
  server.listen(0,'127.0.0.1');await once(server,'listening');t.after(()=>new Promise(resolve=>server.close(resolve)));
  const url=`http://127.0.0.1:${server.address().port}`;
  const redirect=await fetch(url+'/ads.txt?x=1',{headers:{'X-Forwarded-Proto':'http',Host:'evil.invalid'},redirect:'manual'});
  assert.equal(redirect.status,308);assert.equal(redirect.headers.get('location'),'https://blocklist.packettale.com/ads.txt?x=1');
  const injection=await fetch(url+'//evil.invalid/path',{headers:{'X-Forwarded-Proto':'http'},redirect:'manual'});
  assert.equal(injection.headers.get('location'),'https://blocklist.packettale.com/');
  const secure=await fetch(url+'/',{headers:{'X-Forwarded-Proto':'https'}});assert.equal(secure.status,200);
  assert.equal(secure.headers.get('strict-transport-security'),'max-age=31536000');assert.equal(secure.headers.get('x-frame-options'),'DENY');
  assert.equal(secure.headers.get('referrer-policy'),'no-referrer');assert(secure.headers.get('content-security-policy').includes("frame-ancestors 'none'"));
  for(const path of ['/.env','/.git/config','/.cache/worker-status.json','/src/worker.mjs','/deploy/dns-ip-blocklist.service','/%252e%252e/etc/passwd','/upstreams/../../key.txt','/robots.txt/../private.key'])assert.equal((await fetch(url+path)).status,404,path);
  for(const method of ['POST','PUT','DELETE','PATCH','OPTIONS'])assert.equal((await fetch(url+'/',{method})).status,405,method);
  assert.equal((await fetch(url+'/',{redirect:'manual'})).status,200,'local health checks remain available');
});
