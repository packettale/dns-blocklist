import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { getUrlhausExport, readUrlhausKey } from '../src/urlhaus-client.mjs';
import { csvRows, analyzeUrlhausCsv } from '../src/urlhaus.mjs';

test('URLhaus CSV handles quoted commas, escaped quotes, and multiline fields',()=>{
  assert.deepEqual([...csvRows('# comment\n"1","a,b","escaped ""quote"""\n"2","multi\nline","end"')],[['1','a,b','escaped "quote"'],['2','multi\nline','end']]);
  assert.throws(()=>[...csvRows('"truncated')],/Truncated/);
});

test('URL records are deduplicated into hosts and online status is kept distinct',()=>{
  const text='# id,dateadded,url,url_status,last_online,threat,tags,link,reporter\n'+
    '"1","2026-11-14","https://evil.demo.com/a","online","","malware_download","","",""\n'+
    '"2","2026-11-14","https://evil.demo.com/b","online","","malware_download","","",""\n'+
    '"3","2026-11-13","http://8.8.8.8/file","offline","","malware_download","","",""\n';
  const a=analyzeUrlhausCsv(text,new Set(['evil.demo.com']));
  assert.equal(a.rows,3);assert.equal(a.all.domains,1);assert.equal(a.all.ips,1);
  assert.equal(a.online.total,1);assert.equal(a.all.newDomains,0);assert.equal(a.all.newIPs,1);
});

test('missing key is optional and malformed keys never appear in errors',async()=>{
  assert.equal(await readUrlhausKey({}),null);
  await assert.rejects(()=>readUrlhausKey({URLHAUS_AUTH_KEY:'not a key'}),/Invalid URLhaus key format/);
});

test('authenticated requests do not persist the secret URL and reuse data for five minutes',async t=>{
  const dir=await mkdtemp(join(tmpdir(),'clearlist-secret-'));t.after(()=>rm(dir,{recursive:true,force:true}));
  const key='test_key_for_security_fixture_123456';let calls=0;
  const fake=async(url,options)=>{calls++;assert(url.startsWith('https://urlhaus-api.abuse.ch/'));assert(url.includes(key));assert.equal(options.redirect,'error');return new Response('# Official data\n0.0.0.0 bad.demo.com\n',{headers:{'last-modified':new Date().toUTCString(),'content-type':'text/plain'}});};
  const a=await getUrlhausExport({key,cacheDir:dir,fetchImpl:fake});
  const b=await getUrlhausExport({key,cacheDir:dir,fetchImpl:fake});assert.equal(calls,1);assert.equal(a.text,b.text);
  for(const file of await readdir(dir))assert(!(await readFile(join(dir,file),'utf8')).includes(key));
  assert(!JSON.stringify(a).includes(key));
});

test('reflected secrets are refused and raw network exceptions are redacted',async t=>{
  const dir=await mkdtemp(join(tmpdir(),'clearlist-secret-'));t.after(()=>rm(dir,{recursive:true,force:true}));
  const key='test_key_for_security_fixture_abcdef';
  await assert.rejects(()=>getUrlhausExport({key,cacheDir:dir,fetchImpl:async()=>new Response(key)}),/secret check/);
  assert.equal((await readdir(dir)).length,0);
  try{await getUrlhausExport({key,cacheDir:dir,fetchImpl:async()=>{throw Error('Could not fetch '+key);}});assert.fail('Expected failure');}
  catch(e){assert(!e.message.includes(key));assert(e.message.includes('redacted'));}
});
