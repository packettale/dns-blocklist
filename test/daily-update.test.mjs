import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,access,stat} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {normalizedDigest,buildFingerprint} from '../src/build-inputs.mjs';
import {nextDailyCheck,reserveDailyCheck,dayMilliseconds} from '../src/daily-schedule.mjs';
import {parseText} from '../src/parser.mjs';
import {run} from '../src/update.mjs';
import {SnapshotStore} from '../src/snapshots.mjs';
import {validate} from '../src/validate.mjs';
import {candidates,supplements,registryUrl} from '../src/sources.mjs';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {setTimeout as delay} from 'node:timers/promises';
import {resolve} from 'node:path';

test('daily check reservation persists across restarts, skips early wakeups, and advances one day after an unchanged check',()=>{
  const now=Date.parse('2026-11-14T19:00:00Z'),saved=reserveDailyCheck(now);
  assert.equal(nextDailyCheck(saved,now+60000),now+dayMilliseconds);
  assert.equal(nextDailyCheck(JSON.parse(JSON.stringify(saved)),now+3600000),now+dayMilliseconds);
  assert.equal(nextDailyCheck({lastAttemptAt:new Date(now).toISOString()}),now+dayMilliseconds);
  const next=reserveDailyCheck(now+dayMilliseconds);assert.equal(nextDailyCheck(next),now+2*dayMilliseconds);
});
test('normalized change detection ignores headers, duplicates and metadata, but detects entries, source membership and policy changes',()=>{
  const parsed=parseText('# Version 1\nb.com\na.com\na.com\n'),later=parseText('# Version 2 and new date\na.com\nb.com\n');
  assert.equal(normalizedDigest(parsed),normalizedDigest(later));
  const loaded=[{source:{id:'a',category:'ads',updatedAt:'old',version:'1'},normalizedHash:normalizedDigest(parsed),normalizedCategories:[]}];
  const fingerprint=()=>buildFingerprint({loaded,localAllows:[],suffixText:'// date\ncom\norg\n'}),before=fingerprint();
  loaded[0].source.updatedAt='new';loaded[0].source.version='2';loaded[0].state='cached';loaded[0].error='timeout';assert.equal(fingerprint(),before);
  loaded[0].normalizedHash=normalizedDigest(parseText('a.com\nb.com\nc.com'));assert.notEqual(fingerprint(),before);
  assert.notEqual(buildFingerprint({loaded:[],localAllows:[],suffixText:'com\norg\n'}),before);
  const summary={normalizedHash:'same',normalizedCategories:['ads'],source:{id:'categorized-source'}};
  assert.equal(buildFingerprint({loaded:[summary],localAllows:[],suffixText:'com'}),buildFingerprint({loaded:[{...summary,source:{...summary.source,category:'categorized'}}],localAllows:[],suffixText:'com'}));
});
test('unchanged upstreams skip an empty inactive slot; changed data builds that slot; another unchanged cycle preserves publication',async t=>{
  const root=await mkdtemp(join(tmpdir(),'blocklist-daily-'));t.after(()=>rm(root,{recursive:true,force:true}));
  await mkdir(join(root,'web'));await writeFile(join(root,'web','index.html'),'<title>Test</title>');await writeFile(join(root,'allowlist.txt'),'');
  const revision=new Date(Date.now()-3600000).toISOString(),ids=[...new Set([...candidates,...supplements].filter(s=>s.registryId).map(s=>s.registryId))];
  const registry={filters:ids.map(id=>({filterId:id,name:`Source ${id}`,tags:[],timeUpdated:revision,version:'1',homepage:'https://feed.test/',downloadUrl:`https://feed.test/${id}`,subscriptionUrl:`https://original.test/${id}`})),tags:[]};
  const suffix=Array.from({length:1001},(_,i)=>`suffix${i}`).join('\n')+'\ncom\n';let generation=0,comments=0;
  const fetchImpl=async url=>{
    if(url===registryUrl)return new Response(JSON.stringify(registry));
    if(url.includes('publicsuffix.org'))return new Response(suffix);
    if(url.includes('api.github.com')&&url.includes('/commits?'))return new Response(JSON.stringify([{sha:'123',html_url:'https://github.com/example/commit/123',commit:{committer:{date:revision}}}]));
    if(url.includes('api.github.com'))return new Response(JSON.stringify({archived:false,disabled:false}));
    if(url.includes('services.json'))return new Response(JSON.stringify({license:'test',categories:{Advertising:[{A:{'https://a.com':['disc.demo.com']}}]}}));
    const lines=Array.from({length:20},(_,i)=>`shared${i}.demo.com`);if(generation&&url==='https://feed.test/1')lines.push('new.demo.com');
    return new Response(`# Upstream revision note ${comments}\n`+lines.join('\n'),{headers:{'content-type':'text/plain','last-modified':new Date(revision).toUTCString()}});
  };
  const store=new SnapshotStore({root,validate}),a=await store.target();const first=await run({root,outputDir:a.directory,fetchImpl,discovery:false});await store.commit(a,first);
  const b=await store.target(),original=await readFile(join(a.directory,'stats.json'),'utf8'),mtime=(await stat(join(a.directory,'all.txt'))).mtimeMs;
  comments=1;registry.filters.forEach(f=>f.version='2');const unchanged=await run({root,outputDir:b.directory,baselineDir:a.directory,fetchImpl,discovery:false});
  assert.equal(unchanged._unchanged,true);assert.equal(unchanged.publishedAt,first.publishedAt);await assert.rejects(access(join(b.directory,'all.txt')),/ENOENT/);
  assert.equal(await readFile(join(a.directory,'stats.json'),'utf8'),original);assert.equal((await stat(join(a.directory,'all.txt'))).mtimeMs,mtime);
  generation=1;const changed=await run({root,outputDir:b.directory,baselineDir:a.directory,fetchImpl,discovery:false});assert(!changed._unchanged);assert((await readFile(join(b.directory,'all.txt'),'utf8')).includes('new.demo.com'));await store.commit(b,changed);
  const again=await run({root,outputDir:a.directory,baselineDir:b.directory,fetchImpl,discovery:false});assert.equal(again._unchanged,true);assert.equal(again.inputFingerprint,changed.inputFingerprint);assert.equal(store.activeSlot,'b');
  const future=reserveDailyCheck(),schedulePath=join(root,'.cache','daily-schedule.json'),statusPath=join(root,'.cache','worker-status.json');await writeFile(schedulePath,JSON.stringify(future));
  for(let restart=0;restart<2;restart++){
    await rm(statusPath,{force:true});
    const child=spawn(process.execPath,[resolve('src/worker.mjs')],{cwd:root,stdio:'ignore',windowsHide:true});const ended=once(child,'exit');
    try{for(let i=0;i<200;i++){try{if(JSON.parse(await readFile(statusPath,'utf8')).state==='waiting')break;}catch{}await delay(20);}const status=JSON.parse(await readFile(statusPath,'utf8'));assert.equal(status.nextCheckAt,future.nextCheckAt);assert.equal(status.lastAttemptAt,undefined);await assert.rejects(access(join(root,'.cache','update-result.json')),/ENOENT/);}finally{child.kill('SIGTERM');await ended;}
    assert.deepEqual(JSON.parse(await readFile(schedulePath,'utf8')),future);
  }
});
