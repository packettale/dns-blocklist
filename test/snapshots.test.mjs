import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {SnapshotStore} from '../src/snapshots.mjs';

test('validated snapshots switch atomically, survive restart, and reject failed or active-slot builds',async t=>{
  const root=await mkdtemp(join(tmpdir(),'blocklist-snapshots-'));t.after(()=>rm(root,{recursive:true,force:true}));
  const bootstrap={inputFingerprint:'bootstrap',publishedAt:'2026-11-14T00:00:00Z'};
  await mkdir(join(root,'dist'));await writeFile(join(root,'dist','stats.json'),JSON.stringify(bootstrap));
  const validate=async directory=>{const text=await readFile(join(directory,'stats.json'),'utf8');if(JSON.parse(text).invalid)throw Error('Invalid feed');};
  let store=new SnapshotStore({root,validate});await store.initialize();assert.equal(store.active.manifest.inputFingerprint,'bootstrap');
  const a=await store.target(),first={inputFingerprint:'new',publishedAt:'2026-11-14T01:00:00Z'};
  await writeFile(join(a.directory,'stats.json'),JSON.stringify(first));await store.commit(a,first);
  assert.equal(store.activeSlot,'a');assert.equal(store.active.manifest,first);
  await assert.rejects(store.commit(a,first),/active snapshot/);
  store=new SnapshotStore({root,validate});await store.initialize();assert.equal(store.activeSlot,'a');assert.equal(store.active.manifest.inputFingerprint,'new');
  const b=await store.target();assert.equal(b.slot,'b');
  const bad={inputFingerprint:'bad',invalid:true};await writeFile(join(b.directory,'stats.json'),JSON.stringify(bad));
  await assert.rejects(store.commit(b,bad),/Invalid feed/);assert.equal(store.activeSlot,'a');
  assert.equal(JSON.parse(await readFile(store.pointer,'utf8')).slot,'a');
  await writeFile(join(b.directory,'stats.json'),JSON.stringify(first));assert.equal(await store.commit(b,first),false);assert.equal(store.activeSlot,'a');
  const next={inputFingerprint:'next',publishedAt:'2026-11-14T02:00:00Z'};await writeFile(join(b.directory,'stats.json'),JSON.stringify(next));await store.commit(b,next);
  assert.equal(store.activeSlot,'b');assert.equal((await store.target()).slot,'a');
  await assert.rejects(store.commit({slot:'../outside',directory:root},next),/Invalid snapshot slot/);
});
