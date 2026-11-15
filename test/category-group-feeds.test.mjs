import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm,access} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {writeCategoryGroupFeeds} from '../src/category-group-feeds.mjs';
import {sha256} from '../src/io.mjs';

test('full category-group feeds deduplicate every subcategory and omit combined endpoints for singletons',async t=>{
  const directory=await mkdtemp(join(tmpdir(),'blocklist-groups-'));t.after(()=>rm(directory,{recursive:true,force:true}));
  const inputs={ads:['8.8.8.8','a.com','shared.com'],analytics:['2606:4700:4700::1111','b.com','shared.com'],malware:['mal.com','phish.com'],phishing:['phish.com'],tor:['1.1.1.1']};
  const categories={},feeds={};
  for(const [name,lines]of Object.entries(inputs)){await writeFile(join(directory,name+'.txt'),lines.join('\n')+'\n');const ips=lines.filter(x=>x.includes(':')||/^[\d.]+$/.test(x)).length;categories[name]={total:lines.length,domains:lines.length-ips,ips};}
  const groups=await writeCategoryGroupFeeds({directory,categories,feeds});
  assert.deepEqual(Object.keys(groups),['ads-tracking','threats']);assert.deepEqual(groups['ads-tracking'].categories,['ads','analytics']);
  assert.deepEqual([groups['ads-tracking'].total,groups['ads-tracking'].domains,groups['ads-tracking'].ips],[5,3,2]);
  const combined='2606:4700:4700::1111\n8.8.8.8\na.com\nb.com\nshared.com\n';
  assert.equal(await readFile(join(directory,'groups/ads-tracking.txt'),'utf8'),combined);assert.equal(feeds['groups/ads-tracking'].sha256,sha256(combined));
  assert.equal(await readFile(join(directory,'groups/ads-tracking.domains.txt'),'utf8'),'a.com\nb.com\nshared.com\n');assert.equal(await readFile(join(directory,'groups/ads-tracking.ips.txt'),'utf8'),'2606:4700:4700::1111\n8.8.8.8\n');
  assert.equal(await readFile(join(directory,'groups/threats.txt'),'utf8'),'mal.com\nphish.com\n');assert.equal(feeds['groups/threats'].count,2);
  await assert.rejects(access(join(directory,'groups/tor.txt')),/ENOENT/);assert(!groups.tor);assert(!feeds['groups/threats.domains']);
});
