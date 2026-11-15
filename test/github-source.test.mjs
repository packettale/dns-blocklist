import test from 'node:test';
import assert from 'node:assert/strict';
import {createGitHubEligibility,mullvadCatalogIncludes} from '../src/github-source.mjs';

const inventory=`---\ndns_blocklists_lists:\n  - name: mullvad-ads-blocklist\n    type: adblock\n    content: "{{ lookup('ansible.builtin.file', 'files/adblock') }}"\n`;
const source={id:'mullvad-adblock',category:'ads',githubPath:{repo:'mullvad/dns-blocklists',path:'files/adblock'},maintenanceCatalog:{path:'inventory/group_vars/all.yml',entry:'mullvad-ads-blocklist',type:'adblock'}};
function setup({catalog=inventory,days=2,archived=false,fileDays=100}={}){
  const now=Date.parse('2026-11-15T00:00:00Z'),calls=[];
  const downloader={async get(url){calls.push(url);if(url.includes('/commits?')){const isCatalog=url.includes('inventory%2F');return {text:JSON.stringify([{sha:isCatalog?'catalog-revision':'file-revision',html_url:'https://github.com/mullvad/dns-blocklists/commit/review',commit:{committer:{date:new Date(now-(isCatalog?days:fileDays)*86400000).toISOString()}}}])};}return {text:catalog};}};
  return {check:createGitHubEligibility({downloader,checkRepository:async()=>({archived,disabled:false}),now,maxAgeDays:30}),calls};
}
test('stable provider lists require an exact enabled file and category in the maintained inventory',()=>{
  const entry={entry:'mullvad-ads-blocklist',path:'files/adblock',type:'adblock'};
  assert(mullvadCatalogIncludes(inventory,entry));
  assert(!mullvadCatalogIncludes(inventory,{...entry,path:'files/tracker'}));
  assert(!mullvadCatalogIncludes(inventory,{...entry,type:'social'}));
  assert(!mullvadCatalogIncludes(inventory.replace('dns_blocklists_lists:','disabled:'),entry));
  assert(!mullvadCatalogIncludes(inventory+inventory.split('dns_blocklists_lists:\n')[1],entry));
});
test('stable custom files preserve their own revision while current provider evidence is shared across concurrent checks',async()=>{
  const {check,calls}=setup();const results=await Promise.all([check(source),check(source)]);
  assert(results.every(result=>result.eligible&&result.version==='file-revision'));
  assert(results.every(result=>result.updatedAt==='2026-08-07T00:00:00.000Z'));
  assert.equal(calls.filter(url=>url.includes('inventory%2F')).length,1);
  assert.equal(calls.filter(url=>url.includes('raw.githubusercontent.com')).length,1);
});
test('stale, future, archived, removed or reclassified provider inventories cannot authorize stable files',async()=>{
  for(const options of [{days:31},{days:-2},{archived:true},{catalog:inventory.replace('mullvad-ads-blocklist','removed-list')},{catalog:inventory.replace('type: adblock','type: social')}])await assert.rejects(()=>setup(options).check(source));
  await assert.rejects(()=>setup().check({...source,githubPath:{repo:'other/repo',path:'files/adblock'}}),/Unsupported/);
  await assert.rejects(()=>setup().check({...source,maintenanceCatalog:undefined}),/not changed recently/);
  const recent=await setup({fileDays:1}).check({...source,maintenanceCatalog:undefined});assert(recent.eligible);
});
