import test from 'node:test';
import assert from 'node:assert/strict';
import {categoryInfo,applyTaxonomy,taxonomySections} from '../src/category-taxonomy.mjs';
test('threats, NSFW, Tor and mixed policies never fall through to normal services',()=>{
  assert.deepEqual(categoryInfo('adult'),{label:'Pornography',section:'nsfw',kind:'content'});
  assert.equal(categoryInfo('violence').section,'nsfw');assert.equal(categoryInfo('malware').section,'threats');assert.equal(categoryInfo('phishing').section,'threats');
  assert.equal(categoryInfo('tor').section,'tor');assert.equal(categoryInfo('malware-and-support').section,'advanced');
  for(const id of ['newly-registered-domains','dga','attacking-ips','risk','typosquatting','badware-hosting'])assert.equal(categoryInfo(id).section,'risk',id);
  for(const id of ['ai','dating','social','remote-access','dns-resolvers','cryptocurrency','big-tech-google','vpn-proxy'])assert.deepEqual([categoryInfo(id).section,categoryInfo(id).kind],['services','service'],id);
  assert.equal(categoryInfo('new-unreviewed-category').section,'other');assert.equal(categoryInfo('new-unreviewed-category').kind,'unclassified');
});
test('taxonomy adds explicit labels without changing counts or default bundle membership',()=>{
  const snapshot={categories:{adult:{total:5,domains:5,ips:0},malware:{total:3,domains:2,ips:1},tor:{total:2,domains:0,ips:2}},bundles:{protection:{categories:['malware']}}};
  const result=applyTaxonomy(snapshot);assert.equal(result.categories.adult.total,5);assert.equal(result.categories.malware.ips,1);assert.equal(result.categories.tor.section,'tor');assert.deepEqual(result.bundles,snapshot.bundles);assert.deepEqual(result.taxonomy,taxonomySections);assert.deepEqual(applyTaxonomy(result),result);
});
