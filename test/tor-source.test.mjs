import test from 'node:test';
import assert from 'node:assert/strict';
import {parseTorSummary} from '../src/tor-source.mjs';
test('official Tor summaries extract public IPs only from running relays, preserve the consensus timestamp and reject unknown schemas',()=>{
  const data={version:'8.0',relays_published:'2026-11-14 17:00:00',relays:[{r:true,a:['8.8.8.8','[2606:4700:4700::1111]','10.0.0.1','invalid.com']},{r:false,a:['1.1.1.1']},{r:true,a:['8.8.8.8']}],bridges:[{r:true,a:['9.9.9.9']}]};
  const parsed=parseTorSummary(JSON.stringify(data));assert.deepEqual(parsed.block,['2606:4700:4700::1111','8.8.8.8']);assert.equal(parsed.publishedAt,'2026-11-14T17:00:00Z');assert.equal(parsed.rejected,2);
  assert.throws(()=>parseTorSummary(JSON.stringify({...data,version:'9.0'})),/Unsupported/);assert.throws(()=>parseTorSummary(JSON.stringify({...data,relays_published:'2026-02-30 17:00:00'})),/Invalid/);
});
