import test from 'node:test';
import assert from 'node:assert/strict';
import {publicManifest} from '../src/public-data.mjs';
test('public data contains included sources once and never exports private review records',()=>{
  const source={id:'included',name:'Included',domains:1,ips:0,total:1};
  const output=publicManifest({schemaVersion:2,policy:{updateIntervalMinutes:5,maxAgeDays:30,selectedPrimary:1,selection:'private-review'},coverage:{excluded:1,reason:'private-review'},sources:[source],sourceReports:[
    {...source,selected:true,state:'current',note:'private-review',reason:'private-review',trustEvidence:'private-review',updatedAt:'2026-11-14T00:00:00Z'},
    {...source,selected:true,state:'duplicate',duplicateOf:'included',note:'private-review'},
    {id:'rejected-private-record',selected:false,state:'excluded',reason:'private-review'},
  ]});
  assert.equal(output.sourceReports.length,1);assert.equal(output.sourceReports[0].id,'included');assert.equal(output.coverage,undefined);
  assert(!JSON.stringify(output).includes('private-review'));assert(!JSON.stringify(output).includes('rejected-private-record'));
  assert.deepEqual(publicManifest(output),output);
});
