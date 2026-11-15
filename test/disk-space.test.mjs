import test from 'node:test';
import assert from 'node:assert/strict';
import {ensureBuildSpace,requiredBuildBytes} from '../src/disk-space.mjs';
test('updates reserve room for a complete snapshot and temporary work before downloading',async()=>{
  const GiB=1024**3;
  assert.equal(requiredBuildBytes(null),5*GiB);assert.equal(requiredBuildBytes({feeds:{one:{bytes:4*GiB}}}),6*GiB);
  const statfsImpl=async()=>({bavail:4*GiB,bsize:1});await assert.rejects(ensureBuildSpace('.',null,{statfsImpl}),/previous snapshot retained/);
  assert.equal((await ensureBuildSpace('.',null,{statfsImpl:async()=>({bavail:6*GiB,bsize:1})})).required,5*GiB);
});
