import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,access,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {once} from 'node:events';
import {createServer} from 'node:http';
import {setTimeout as delay} from 'node:timers/promises';
import {spawnUpdate} from '../src/update-process.mjs';

test('CPU-heavy update subprocess leaves the HTTP parent responsive and reports failures',async t=>{
  const root=await mkdtemp(join(tmpdir(),'blocklist-process-'));t.after(()=>rm(root,{recursive:true,force:true}));await mkdir(join(root,'src'));
  const ready=join(root,'ready');
  await writeFile(join(root,'src','update-child.mjs'),`import {writeFileSync} from 'node:fs';writeFileSync(${JSON.stringify(ready)},'ready');const end=Date.now()+2000;while(Date.now()<end){};`);
  const server=createServer((_req,res)=>res.end('available'));server.listen(0,'127.0.0.1');await once(server,'listening');t.after(()=>new Promise(resolve=>server.close(resolve)));
  let ended=false;const updating=spawnUpdate({root,directory:join(root,'output')}).then(()=>{ended=true;});
  for(let i=0;i<200;i++){try{await access(ready);break;}catch{await delay(10);}}
  await access(ready);const before=Date.now(),response=await fetch(`http://127.0.0.1:${server.address().port}`);assert.equal(await response.text(),'available');assert(Date.now()-before<1000);assert.equal(ended,false);await updating;
  await writeFile(join(root,'src','update-child.mjs'),'process.exitCode=7;');await assert.rejects(spawnUpdate({root,directory:join(root,'output')}),/exited 7/);
});
