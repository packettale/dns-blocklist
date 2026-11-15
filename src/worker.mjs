import {mkdir,readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {validate} from './validate.mjs';
import {SnapshotStore} from './snapshots.mjs';
import {writeJson,jsonFile} from './io.mjs';
import {spawnUpdate} from './update-process.mjs';
import {nextDailyCheck,reserveDailyCheck} from './daily-schedule.mjs';

const root=process.cwd(),store=new SnapshotStore({root,validate});
let stopping=false,wake,child;
await store.initialize();
const statusFile=join(root,'.cache','worker-status.json');
const scheduleFile=join(root,'.cache','daily-schedule.json'),resultPath=join(root,'.cache','update-result.json');
const previousStatus=await jsonFile(statusFile,{});
let schedule=await jsonFile(scheduleFile);
if(!schedule){schedule={lastCheckAt:previousStatus.lastAttemptAt||null,nextCheckAt:new Date(nextDailyCheck(previousStatus)).toISOString()};await writeJson(scheduleFile,schedule);}
let status={...previousStatus,startedAt:new Date().toISOString(),state:'starting'};
async function record(update){status={...status,...update,publishedAt:store.active.manifest?.publishedAt||null};await writeJson(statusFile,status);}
function stop(){stopping=true;wake?.();child?.kill('SIGTERM');}
process.on('SIGINT',stop);process.on('SIGTERM',stop);
while(!stopping){
  const due=nextDailyCheck(schedule);
  if(due>Date.now()){
    await record({state:'waiting',nextCheckAt:new Date(due).toISOString()});
    await new Promise(accept=>{const timer=setTimeout(accept,due-Date.now());wake=()=>{clearTimeout(timer);accept();};});wake=undefined;continue;
  }
  const started=Date.now();
  try{
    await mkdir(join(root,'.cache'),{recursive:true});
    schedule=reserveDailyCheck(started);await writeJson(scheduleFile,schedule);
    await record({state:'updating',lastAttemptAt:new Date(started).toISOString(),nextCheckAt:schedule.nextCheckAt});
    const target=await store.target();
    await spawnUpdate({root,directory:target.directory,baselineDirectory:store.active.directory,resultPath,onChild:value=>{child=value;}});child=undefined;
    if(stopping)break;
    const result=await jsonFile(resultPath);if(result?.target!==target.directory)throw Error('Update result does not match the staging directory');
    let changed=false;
    if(result.outcome==='built'){
      const manifest=JSON.parse(await readFile(join(target.directory,'stats.json'),'utf8'));
      if(result.inputFingerprint!==manifest.inputFingerprint)throw Error('Update result fingerprint mismatch');
      changed=await store.commit(target,manifest);
    }else if(result.outcome!=='unchanged'||result.inputFingerprint!==store.active.manifest?.inputFingerprint)throw Error('Unchanged check does not match the active snapshot');
    await record({state:'waiting',lastSuccessAt:new Date().toISOString(),durationSeconds:(Date.now()-started)/1000,changed,error:null});
    console.log(`Update cycle completed in ${((Date.now()-started)/1000).toFixed(1)}s; snapshot ${changed?'activated':'unchanged'}.`);
  }catch(error){if(stopping)break;await record({state:'failed',lastFailureAt:new Date().toISOString(),error:error.message});console.error('Update failed; previous snapshot retained: '+error.message);}
}
