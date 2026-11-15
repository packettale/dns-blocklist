import {spawn} from 'node:child_process';
import {join} from 'node:path';

export function spawnUpdate({root,directory,baselineDirectory='',resultPath=join(root,'.cache','update-result.json'),onChild,spawnImpl=spawn}){
  return new Promise((resolve,reject)=>{
    const child=spawnImpl(process.execPath,[join(root,'src','update-child.mjs'),directory,baselineDirectory,resultPath],{cwd:root,env:process.env,stdio:'inherit',windowsHide:true});
    onChild?.(child);
    child.once('error',reject);
    child.once('exit',(code,signal)=>code===0?resolve():reject(Error(`Update subprocess exited ${signal||code}`)));
  });
}
