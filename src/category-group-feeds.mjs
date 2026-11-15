import {createReadStream} from 'node:fs';
import {mkdir,open,rename,access} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {taxonomySections,categoryInfo} from './category-taxonomy.mjs';

async function portableMerge(paths,target){
  const readers=paths.map(path=>createInterface({input:createReadStream(path),crlfDelay:Infinity}));
  const iterators=readers.map(reader=>reader[Symbol.asyncIterator]());
  const current=await Promise.all(iterators.map(iterator=>iterator.next()));
  const out=await open(target,'w');let previous='',buffer=[];
  try{
    while(true){
      let selected=-1;for(let i=0;i<current.length;i++)if(!current[i].done&&(selected===-1||current[i].value<current[selected].value))selected=i;
      if(selected===-1)break;
      const value=current[selected].value;if(value!==previous){buffer.push(value);previous=value;}
      if(buffer.length>=8192){await out.writeFile(buffer.join('\n')+'\n');buffer=[];}
      current[selected]=await iterators[selected].next();
    }
    if(buffer.length)await out.writeFile(buffer.join('\n')+'\n');
  }finally{for(const reader of readers)reader.close();await out.close();}
}
async function merge(paths,target){
  const binary=process.platform==='win32'?'C:/Program Files/Git/usr/bin/sort.exe':'/usr/bin/sort';
  try{await access(binary);}catch{return portableMerge(paths,target);}
  await new Promise((resolve,reject)=>{
    const child=spawn(binary,['-m','-u','-o',target,'--',...paths],{env:{...process.env,LC_ALL:'C'},stdio:['ignore','ignore','pipe'],windowsHide:true});
    let error='';child.stderr.on('data',chunk=>{error+=chunk.toString().slice(0,1000);});child.once('error',reject);child.once('exit',code=>code===0?resolve():reject(Error(`Category merge failed (${code}): ${error}`)));
  });
}
function meter(){return {count:0,domains:0,ips:0,bytes:0,hash:createHash('sha256')};}
function finish(value,url){const {hash,...counts}=value;return {...counts,sha256:hash.digest('hex'),url};}
export async function writeCategoryGroupFeeds({directory,categories,feeds}){
  await mkdir(join(directory,'groups'),{recursive:true});const groups={};
  for(const section of taxonomySections){
    const members=Object.keys(categories).filter(id=>categories[id].total&&categoryInfo(id).section===section.id);
    if(members.length<2)continue;
    const name=`groups/${section.id}`,target=join(directory,`${name}.txt`),temp=target+'.tmp';
    await merge(members.map(id=>join(directory,`${id}.txt`)),temp);
    const combined=meter(),onlyDomains=members.every(id=>!categories[id].ips),onlyIPs=members.every(id=>!categories[id].domains);
    if(onlyDomains||onlyIPs){
      for await(const chunk of createReadStream(temp,{highWaterMark:1024*1024})){combined.hash.update(chunk);combined.bytes+=chunk.length;let index=-1;while((index=chunk.indexOf(10,index+1))!==-1)combined.count++;}
      combined[onlyDomains?'domains':'ips']=combined.count;
    }else{
      const typed={domains:meter(),ips:meter()},handles={domains:await open(target+'.domains.tmp','w'),ips:await open(target+'.ips.tmp','w')};let carry='';
      try{
        for await(const chunk of createReadStream(temp,{highWaterMark:1024*1024})){
          combined.hash.update(chunk);combined.bytes+=chunk.length;const lines=(carry+chunk.toString('utf8')).split('\n');carry=lines.pop();const rows={domains:[],ips:[]};
          for(const line of lines){const kind=line.includes(':')||/^[\d.]+$/.test(line)?'ips':'domains';rows[kind].push(line);combined.count++;combined[kind]++;typed[kind].count++;typed[kind][kind]++;}
          for(const kind of ['domains','ips'])if(rows[kind].length){const text=rows[kind].join('\n')+'\n';typed[kind].hash.update(text);typed[kind].bytes+=Buffer.byteLength(text);await handles[kind].writeFile(text);}
        }
        if(carry)throw Error('Category group input is missing a final newline');
      }finally{await handles.domains.close();await handles.ips.close();}
      for(const kind of ['domains','ips']){const key=`${name}.${kind}`;await rename(target+`.${kind}.tmp`,join(directory,`${key}.txt`));feeds[key]=finish(typed[kind],`${key}.txt`);}
    }
    await rename(temp,target);feeds[name]=finish(combined,`${name}.txt`);feeds[name].categories=members;
    for(const kind of ['domains','ips'])if(feeds[`${name}.${kind}`])feeds[`${name}.${kind}`].categories=members.filter(id=>categories[id][kind]>0);
    groups[section.id]={label:section.label,feed:name,categories:members,total:combined.count,domains:combined.domains,ips:combined.ips};
  }
  return groups;
}
