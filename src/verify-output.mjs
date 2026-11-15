import { createReadStream } from 'node:fs';
import { readdir, rm, stat } from 'node:fs/promises';
import { join, relative } from 'node:path';
import {documentationFiles} from './public-docs.mjs';

export async function publicFiles(directory) {
  const files=[];
  for(const entry of await readdir(directory,{withFileTypes:true})){
    const path=join(directory,entry.name);
    if(entry.isDirectory())files.push(...await publicFiles(path));
    else if(entry.isFile())files.push(path);
    else throw Error('Public output contains a symlink or unsupported file');
  }
  return files;
}
export async function scanPublicSecret(directory,secret){
  for(const path of await publicFiles(directory)){
    let tail='';
    for await(const chunk of createReadStream(path,{encoding:'utf8'})){
      const text=tail+chunk;if(text.includes(secret))throw Error('Public output failed the secret check; publication blocked');
      tail=text.slice(-(secret.length-1));
    }
  }
}
export async function pruneFeeds(directory,feeds){
  const expected=new Set(Object.keys(feeds).map(n=>`${n}.txt`));
  expected.add('robots.txt');
  for(const file of Object.values(documentationFiles))expected.add(file);
  for(const path of await publicFiles(directory))if(path.endsWith('.txt')&&!expected.has(relative(directory,path).replaceAll('\\','/')))await rm(path);
}
export async function hostingReport(directory){
  const files=await publicFiles(directory),sizes=await Promise.all(files.map(async path=>({path:relative(directory,path).replaceAll('\\','/'),bytes:(await stat(path)).size})));
  return {bytes:sizes.reduce((sum,f)=>sum+f.bytes,0),files:sizes.length,overGitFileLimit:sizes.filter(f=>f.bytes>100*1024*1024),overPagesSiteLimit:sizes.reduce((sum,f)=>sum+f.bytes,0)>1024*1024*1024};
}
