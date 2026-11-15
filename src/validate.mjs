import { readFile } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { join,resolve,relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { normalize } from './parser.mjs';
import { publicFiles } from './verify-output.mjs';
import {documentationFiles,renderPublicDocumentation} from './public-docs.mjs';

const asciiDomain=/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const reserved=new Set(['localhost','local','internal','invalid','test','example','home','arpa']);
export function normalizedKind(line){
  if(line.includes(':')||/^[\d.]+$/.test(line))return normalize(line)===line&&isIP(line)?'ips':null;
  if(line.length>253||!asciiDomain.test(line))return null;
  const suffix=line.slice(line.lastIndexOf('.')+1);if(reserved.has(suffix)||/^\d+$/.test(suffix))return null;
  if(line.includes('xn--')&&normalize(line)!==line)return null;
  return 'domains';
}

export async function validate(directory){
  const stats=JSON.parse(await readFile(join(directory,'stats.json'),'utf8'));let count=0;const verifiedHashes=new Map();
  for(const path of await publicFiles(directory)){
    if(!path.endsWith('.txt'))continue;
    const file=relative(directory,path).replaceAll('\\','/'),expected=stats.feeds[file.slice(0,-4)];
    if(file==='robots.txt')continue;
    if(stats.documentation&&Object.values(documentationFiles).includes(file))continue;
    if(!expected)throw Error(`${file}: not declared in manifest`);
    const hash=createHash('sha256'),stream=createReadStream(path,{highWaterMark:1024*1024}),prior=verifiedHashes.get(expected.sha256);
    let previous='',total=0,domains=0,ips=0,lastByte=null,bytes=0,carry='';
    for await(const chunk of stream){
      hash.update(chunk);bytes+=chunk.length;lastByte=chunk.at(-1);
      if(prior)continue;
      const text=carry+chunk.toString('utf8');let start=0,next;
      while((next=text.indexOf('\n',start))!==-1){
        const line=text.slice(start,next);start=next+1;total++;const kind=normalizedKind(line);
        if(!kind)throw Error(`${file}: invalid entry at line ${total}`);
        if(previous&&previous>=line)throw Error(`${file}: unsorted or duplicate at line ${total}`);
        previous=line;kind==='ips'?ips++:domains++;
      }
      carry=text.slice(start);if(carry.length>253)throw Error(`${file}: oversized entry`);
    }
    if(prior)({total,domains,ips}=prior);
    if(bytes&&lastByte!==10)throw Error(`${file}: missing final newline`);
    if(expected.sha256!==hash.digest('hex')||expected.count!==total||expected.domains!==domains||expected.ips!==ips||expected.bytes!==bytes)throw Error(`${file}: manifest mismatch`);
    verifiedHashes.set(expected.sha256,{total,domains,ips});
    count++;
  }
  if(count!==Object.keys(stats.feeds).length)throw Error('Missing output file');
  if(stats.totals.total!==stats.totals.domains+stats.totals.ips)throw Error('Totals do not reconcile');
  for(const s of stats.sources)if(s.domains!==s.uniqueDomains+s.sharedDomains||s.ips!==s.uniqueIPs+s.sharedIPs)throw Error(`${s.id}: overlap does not reconcile`);
  for(const [name,category]of Object.entries(stats.categories)){
    const feed=stats.feeds[name];if(feed.count!==category.total||feed.domains!==category.domains||feed.ips!==category.ips)throw Error(`${name}: category totals do not reconcile`);
    if(category.statisticsUrl){const detail=JSON.parse(await readFile(join(directory,category.statisticsUrl),'utf8'));if(detail.sources.length!==stats.sources.length||detail.matrix.length!==stats.sources.length)throw Error(`${name}: invalid overlap statistics`);}
  }
  if(stats.bundles){
    const seen=new Set();
    for(const [group,bundle]of Object.entries(stats.bundles)){
      const feed=stats.feeds[bundle.feed];if(feed.domains!==bundle.domains||feed.ips!==bundle.ips)throw Error(`${group}: bundle totals do not reconcile`);
      for(const name of bundle.categories){if(seen.has(name)||stats.categories[name]?.group!==group||!stats.categories[name].total)throw Error(`${group}: incorrect category membership`);seen.add(name);}
    }
    if(Object.entries(stats.categories).some(([name,c])=>c.total&&!seen.has(name)))throw Error('A populated category is missing from both bundles');
    if(stats.feeds.combined.sha256!==stats.feeds.protection.sha256)throw Error('Default feed differs from the protection bundle');
  }
  if(stats.documentation)await validateDocumentation(directory,stats);
  for(const [id,group]of Object.entries(stats.groups||{})){
    const expected=Object.keys(stats.categories).filter(name=>stats.categories[name].total&&stats.categories[name].section===id);
    if(expected.length<2||JSON.stringify(group.categories)!==JSON.stringify(expected))throw Error(`${id}: invalid combined category membership`);
    const feed=stats.feeds[group.feed];if(!feed||feed.count!==group.total||feed.domains!==group.domains||feed.ips!==group.ips)throw Error(`${id}: group totals do not reconcile`);
    if(group.statisticsUrl){const detail=JSON.parse(await readFile(join(directory,group.statisticsUrl),'utf8'));if(detail.sources.length!==stats.sources.length||detail.matrix.length!==stats.sources.length)throw Error(`${id}: invalid combined statistics`);}
  }
  console.log(`Validated ${count} plain-text feeds and category statistics.`);
}
export async function validateDocumentation(directory,stats){
  const {access}=await import('node:fs/promises');
  const {sep}=await import('node:path');
  if(JSON.stringify(stats.documentation)!==JSON.stringify(documentationFiles))throw Error('Unrecognized public documentation paths');
  for(const [name,expected]of Object.entries(renderPublicDocumentation(stats))){
    const actual=await readFile(join(directory,name),'utf8');if(actual!==expected)throw Error(`${name}: documentation differs from the current snapshot`);
    for(const match of actual.matchAll(/\]\(<([^>]+)>\)/g)){
      const target=match[1];if(/^https?:\/\//.test(target))continue;
      const path=resolve(directory,target);if(!path.startsWith(resolve(directory)+sep))throw Error(`${name}: documentation link leaves the public output`);
      await access(path);
    }
  }
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))validate(resolve(process.argv[2]||'dist')).catch(error=>{console.error(error.message);process.exitCode=1;});
