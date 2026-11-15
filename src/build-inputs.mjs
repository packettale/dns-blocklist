import {createHash} from 'node:crypto';
import {categoryGroup} from './category-policy.mjs';
import {categoryInfo} from './category-taxonomy.mjs';
import {normalize} from './parser.mjs';
import {sha256} from './io.mjs';

export function normalizedDigest(parsed){
  const hash=createHash('sha256');
  const add=(name,values)=>{hash.update(JSON.stringify(name)+'\n');for(let i=0;i<values.length;i+=8192)hash.update(values.slice(i,i+8192).join('\n')+'\n');hash.update('\0');};
  add('block',parsed.block);add('allow',parsed.allow||[]);
  for(const name of Object.keys(parsed.categories||{}).sort())add(name,parsed.categories[name]);
  return hash.digest('hex');
}
export function buildFingerprint({loaded,localAllows,suffixText}){
  const names=new Set();
  const inputs=loaded.map(item=>{const source=item.source,category=source.category||'categorized';for(const name of [category,...(source.additionalCategories||[]),...(item.normalizedCategories||[])])if(name)names.add(name);return {id:source.id,category,additionalCategories:[...(source.additionalCategories||[])].sort(),normalizedHash:item.normalizedHash};});
  const allow=[...new Set(localAllows.map(value=>{const exact=value.startsWith('='),name=normalize(exact?value.slice(1):value);return name?(exact?'=':'')+name:null;}).filter(Boolean))].sort();
  const suffixes=[...new Set(suffixText.split(/\r?\n/).map(line=>line.trim()).filter(line=>line&&!line.startsWith('//')))].sort();
  const policy=[...names].sort().map(name=>[name,categoryGroup(name),categoryInfo(name).section]);
  return sha256(JSON.stringify({schema:1,inputs,allow,suffixes,policy}));
}
