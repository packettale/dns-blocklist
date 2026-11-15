import {isIP} from 'node:net';
import {normalize} from './parser.mjs';

export function parseTorSummary(text){
  const data=JSON.parse(text);
  if(!/^8\./.test(data.version||'')||!Array.isArray(data.relays)||!/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(data.relays_published||''))throw Error('Unsupported official Tor summary');
  const publishedAt=data.relays_published.replace(' ','T')+'Z';
  if(!Number.isFinite(Date.parse(publishedAt))||new Date(publishedAt).toISOString().slice(0,19).replace('T',' ')!==data.relays_published)throw Error('Invalid Tor consensus timestamp');
  const entries=new Set();let rejected=0;
  for(const relay of data.relays){
    if(relay.r!==true||!Array.isArray(relay.a))continue;
    for(const address of relay.a){const candidate=typeof address==='string'&&address.startsWith('[')&&address.endsWith(']')?address.slice(1,-1):address;const value=typeof candidate==='string'&&isIP(candidate)?normalize(candidate):null;if(value)entries.add(value);else rejected++;}
  }
  return {block:[...entries].sort(),allow:[],rejected,publishedAt,licenseText:'Tor Metrics public data: CC0, https://metrics.torproject.org/about.html'};
}
