import {isIP} from 'node:net';

export function isBrowserNavigation(req){
  return req.headers['sec-fetch-mode']==='navigate'&&['document','empty'].includes(req.headers['sec-fetch-dest']);
}

export function clientAddress(req){
  const remote=req.socket.remoteAddress||'unknown';
  if(['127.0.0.1','::1','::ffff:127.0.0.1'].includes(remote)){
    const forwarded=req.headers['cf-connecting-ip'];
    if(typeof forwarded==='string'&&isIP(forwarded))return forwarded;
  }
  return remote.startsWith('::ffff:')&&isIP(remote.slice(7))===4?remote.slice(7):remote;
}

export class FeedRateLimit {
  constructor({seconds=300,maxEntries=50000,now=Date.now}={}){
    if(!Number.isInteger(seconds)||seconds<1)throw Error('Invalid feed refresh interval');
    this.seconds=seconds;this.maxEntries=maxEntries;this.now=now;this.entries=new Map();this.nextSweep=0;
  }
  check(ip,feed,method){
    const now=this.now(),key=JSON.stringify([ip,feed]);
    if(now>=this.nextSweep){for(const [key,value]of this.entries)if(value.until<=now)this.entries.delete(key);this.nextSweep=now+30000;}
    let record=this.entries.get(key);
    if(!record||record.until<=now){
      if(this.entries.size>=this.maxEntries)this.entries.delete(this.entries.keys().next().value);
      record={until:now+this.seconds*1000,GET:false,HEAD:false};this.entries.set(key,record);
    }
    const retryAfter=Math.max(1,Math.ceil((record.until-now)/1000));
    if(record[method])return {allowed:false,retryAfter};
    record[method]=true;return {allowed:true,retryAfter};
  }
}
