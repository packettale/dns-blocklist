import {createServer} from 'node:http';
import {open} from 'node:fs/promises';
import {resolve,sep,extname} from 'node:path';
import {documentationFiles} from './public-docs.mjs';
import {FeedRateLimit,clientAddress,isBrowserNavigation} from './feed-rate-limit.mjs';
const mime={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json; charset=utf-8','.txt':'text/plain; charset=utf-8','.md':'text/markdown; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon','.xml':'application/xml; charset=utf-8'};
const assets=new Set(['index.html','app.js','style.css','stats.json','sources.json','NOTICE.md','packettale-icon.svg','packettale-logo.png','packettale-wordmark.svg','favicon.ico','robots.txt','sitemap.xml',...Object.values(documentationFiles)]);
export function createFeedServer({getSnapshot,publicHostname='',requireHttps=false,feedRefreshSeconds=0}){
  if(publicHostname&&!/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/.test(publicHostname))throw Error('Invalid public hostname');
  const limiter=feedRefreshSeconds?new FeedRateLimit({seconds:feedRefreshSeconds}):null;
  return createServer({headersTimeout:15000,requestTimeout:30000,keepAliveTimeout:5000,maxHeaderSize:16384},async(req,res)=>{
    const loopback=['127.0.0.1','::1','::ffff:127.0.0.1'].includes(req.socket.remoteAddress);
    const forwarded=loopback?req.headers['x-forwarded-proto']:undefined;
    const secure=forwarded==='https';
    res.setHeader('X-Content-Type-Options','nosniff');
    res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
    res.setHeader('X-Frame-Options','DENY');
    res.setHeader('Referrer-Policy','no-referrer');
    res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=(), payment=()');
    if(requireHttps&&publicHostname&&forwarded!==undefined&&!secure){
      const path=req.url.startsWith('/')&&!req.url.startsWith('//')?req.url:'/';
      res.writeHead(308,{'Location':`https://${publicHostname}${path}`,'Cache-Control':'no-store'});res.end();return;
    }
    if(secure)res.setHeader('Strict-Transport-Security','max-age=31536000');
    if(!['GET','HEAD'].includes(req.method)){res.writeHead(405,{'Allow':'GET, HEAD'});res.end();return;}
    let handle;
    try{
      const {directory,manifest}=getSnapshot();if(!manifest)throw Error('Not ready');
      const pathname=decodeURIComponent(new URL(req.url,'http://localhost').pathname),name=pathname==='/'?'index.html':pathname.slice(1);
      const allowed=assets.has(name)||name.endsWith('.txt')&&manifest.feeds[name.slice(0,-4)]||name.startsWith('statistics/')&&name.endsWith('.json')&&(manifest.categories[name.slice(11,-5)]||manifest.bundles?.[name.slice(11,-5)]||name.startsWith('statistics/groups/')&&manifest.groups?.[name.slice(18,-5)]?.statisticsUrl===name);
      if(!allowed)throw Error('Not a public artifact');
      if(limiter&&!isBrowserNavigation(req)&&name.endsWith('.txt')&&manifest.feeds[name.slice(0,-4)]){
        const result=limiter.check(clientAddress(req),name,req.method);
        if(!result.allowed){res.writeHead(429,{'Content-Type':'text/plain; charset=utf-8','Cache-Control':'private, no-store','Retry-After':String(result.retryAfter)});res.end(req.method==='HEAD'?undefined:'Refresh limit exceeded. Try again after the Retry-After interval.\n');return;}
      }
      const file=resolve(directory,name);if(!file.startsWith(resolve(directory)+sep))throw Error('Outside public output');
      handle=await open(file,'r');const info=await handle.stat();if(!info.isFile())throw Error('Not a file');
      const etag='"'+(manifest.feeds[name.slice(0,-4)]?.sha256||`${info.size}-${info.mtimeMs}`)+'"';
      const headers={'Content-Type':mime[extname(file)]||'application/octet-stream','Cache-Control':'public, max-age=60, must-revalidate','ETag':etag,'Last-Modified':info.mtime.toUTCString(),'X-Content-Type-Options':'nosniff'};
      if(manifest.documentation){const prefix='../'.repeat(name.split('/').length-1);headers.Link=`<${prefix}llms.txt>; rel="describedby"`+(name==='index.html'?', <index.md>; rel="alternate"; type="text/markdown"':'');}
      if(req.headers['if-none-match']?.split(',').map(x=>x.trim().replace(/^W\//,'')).includes(etag)){res.writeHead(304,headers);res.end();await handle.close();handle=null;return;}
      res.writeHead(200,{...headers,'Content-Length':info.size});
      if(req.method==='HEAD'){res.end();await handle.close();handle=null;return;}
      const stream=handle.createReadStream();handle=null;stream.on('error',()=>res.destroy());res.on('close',()=>stream.destroy());stream.pipe(res);
    }catch{
      if(handle)await handle.close();if(!res.headersSent){res.writeHead(404,{'Content-Type':'text/plain; charset=utf-8'});res.end('Not found');}else res.destroy();
    }
  });
}
