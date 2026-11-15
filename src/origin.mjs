import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createFeedServer} from './http-server.mjs';

const root=process.cwd(),pointerFile=join(root,'.cache','snapshots','active.json');
let active={directory:join(root,'dist'),manifest:null},fingerprint=null,refreshing=false;
async function refresh(){
  if(refreshing)return;refreshing=true;
  try{
    let pointer;
    try{pointer=JSON.parse(await readFile(pointerFile,'utf8'));}catch(error){if(error.code!=='ENOENT')throw error;}
    if(pointer&&!['a','b'].includes(pointer.slot))throw Error('Invalid snapshot pointer');
    const next=pointer?.inputFingerprint||'bootstrap';if(active.manifest&&next===fingerprint)return;
    const directory=pointer?join(root,'.cache','snapshots',pointer.slot):join(root,'dist');
    const manifest=JSON.parse(await readFile(join(directory,'stats.json'),'utf8'));
    if(pointer&&pointer.inputFingerprint!==manifest.inputFingerprint)throw Error('Snapshot pointer mismatch');
    active={directory,manifest};fingerprint=next;
    console.log(`Serving validated snapshot ${manifest.publishedAt}.`);
  }finally{refreshing=false;}
}
await refresh();
const server=createFeedServer({getSnapshot:()=>active,publicHostname:process.env.PUBLIC_HOSTNAME||'',requireHttps:process.env.REQUIRE_HTTPS==='true',feedRefreshSeconds:Number(process.env.FEED_MIN_REFRESH_SECONDS||0)});
server.listen(Number(process.env.PORT||80),process.env.HOST||'127.0.0.1',()=>console.log('packettale origin ready.'));
const timer=setInterval(()=>refresh().catch(error=>console.error('Snapshot refresh failed; previous snapshot retained: '+error.message)),5000);
function stop(){clearInterval(timer);server.close();}
process.on('SIGINT',stop);process.on('SIGTERM',stop);
