import {statfs} from 'node:fs/promises';
const GiB=1024**3;
export function requiredBuildBytes(manifest){
  const output=Object.values(manifest?.feeds||{}).reduce((sum,feed)=>sum+(feed.bytes||0),0);
  return Math.max(5*GiB,output+2*GiB);
}
export async function ensureBuildSpace(directory,manifest,{statfsImpl=statfs}={}){
  const info=await statfsImpl(directory),available=Number(info.bavail)*Number(info.bsize),required=requiredBuildBytes(manifest);
  if(available<required)throw Error(`Insufficient disk space for a safe update (${(available/GiB).toFixed(1)} GiB free; ${(required/GiB).toFixed(1)} GiB required); previous snapshot retained`);
  return {available,required};
}
