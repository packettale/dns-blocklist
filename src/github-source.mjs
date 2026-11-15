const ageDays=(date,now)=>(now-Date.parse(date))/86400000;
const recent=(date,now,days)=>Number.isFinite(ageDays(date,now))&&ageDays(date,now)>=-1&&ageDays(date,now)<=days;

export function mullvadCatalogIncludes(text,{entry,path,type}){
  const body=text.split(/^dns_blocklists_lists:\s*$/m)[1];if(!body)return false;
  const records=body.split(/(?=^  - name:)/m).filter(block=>block.match(/^  - name: ([a-z0-9-]+)\s*$/m)?.[1]===entry);
  if(records.length!==1)return false;
  const file=records[0].match(/^    content: "\{\{ lookup\('ansible\.builtin\.file', '([^']+)'\) \}\}"\s*$/m)?.[1];
  const category=records[0].match(/^    type: ([a-z0-9-]+)\s*$/m)?.[1];
  return file===path&&category===type;
}

export function createGitHubEligibility({downloader,checkRepository,now,maxAgeDays}){
  const catalogs=new Map();
  async function revision(repo,path){
    const commits=JSON.parse((await downloader.get(`https://api.github.com/repos/${repo}/commits?path=${encodeURIComponent(path)}&per_page=1`,{maxBytes:1000000})).text);
    const commit=commits[0];if(!commit?.sha||!commit?.commit?.committer?.date)throw Error('No revision found for this exact source file');return commit;
  }
  return async source=>{
    const {repo,path}=source.githubPath;
    const [commit,repository]=await Promise.all([revision(repo,path),checkRepository(repo)]);
    if(repository.archived||repository.disabled)throw Error('Repository is archived or disabled');
    const date=commit.commit.committer.date;
    if(!Number.isFinite(ageDays(date,now))||ageDays(date,now)<-1)throw Error('Invalid or future source revision timestamp');
    if(source.maintenanceCatalog){
      const catalog=source.maintenanceCatalog;
      if(repo!=='mullvad/dns-blocklists'||catalog.path!=='inventory/group_vars/all.yml'||!/^files\/(?:adblock|tracker|malware|adult|social)$/.test(path))throw Error('Unsupported provider maintenance evidence');
      if(!catalogs.has(catalog.path))catalogs.set(catalog.path,(async()=>{
        const current=await revision(repo,catalog.path);
        if(!recent(current.commit.committer.date,now,maxAgeDays))throw Error('Provider source inventory is stale or has an invalid timestamp');
        const result=await downloader.get(`https://raw.githubusercontent.com/${repo}/${current.sha}/${catalog.path}`,{maxBytes:1000000});
        return {commit:current,text:result.text};
      })());
      const current=await catalogs.get(catalog.path);
      if(!mullvadCatalogIncludes(current.text,{entry:catalog.entry,path,type:catalog.type}))throw Error('Source is absent from the current provider inventory or its classification changed');
      return {...source,eligible:true,updatedAt:date,version:commit.sha,activeEvidence:current.commit.html_url,statusPolicy:'Official non-archived repository; recently maintained provider inventory explicitly includes this exact file and category. Source date is its own last content revision.'};
    }
    if(!recent(date,now,source.maxAgeDays||maxAgeDays))throw Error(`Upstream file has not changed recently: ${date}`);
    return {...source,eligible:true,updatedAt:date,version:commit.sha,activeEvidence:commit.html_url,statusPolicy:'Official non-archived repository and recent revision of the exact source file'};
  };
}
