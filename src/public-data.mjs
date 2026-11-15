export function publicSourceReports(reports,counts){
  const accepted=new Map(counts.map(s=>[s.id,s]));
  const seen=new Set();
  return reports.filter(s=>s.selected!==false&&!s.duplicateOf&&s.state!=='duplicate'&&accepted.has(s.id)&&!seen.has(s.id)&&seen.add(s.id)).map(s=>{
    const c=accepted.get(s.id);
    return {id:s.id,name:s.name,provider:s.provider,category:s.category,additionalCategories:s.additionalCategories||[],domains:c.domains,ips:c.ips,total:c.total,updatedAt:s.updatedAt,state:s.state,
      homepage:s.homepage,upstreamUrl:s.upstreamUrl,license:s.license,provenance:s.provenance?.startsWith('https://')?s.provenance:null,normalizedFeed:s.normalizedFeed};
  });
}
export function publicManifest(snapshot){
  const {coverage,sourceReports,policy,...data}=snapshot;
  return applyTaxonomy({...data,policy:{maxAgeDays:policy.maxAgeDays,updateIntervalMinutes:policy.updateIntervalMinutes,selectedPrimary:policy.selectedPrimary},sourceReports:publicSourceReports(sourceReports,snapshot.sources)});
}
import {applyTaxonomy} from './category-taxonomy.mjs';
