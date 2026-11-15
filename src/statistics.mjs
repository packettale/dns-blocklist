import { isIP } from 'node:net';

export function calculateStatistics(sourceEntries, categoryEntries) {
  const entries = new Map();
  const sources = sourceEntries.map(({ source, entries: items }, index) => {
    const bit = 1n << BigInt(index);
    let domains = 0, ips = 0;
    for (const entry of new Set(items)) {
      entries.set(entry, (entries.get(entry) || 0n) | bit);
      if (isIP(entry)) ips++; else domains++;
    }
    return { id: source.id, name: source.name, role: source.role, homepage: source.homepage,
      category: source.category || 'categorized', domains, ips, total: domains + ips,
      uniqueDomains: 0, uniqueIPs: 0, sharedDomains: 0, sharedIPs: 0 };
  });
  const matrix = sources.map(() => sources.map(() => ({ domains: 0, ips: 0 })));
  const histogram = {};
  let domains = 0, ips = 0, uniqueDomains = 0, uniqueIPs = 0;
  const masks = new Map();
  for (const [entry, mask] of entries) {
    const kind = isIP(entry) ? 'ips' : 'domains';
    if (kind === 'ips') ips++; else domains++;
    const group = masks.get(mask) || { domains: 0, ips: 0 };
    group[kind]++;
    masks.set(mask, group);
  }
  // Group entries by source membership to avoid doing pairwise work for every
  // domain. A pair is counted once per entry, never once per category.
  for (const [mask, totals] of masks) {
    const members = [];
    for (let i = 0; i < sources.length; i++) if (mask & (1n << BigInt(i))) members.push(i);
    const count = members.length;
    histogram[count] ||= { domains: 0, ips: 0 };
    histogram[count].domains += totals.domains; histogram[count].ips += totals.ips;
    if (count === 1) { uniqueDomains += totals.domains; uniqueIPs += totals.ips; }
    for (const i of members) {
      sources[i][count === 1 ? 'uniqueDomains' : 'sharedDomains'] += totals.domains;
      sources[i][count === 1 ? 'uniqueIPs' : 'sharedIPs'] += totals.ips;
      for (const j of members) {
        matrix[i][j].domains += totals.domains; matrix[i][j].ips += totals.ips;
      }
    }
  }
  const categories = {};
  for (const [name, items] of Object.entries(categoryEntries)) {
    const members = new Set(items);
    // Each upstream's contribution here is its intersection with the category,
    // even when that upstream calls the entry mixed or uses a different label.
    const categorySources = sourceEntries.map(({ source, entries: values }) => ({ source, entries: values.filter(x => members.has(x)) }));
    const result = calculateStatistics(categorySources, {});
    categories[name] = { domains: result.domains, ips: result.ips, total: result.total,
      sharedDomains: result.sharedDomains, sharedIPs: result.sharedIPs,
      uniqueDomains: result.uniqueDomains, uniqueIPs: result.uniqueIPs,
      sources: result.sources, matrix: result.matrix };
  }
  return { total: domains + ips, domains, ips, uniqueDomains, uniqueIPs,
    sharedDomains: domains - uniqueDomains, sharedIPs: ips - uniqueIPs,
    histogram, sources, matrix, categories };
}
