import { readFile } from 'node:fs/promises';
const data = JSON.parse(await readFile(new URL('../dist/stats.json', import.meta.url), 'utf8'));
console.log(`Published: ${data.publishedAt}\nDomains: ${data.totals.domains.toLocaleString()}\nIPs: ${data.totals.ips.toLocaleString()}\n`);
console.table(data.sourceReports.map(s => ({ source: s.name, role: s.role, state: s.state, updated: s.updatedAt, entries: s.acceptedEntries, reason: s.reason || '' })));
