import { isIP } from 'node:net';
import { normalize } from './parser.mjs';

// A small RFC 4180 reader: commas and newlines inside quoted fields, and
// doubled quotes, are preserved. URLhaus metadata lines start with '#'.
export function* csvRows(text) {
  let row = [], field = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"') {
      if (quoted && text[i + 1] === '"') { field += '"'; i++; }
      else quoted = !quoted;
    } else if (ch === ',' && !quoted) { row.push(field); field = ''; }
    else if ((ch === '\n' || ch === '\r') && !quoted) {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      row.push(field);
      if (row.some(x => x) && !row[0].startsWith('#')) yield row;
      row = []; field = '';
    } else field += ch;
  }
  if (quoted) throw new Error('Truncated URLhaus CSV');
  if (field || row.length) {
    row.push(field);
    if (!row[0].startsWith('#')) yield row;
  }
}

export function analyzeUrlhausCsv(text, existing = new Set()) {
  const all = new Set(), online = new Set();
  const statuses = {}, threats = {};
  let rows = 0, invalid = 0, oldest = null, newest = null;
  for (const row of csvRows(text)) {
    if (row[0] === 'id') continue;
    rows++;
    const status = row[3]; statuses[status] = (statuses[status] || 0) + 1;
    threats[row[5]] = (threats[row[5]] || 0) + 1;
    if (!oldest || row[1] < oldest) oldest = row[1];
    if (!newest || row[1] > newest) newest = row[1];
    try {
      const url = new URL(row[2]);
      if (!['http:', 'https:'].includes(url.protocol)) { invalid++; continue; }
      const host = normalize(url.hostname.replace(/^\[|\]$/g, ''));
      if (!host) { invalid++; continue; }
      all.add(host);
      if (status === 'online') online.add(host);
    } catch { invalid++; }
  }
  function totals(items) {
    const domains = [...items].filter(x => !isIP(x)), ips = [...items].filter(x => isIP(x));
    return { domains: domains.length, ips: ips.length, total: items.size,
      newDomains: domains.filter(x => !existing.has(x)).length, newIPs: ips.filter(x => !existing.has(x)).length };
  }
  return { rows, statuses, threats, invalid, oldest, newest, all: totals(all), online: totals(online),
    note: 'Host counts extracted from URLs are candidates, not a validated whole-domain/IP blocklist. Active URLs can be hosted on legitimate shared infrastructure.' };
}
