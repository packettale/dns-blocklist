import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';

// Output is deliberately a DNS/IP subset. Never widen a URL or a scoped rule
// into a whole-host block merely to make it fit a plain text file.
export function normalize(value) {
  let host = value.trim().toLowerCase().replace(/\.$/, '');
  if (!host || /[\s/\\*^|@$#<>"';,=]/.test(host)) return null;
  const family = isIP(host);
  if (family === 4) {
    const [a, b, c] = host.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224 ||
        (a === 100 && b >= 64 && b <= 127) ||
        (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && (b === 168 || (b === 0 && [0, 2].includes(c)))) ||
        (a === 198 && ([18, 19].includes(b) || (b === 51 && c === 100))) ||
        (a === 203 && b === 0 && c === 113)) return null;
    return host;
  }
  if (family === 6) {
    host = new URL(`http://[${host}]/`).hostname.slice(1, -1);
    // Global unicast only. Local, mapped, multicast and documentation IPs
    // should never become network-wide blocking entries.
    if (!/^[23]/.test(host) || host.startsWith('2001:db8:')) return null;
    return host;
  }
  if (/^[\d.]+$/.test(host) || host.includes(':')) return null;
  host = domainToASCII(host);
  if (!host || host.length > 253 || !host.includes('.')) return null;
  const labels = host.split('.');
  if (labels.some(s => s.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(s))) return null;
  if (/^\d+$/.test(labels.at(-1))) return null;
  if (['localhost', 'local', 'internal', 'invalid', 'test', 'example', 'home', 'arpa'].includes(labels.at(-1))) return null;
  return host;
}

export function parseLine(input) {
  const line = input.replace(/^\uFEFF/, '').trim();
  if (!line || /^[#!;\[]/.test(line) || line.includes('##') || line.includes('#@#')) return null;
  // A conditional exception cannot be represented faithfully in a plain feed.
  // Conservatively protect its hostname rather than discard the exception.
  const exception = line.match(/^@@\|\|([^/^|$]+)\^(?:\$.*)?$/);
  if (exception) {
    const host = normalize(exception[1]);
    return host ? { allow: [host], block: [] } : null;
  }
  const disabled = line.match(/^\|\|([^/^|$]+)\^\$badfilter$/);
  if (disabled) {
    const host = normalize(disabled[1]);
    return host ? { allow: [host], block: [] } : null;
  }
  const adblock = line.match(/^\|\|([^/^|$]+)\^$/);
  if (adblock) {
    const host = normalize(adblock[1]);
    return host ? { allow: [], block: [host] } : null;
  }
  const plain = line.split('#', 1)[0].trim();
  const tokens = plain.split(/\s+/);
  // Hosts mappings are addresses followed by hostnames; mapping addresses are
  // not indicators and must not be emitted as blocked IPs.
  if (tokens.length > 1 && isIP(tokens[0])) {
    const block = tokens.slice(1).map(normalize).filter(x => x && !isIP(x));
    return block.length ? { allow: [], block } : null;
  }
  if (tokens.length !== 1) return null;
  const host = normalize(tokens[0]);
  return host ? { allow: [], block: [host] } : null;
}

export function parseText(text) {
  if (/^\s*(?:<!doctype\s+html|<html|\{\s*"(?:error|message)")/i.test(text)) throw new Error('HTML/JSON error document instead of a feed');
  const block = new Set(), allow = new Set();
  let rejected = 0, dataLines = 0;
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || /^[\s]*[#!;\[]/.test(line)) continue;
    dataLines++;
    const parsed = parseLine(line);
    if (!parsed) { rejected++; continue; }
    parsed.block.forEach(x => block.add(x));
    parsed.allow.forEach(x => allow.add(x));
  }
  return { block: [...block].sort(), allow: [...allow].sort(), rejected, dataLines };
}

export function parseDisconnect(text) {
  const data = JSON.parse(text);
  if (!data.categories || typeof data.categories !== 'object') throw new Error('Invalid Disconnect category document');
  const names = { Advertising: 'ads', Analytics: 'analytics', Social: 'social',
    Email: 'email-tracking', Fingerprinting: 'fingerprinting',
    'FingerprintingInvasive': 'fingerprinting', 'FingerprintingGeneral': 'fingerprinting',
    Cryptomining: 'cryptomining', 'Session Replay': 'session-replay' };
  const categories = {};
  const walk = (value, target) => {
    if (Array.isArray(value)) for (const item of value) {
      if (typeof item === 'string') { const n = normalize(item); if (n) target.add(n); }
      else walk(item, target);
    }
    else if (value && typeof value === 'object') for (const child of Object.values(value)) walk(child, target);
  };
  for (const [key, category] of Object.entries(names)) {
    if (!data.categories[key]) continue;
    const found = new Set();
    walk(data.categories[key], found);
    categories[category] = [...new Set([...(categories[category] || []), ...found])].sort();
  }
  // A social-service host can be a tracker in a browser's third-party context
  // while still being the service's normal first-party website. DNS cannot
  // preserve that context: retain those hosts in the optional social policy.
  const services=new Set(categories.social||[]);
  for(const category of Object.keys(categories))if(category!=='social')categories[category]=categories[category].filter(host=>!services.has(host));
  // Content, anti-fraud, consent managers, and aggressive-email categories are
  // deliberately not converted into a DNS blocklist.
  return { categories, block: [...new Set(Object.values(categories).flat())].sort(),
    allow: [], rejected: 0, licenseText: data.license };
}

export function publicSuffixes(text) {
  const exact = new Set(), wildcard = new Set(), exceptions = new Set();
  for (const raw of text.split(/\r?\n/)) {
    const s = raw.trim();
    if (!s || s.startsWith('//')) continue;
    if (s.startsWith('!')) exceptions.add(domainToASCII(s.slice(1)));
    else if (s.startsWith('*.')) wildcard.add(domainToASCII(s.slice(2)));
    else exact.add(domainToASCII(s));
  }
  if (exact.size < 1000) throw new Error('Public suffix list is incomplete');
  return host => {
    if (isIP(host) || exceptions.has(host)) return false;
    return exact.has(host) || wildcard.has(host.split('.').slice(1).join('.'));
  };
}

export function allowMatcher(entries) {
  const suffix = new Set(), exact = new Set(), ancestors = new Set();
  for (let entry of entries) {
    const onlyExact = entry.startsWith('=');
    if (onlyExact) entry = entry.slice(1);
    const n = normalize(entry);
    if (!n) continue;
    (onlyExact ? exact : suffix).add(n);
    // Drop a parent block that would otherwise swallow an allowed child.
    if (!isIP(n)) {
      const parts = n.split('.');
      for (let i = 1; i < parts.length - 1; i++) ancestors.add(parts.slice(i).join('.'));
    }
  }
  return host => {
    if (exact.has(host) || ancestors.has(host) || suffix.has(host)) return true;
    if (isIP(host)) return false;
    const p = host.split('.');
    for (let i = 1; i < p.length - 1; i++) if (suffix.has(p.slice(i).join('.'))) return true;
    return false;
  };
}
