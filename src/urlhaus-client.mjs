import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { atomicWrite, jsonFile, writeJson, sha256 } from './io.mjs';

export async function readUrlhausKey(env = process.env) {
  let key = (env.URLHAUS_AUTH_KEY || '').trim();
  if (!key && env.URLHAUS_AUTH_KEY_FILE) {
    try { key = (await readFile(env.URLHAUS_AUTH_KEY_FILE, 'utf8')).replace(/^\uFEFF/, '').trim(); }
    catch { throw new Error('Unable to read the configured URLhaus key file; contents were not logged'); }
  }
  if (!key) return null;
  if (!/^[A-Za-z0-9_-]{16,256}$/.test(key)) throw new Error('Invalid URLhaus key format; contents were not logged');
  return key;
}

// Intentionally separate from the normal HTTP downloader: its generic cache
// records request URLs. URLhaus embeds the secret in its path, so neither its
// authenticated URL nor its raw exception may enter caches, logs or reports.
export async function getUrlhausExport({ key, exportName = 'hostfile.txt', cacheDir,
  fetchImpl = fetch, now = Date.now(), timeoutMs = 30000, maxBytes = 80000000 }) {
  if (!key || !/^[A-Za-z0-9_-]{16,256}$/.test(key)) throw new Error('URLhaus key is missing or invalid');
  if (!['hostfile.txt', 'rpz.txt', 'recent.csv', 'online.csv'].includes(exportName)) throw new Error('Unsupported URLhaus export');
  const bodyPath = join(cacheDir, exportName), metaPath = join(cacheDir, exportName + '.json');
  const old = await jsonFile(metaPath);
  let body;
  try { body = await readFile(bodyPath, 'utf8'); } catch (e) { if (e.code !== 'ENOENT') throw new Error('Unable to read URLhaus data cache'); }
  if (old && body !== undefined && old.sha256 === sha256(body) && now - new Date(old.checkedAt).getTime() < 300000) {
    if (body.includes(key) || JSON.stringify(old).includes(key)) throw new Error('URLhaus cache failed the secret check');
    return { ...old, text: body };
  }
  let response;
  try {
    response = await fetchImpl(`https://urlhaus-api.abuse.ch/v2/files/exports/${encodeURIComponent(key)}/${exportName}`, {
      headers: { 'User-Agent': 'DNS-IP-Blocklist/1.0' },
      redirect: 'error', signal: AbortSignal.timeout(timeoutMs),
    });
  } catch { throw new Error(`URLhaus ${exportName} request failed; authenticated URL redacted`); }
  if (!response.ok) { await response.body?.cancel(); throw new Error(`URLhaus ${exportName} returned HTTP ${response.status}`); }
  if (/text\/html/i.test(response.headers.get('content-type') || '')) throw new Error('URLhaus returned HTML instead of a feed');
  if (Number(response.headers.get('content-length')) > maxBytes) throw new Error('URLhaus export exceeds the configured download limit');
  const decoder = new TextDecoder(); body = ''; let bytes = 0;
  try {
    for await (const chunk of response.body) {
      bytes += chunk.length;
      if (bytes > maxBytes) throw new Error('size limit');
      body += decoder.decode(chunk, { stream: true });
    }
    body += decoder.decode();
  } catch { throw new Error('URLhaus export download failed or exceeded the size limit; authenticated URL redacted'); }
  const meta = { export: exportName, checkedAt: new Date(now).toISOString(),
    lastModified: response.headers.get('last-modified'), contentType: response.headers.get('content-type'),
    sha256: sha256(body), bytes, status: 200 };
  if (body.includes(key) || JSON.stringify(meta).includes(key)) throw new Error('URLhaus response failed the secret check and was not saved');
  await atomicWrite(bodyPath, body); await writeJson(metaPath, meta);
  return { ...meta, text: body };
}
