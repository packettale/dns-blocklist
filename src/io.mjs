import { mkdir, readFile, writeFile, rename } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';

export const sha256 = data => createHash('sha256').update(data).digest('hex');
export async function jsonFile(path, fallback = null) {
  try { return JSON.parse(await readFile(path, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return fallback; throw error; }
}
export async function atomicWrite(path, data) {
  await mkdir(dirname(path), { recursive: true });
  try { if (await readFile(path, 'utf8') === data) return false; }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const temp = `${path}.tmp`;
  await writeFile(temp, data, 'utf8');
  await rename(temp, path);
  return true;
}
export const writeJson = (path, value) => atomicWrite(path, `${JSON.stringify(value, null, 2)}\n`);

export class Downloader {
  constructor(cacheDir, settings, fetchImpl = fetch) {
    this.cacheDir = cacheDir; this.settings = settings; this.fetch = fetchImpl;
  }
  async get(url, { force = false, maxBytes = this.settings.maxBytes, minIntervalMs = 0, requestUrl = url } = {}) {
    if(new URL(requestUrl).hostname!==new URL(url).hostname)throw new Error('Revision fetch cannot change the source host');
    const key = sha256(url);
    const metaPath = join(this.cacheDir, `${key}.json`);
    const bodyPath = join(this.cacheDir, `${key}.body`);
    const old = await jsonFile(metaPath, {});
    let oldBody;
    try { oldBody = await readFile(bodyPath, 'utf8'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (!force && oldBody !== undefined && minIntervalMs && Date.now() - new Date(old.checkedAt).getTime() < minIntervalMs) {
      return { ...old, text: oldBody, unchanged: true };
    }
    const headers = { 'User-Agent': 'DNS-IP-Blocklist/1.0' };
    if (!force && oldBody !== undefined) {
      if (old.etag) headers['If-None-Match'] = old.etag;
      if (old.lastModified) headers['If-Modified-Since'] = old.lastModified;
    }
    // Never send GitHub's token to an upstream feed or a redirected host.
    const api = new URL(url).hostname === 'api.github.com';
    if (api && process.env.GH_TOKEN) headers.Authorization = `Bearer ${process.env.GH_TOKEN}`;
    const response = await this.fetch(requestUrl, { headers, redirect: api ? 'error' : 'follow', signal: AbortSignal.timeout(this.settings.timeoutMs) });
    const checkedAt = new Date().toISOString();
    if (response.status === 304 && oldBody !== undefined) {
      const meta = { ...old, checkedAt, status: 304 };
      await writeJson(metaPath, meta);
      return { ...meta, text: oldBody, unchanged: true };
    }
    if (!response.ok) throw new Error(`HTTP ${response.status} from ${new URL(url).hostname}`);
    const length = Number(response.headers.get('content-length'));
    if (length > maxBytes) throw new Error(`Feed exceeds ${maxBytes} byte limit`);
    const decoder = new TextDecoder();
    let text = '', size = 0;
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > maxBytes) { await response.body.cancel().catch(() => {}); throw new Error('Feed exceeded download limit'); }
      text += decoder.decode(chunk, { stream: true });
    }
    text += decoder.decode();
    const meta = { url, finalUrl: response.url || url, checkedAt, etag: response.headers.get('etag'),
      lastModified: response.headers.get('last-modified'), contentType: response.headers.get('content-type'),
      sha256: sha256(text), bytes: size, status: 200 };
    // Raw response caching is not the accepted-feed cache. Bad downloads can
    // never replace a previously accepted normalized snapshot.
    await atomicWrite(bodyPath, text);
    await writeJson(metaPath, meta);
    return { ...meta, text, unchanged: meta.sha256 === old.sha256 };
  }
}

export async function parallelMap(items, concurrency, task) {
  let next = 0;
  const results = new Array(items.length);
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (next < items.length) { const index = next++; results[index] = await task(items[index], index); }
  }));
  return results;
}
