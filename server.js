/**
 * blobstore — a free, content-addressed object store for parasite apps.
 *
 * The box has real disk; Cloudflare doesn't meter bandwidth for normal web
 * content. So: store an upload's bytes on the box keyed by its sha256, serve it
 * with an immutable Cache-Control + a content-addressed URL → Cloudflare caches
 * it forever (the content can't change — a new file is a new hash), so the box
 * serves each file ~once and CF serves it for free thereafter.
 *
 *   POST /upload   (token)  raw body = file bytes  → { hash, url, size, type }
 *   GET  /<hash>.<ext>      (public) → the file, safe headers, immutable cache
 *   GET  /health
 *
 * SECURITY (built in, not bolted on):
 *  - upload requires Bearer BLOB_TOKEN
 *  - real type is sniffed from MAGIC BYTES (client-claimed type is ignored)
 *  - only a whitelist of inline-safe types is accepted; HTML/SVG/JS/executables
 *    are REJECTED, so nothing can run as script on this domain
 *  - responses carry X-Content-Type-Options: nosniff
 *  - storage path is derived ONLY from the computed hex hash (no user input →
 *    no path traversal); GET validates the hash is 64 hex chars
 *  - per-file size cap; dedup by hash
 */

'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Load .env / .env.production ourselves (no dependency) so config is present no
// matter how the process is started (pm2 doesn't auto-read .env files). A real
// already-set env var always wins; an empty/missing one is filled from the file.
(function loadEnv() {
  for (const f of ['.env', '.env.production']) {
    try {
      const p = path.join(__dirname, f);
      if (!fs.existsSync(p)) continue;
      for (const line of fs.readFileSync(p, 'utf8').split(/\r?\n/)) {
        const t = line.trim();
        if (!t || t.startsWith('#')) continue;
        const i = t.indexOf('=');
        if (i > 0) { const k = t.slice(0, i).trim(); if (!process.env[k]) process.env[k] = t.slice(i + 1).trim(); }
      }
    } catch { /* ignore */ }
  }
})();

const PORT = parseInt(process.env.PORT || '4030', 10);
const TOKEN = process.env.BLOB_TOKEN || '';
const PUBLIC_BASE = (process.env.BLOB_PUBLIC_BASE || 'https://blob.pipee.tw').replace(/\/+$/, '');
const MAX_SIZE = parseInt(process.env.BLOB_MAX_SIZE || String(10 * 1024 * 1024), 10); // 10 MB
const BLOB_DIR = path.join(__dirname, 'data', 'blob');

// Whitelist: type → extension. Only inline-safe binary formats. NO html/svg/js.
const TYPES = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/gif': 'gif',
  'image/webp': 'webp',
  'application/pdf': 'pdf',
  'video/mp4': 'mp4',
  'video/webm': 'webm',
  'audio/mpeg': 'mp3',
  'audio/ogg': 'ogg',
};
const EXT_TO_TYPE = Object.fromEntries(Object.entries(TYPES).map(([t, e]) => [e, t]));

/** Detect the real content type from magic bytes. Returns a whitelisted type or null. */
function sniffType(buf) {
  if (buf.length < 12) return null;
  const b = buf;
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return 'image/png';
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
  if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38) return 'image/gif';
  if (b.slice(0, 4).toString('latin1') === 'RIFF' && b.slice(8, 12).toString('latin1') === 'WEBP') return 'image/webp';
  if (b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46) return 'application/pdf';
  if (b.slice(4, 8).toString('latin1') === 'ftyp') return 'video/mp4';
  if (b[0] === 0x1a && b[1] === 0x45 && b[2] === 0xdf && b[3] === 0xa3) return 'video/webm';
  if (b.slice(0, 3).toString('latin1') === 'ID3' || (b[0] === 0xff && (b[1] & 0xe0) === 0xe0)) return 'audio/mpeg';
  if (b.slice(0, 4).toString('latin1') === 'OggS') return 'audio/ogg';
  return null; // unknown / unsafe → rejected
}

function blobPath(hash, ext) {
  // path comes ONLY from the computed hex hash → no traversal possible
  return path.join(BLOB_DIR, hash.slice(0, 2), hash.slice(2, 4), `${hash}.${ext}`);
}

function json(res, code, obj) {
  res.writeHead(code, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
  res.end(JSON.stringify(obj));
}

function authed(req) {
  if (!TOKEN) return false; // closed by default — never run open
  const a = req.headers.authorization || '';
  const bearer = a.startsWith('Bearer ') ? a.slice(7) : '';
  return bearer.length > 0 && bearer === TOKEN;
}

async function readBodyCapped(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_SIZE) { reject(new Error('too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://localhost:${PORT}`);
    const pathname = url.pathname;

    if (req.method === 'GET' && pathname === '/health') {
      return json(res, 200, { status: 'ok', service: 'blobstore' });
    }

    // ── Upload (token-gated) ──
    if (req.method === 'POST' && pathname === '/upload') {
      if (!authed(req)) return json(res, 401, { error: 'Unauthorized' });
      let buf;
      try { buf = await readBodyCapped(req); }
      catch { return json(res, 413, { error: `file exceeds ${MAX_SIZE} bytes` }); }
      if (!buf.length) return json(res, 400, { error: 'empty body' });

      const type = sniffType(buf);
      if (!type) return json(res, 415, { error: 'unsupported or unsafe file type (whitelist: image/pdf/audio/video; html/svg/js rejected)' });
      const ext = TYPES[type];

      const hash = crypto.createHash('sha256').update(buf).digest('hex');
      const dest = blobPath(hash, ext);
      if (!fs.existsSync(dest)) {
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, buf); // dedup: only write if new
      }
      return json(res, 200, { hash, ext, type, size: buf.length, url: `${PUBLIC_BASE}/${hash}.${ext}` });
    }

    // ── Serve (public, immutable) ──
    if (req.method === 'GET') {
      const name = pathname.slice(1); // <hash>.<ext> or <hash>
      const m = name.match(/^([a-f0-9]{64})(?:\.([a-z0-9]{2,5}))?$/);
      if (!m) return json(res, 404, { error: 'not found' });
      const hash = m[1];
      let ext = m[2] || null;
      let type = ext ? EXT_TO_TYPE[ext] : null;

      // Resolve the stored file (try given ext, else search the known exts).
      let file = ext ? blobPath(hash, ext) : null;
      if (!file || !fs.existsSync(file)) {
        file = null;
        for (const e of Object.values(TYPES)) {
          const p = blobPath(hash, e);
          if (fs.existsSync(p)) { file = p; ext = e; type = EXT_TO_TYPE[e]; break; }
        }
      }
      if (!file) return json(res, 404, { error: 'not found' });
      if (!type) type = 'application/octet-stream';

      const data = fs.readFileSync(file);
      res.writeHead(200, {
        'content-type': type,
        'x-content-type-options': 'nosniff', // browser won't re-interpret as HTML
        'cache-control': 'public, max-age=31536000, immutable',
        'access-control-allow-origin': '*',
        'content-length': data.length,
      });
      return res.end(data);
    }

    return json(res, 404, { error: 'not found' });
  } catch (err) {
    return json(res, 500, { error: 'server error' });
  }
});

server.listen(PORT, () => {
  console.log(`[blobstore] listening on :${PORT} (public ${PUBLIC_BASE}, max ${MAX_SIZE} bytes)`);
});
