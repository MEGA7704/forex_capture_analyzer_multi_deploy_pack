const express = require('express');
const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 10000;
const BASE_DATA_DIR = process.env.DATA_DIR || (process.env.RENDER_DISK_PATH ? path.join(process.env.RENDER_DISK_PATH, 'fxa-data') : path.join(__dirname, 'data'));
const LICENSE_FILE = path.join(BASE_DATA_DIR, 'licenses.json');
const EVENTS_FILE = path.join(BASE_DATA_DIR, 'events.json');
const SEED_LICENSE_FILE = path.join(__dirname, 'data', 'licenses.seed.json');
const SEED_EVENTS_FILE = path.join(__dirname, 'data', 'events.seed.json');
const LICENSE_SECRET = process.env.LICENSE_SECRET || 'CHANGE_ME_LICENSE_SECRET';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'CHANGE_ME_ADMIN_TOKEN';
const ADMIN_MASTER_KEY = (process.env.ADMIN_MASTER_KEY || 'CHANGE_ME_ADMIN_MASTER_KEY').trim().toUpperCase();

const GITHUB_TOKEN = String(process.env.GITHUB_TOKEN || '').trim();
const GITHUB_REPO = String(process.env.GITHUB_REPO || '').trim();
const GITHUB_BRANCH = String(process.env.GITHUB_BRANCH || 'main').trim() || 'main';
const GITHUB_LICENSES_PATH = String(process.env.GITHUB_LICENSES_PATH || 'render_data/licenses.json').trim();
const GITHUB_EVENTS_PATH = String(process.env.GITHUB_EVENTS_PATH || 'render_data/events.json').trim();
const GITHUB_SYNC_ENABLED = Boolean(GITHUB_TOKEN && GITHUB_REPO);
const GITHUB_PULL_INTERVAL_MS = Math.max(5000, Number(process.env.GITHUB_PULL_INTERVAL_MS || 15000));

const githubCache = {
  lastPullAt: 0,
  remoteShaByPath: {}
};

app.use(express.json({ limit: '2mb' }));
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'content-type, authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

function normalizeKey(key = '') { return String(key).trim().toUpperCase(); }
function nowIso() { return new Date().toISOString(); }
function toFiniteNumber(value, fallback = 0) { const n = Number(value); return Number.isFinite(n) ? n : fallback; }
function dateOnlyUtc(value) { return String(value || '').slice(0, 10); }
function isExpired(license) {
  if (!license || !license.expiration) return false;
  const exp = new Date(`${dateOnlyUtc(license.expiration)}T23:59:59Z`).getTime();
  return Number.isFinite(exp) ? Date.now() > exp : false;
}
function isCountExhausted(license) {
  if (!license || license.mode !== 'count') return false;
  const used = toFiniteNumber(license.analysis_count, 0);
  const limit = toFiniteNumber(license.analysis_limit, 0);
  return limit <= 0 || used >= limit;
}
function normalizeLicenseShape(license) {
  if (!license) return null;
  license.license_key = normalizeKey(license.license_key || '');
  license.plan_id = String(license.plan_id || '').trim();
  license.plan_label = String(license.plan_label || license.plan_id || '').trim();
  license.mode = license.mode === 'count' ? 'count' : 'duration';
  license.analysis_limit = Math.max(0, Math.trunc(toFiniteNumber(license.analysis_limit, 0)));
  license.analysis_count = Math.max(0, Math.trunc(toFiniteNumber(license.analysis_count, 0)));
  license.session_count = Math.max(0, Math.trunc(toFiniteNumber(license.session_count, 0)));
  license.error_reports = Math.max(0, Math.trunc(toFiniteNumber(license.error_reports, 0)));
  license.sos_reports = Math.max(0, Math.trunc(toFiniteNumber(license.sos_reports, 0)));
  license.piracy_flags = Math.max(0, Math.trunc(toFiniteNumber(license.piracy_flags, 0)));
  license.duration_days = Math.max(0, Math.trunc(toFiniteNumber(license.duration_days, 0)));
  license.device_locked = Boolean(license.device_locked && license.device_id);
  if (license.mode === 'count') {
    const computedRemaining = Math.max(0, license.analysis_limit - license.analysis_count);
    license.analyses_remaining = computedRemaining;
  } else {
    license.analyses_remaining = null;
  }
  return license;
}
function refreshComputedStatus(license) {
  if (!license) return license;
  normalizeLicenseShape(license);
  const previous = String(license.status || '').trim().toLowerCase();
  if (previous === 'blocked') return license;
  if (license.mode === 'duration' && isExpired(license)) license.status = 'expired';
  else if (license.mode === 'count' && isCountExhausted(license)) license.status = 'quota_reached';
  else if (license.activated_at || license.device_locked || license.session_count > 0 || license.analysis_count > 0) license.status = 'active';
  else license.status = 'unused';
  return license;
}
function getLicenseAccessError(license) {
  if (!license) return 'Licence introuvable';
  refreshComputedStatus(license);
  if (license.status === 'blocked') return 'Licence bloquée';
  if (license.mode === 'duration' && (license.status === 'expired' || isExpired(license))) return 'Licence expirée';
  if (license.mode === 'count' && (license.status === 'quota_reached' || isCountExhausted(license))) return 'Quota de captures atteint';
  return '';
}
function restoreLicenseStatus(license) {
  if (!license) return license;
  const previous = String(license.status || '').trim().toLowerCase();
  if (previous === 'blocked') return license;
  return refreshComputedStatus(license);
}
function safeIpHash(ip = '') { return !ip ? '' : 'ip_' + String(ip).split('.').slice(0, 2).join('_'); }
function sanitizeLicenseForClient(license) {
  const clone = { ...license };
  delete clone.notes;
  delete clone.last_ip_hash;
  delete clone.client_meta;
  return clone;
}
function deepEqual(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
function unwrapLicensesPayload(raw) {
  const items = Array.isArray(raw) ? raw : (Array.isArray(raw?.licenses) ? raw.licenses : []);
  return items.map((item) => refreshComputedStatus(item));
}
function wrapLicensesPayload(items) {
  return { licenses: items.map((item) => refreshComputedStatus(item)) };
}

async function fileExists(fp) {
  try { await fs.access(fp); return true; } catch { return false; }
}
async function ensureFiles() {
  await fs.mkdir(BASE_DATA_DIR, { recursive: true });
  if (!(await fileExists(LICENSE_FILE))) {
    const seed = await fs.readFile(SEED_LICENSE_FILE, 'utf8');
    await fs.writeFile(LICENSE_FILE, seed);
  }
  if (!(await fileExists(EVENTS_FILE))) {
    const seedEvents = await fs.readFile(SEED_EVENTS_FILE, 'utf8');
    await fs.writeFile(EVENTS_FILE, seedEvents);
  }
}

function githubContentUrl(remotePath) {
  const encodedPath = remotePath.split('/').map(encodeURIComponent).join('/');
  return `https://api.github.com/repos/${GITHUB_REPO}/contents/${encodedPath}`;
}
async function githubRequest(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      'Accept': 'application/vnd.github+json',
      'Authorization': `Bearer ${GITHUB_TOKEN}`,
      'User-Agent': 'forex-capture-analyzer-render',
      ...(options.headers || {})
    }
  });
  return response;
}
async function githubGetJsonFile(remotePath) {
  if (!GITHUB_SYNC_ENABLED) return { ok: false, notConfigured: true };
  const url = `${githubContentUrl(remotePath)}?ref=${encodeURIComponent(GITHUB_BRANCH)}`;
  const response = await githubRequest(url, { method: 'GET' });
  if (response.status === 404) return { ok: false, notFound: true };
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`GitHub read failed (${response.status}): ${text.slice(0, 180)}`);
  }
  const payload = await response.json();
  const decoded = Buffer.from(String(payload.content || '').replace(/\n/g, ''), 'base64').toString('utf8');
  githubCache.remoteShaByPath[remotePath] = payload.sha;
  return { ok: true, sha: payload.sha, json: JSON.parse(decoded) };
}
async function githubPutJsonFile(remotePath, jsonData, message) {
  if (!GITHUB_SYNC_ENABLED) return { ok: false, notConfigured: true };
  let sha = githubCache.remoteShaByPath[remotePath];
  if (!sha) {
    const current = await githubGetJsonFile(remotePath);
    if (current.ok) sha = current.sha;
  }
  const body = {
    message,
    content: Buffer.from(JSON.stringify(jsonData, null, 2), 'utf8').toString('base64'),
    branch: GITHUB_BRANCH,
    committer: { name: 'Forex Capture Analyzer Bot', email: 'bot@local.invalid' }
  };
  if (sha) body.sha = sha;

  const response = await githubRequest(githubContentUrl(remotePath), {
    method: 'PUT',
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`GitHub write failed (${response.status}): ${text.slice(0, 180)}`);
  }
  const payload = await response.json();
  githubCache.remoteShaByPath[remotePath] = payload.content?.sha || sha;
  return { ok: true, sha: githubCache.remoteShaByPath[remotePath] };
}
async function syncDownFromGitHub(force = false) {
  if (!GITHUB_SYNC_ENABLED) return;
  if (!force && Date.now() - githubCache.lastPullAt < GITHUB_PULL_INTERVAL_MS) return;
  await ensureFiles();

  const remoteLicenses = await githubGetJsonFile(GITHUB_LICENSES_PATH);
  if (remoteLicenses.ok) {
    await fs.writeFile(LICENSE_FILE, JSON.stringify(remoteLicenses.json, null, 2));
  } else if (remoteLicenses.notFound) {
    const local = JSON.parse(await fs.readFile(LICENSE_FILE, 'utf8'));
    await githubPutJsonFile(GITHUB_LICENSES_PATH, local, 'Initialize licenses from Render seed');
  }

  const remoteEvents = await githubGetJsonFile(GITHUB_EVENTS_PATH);
  if (remoteEvents.ok) {
    await fs.writeFile(EVENTS_FILE, JSON.stringify(remoteEvents.json, null, 2));
  } else if (remoteEvents.notFound) {
    const localEvents = JSON.parse(await fs.readFile(EVENTS_FILE, 'utf8'));
    await githubPutJsonFile(GITHUB_EVENTS_PATH, localEvents, 'Initialize events from Render seed');
  }

  githubCache.lastPullAt = Date.now();
}
async function persistLicenses(items, reason = 'Update licenses') {
  const payload = wrapLicensesPayload(items);
  await fs.writeFile(LICENSE_FILE, JSON.stringify(payload, null, 2));
  if (GITHUB_SYNC_ENABLED) {
    await githubPutJsonFile(GITHUB_LICENSES_PATH, payload, reason);
    githubCache.lastPullAt = Date.now();
  }
}
async function persistEvents(items, reason = 'Update events') {
  await fs.writeFile(EVENTS_FILE, JSON.stringify(items, null, 2));
  if (GITHUB_SYNC_ENABLED) {
    await githubPutJsonFile(GITHUB_EVENTS_PATH, items, reason);
    githubCache.lastPullAt = Date.now();
  }
}
async function reconcileLicenses({ forcePull = false, persist = true } = {}) {
  await ensureFiles();
  await syncDownFromGitHub(forcePull);
  const raw = JSON.parse(await fs.readFile(LICENSE_FILE, 'utf8'));
  const current = Array.isArray(raw?.licenses) ? raw.licenses : (Array.isArray(raw) ? raw : []);
  const normalized = current.map((item) => refreshComputedStatus(item));
  if (persist && !deepEqual(wrapLicensesPayload(current), wrapLicensesPayload(normalized))) {
    await persistLicenses(normalized, 'Reconcile license statuses from server rules');
  }
  return normalized;
}
async function readLicenses({ forcePull = false } = {}) {
  return reconcileLicenses({ forcePull, persist: true });
}
async function writeLicenses(items, reason = 'Update licenses') {
  await ensureFiles();
  await persistLicenses(items.map((item) => refreshComputedStatus(item)), reason);
}
async function readEvents({ forcePull = false } = {}) {
  await ensureFiles();
  await syncDownFromGitHub(forcePull);
  return JSON.parse(await fs.readFile(EVENTS_FILE, 'utf8'));
}
async function writeEvents(items, reason = 'Update events') {
  await ensureFiles();
  await persistEvents(items, reason);
}
async function getLicense(key) {
  const items = await readLicenses();
  return items.find((x) => normalizeKey(x.license_key) === normalizeKey(key)) || null;
}
async function putLicense(license, reason = `Update license ${normalizeKey(license?.license_key || '')}`) {
  refreshComputedStatus(license);
  const items = await readLicenses();
  const idx = items.findIndex((x) => normalizeKey(x.license_key) === normalizeKey(license.license_key));
  if (idx >= 0) items[idx] = license; else items.push(license);
  await writeLicenses(items, reason);
  return license;
}
async function listLicenses() { return readLicenses(); }
async function appendEvent(event) {
  const items = await readEvents();
  const full = { id: `evt_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`, ...event };
  items.push(full);
  await writeEvents(items, `Append event ${full.event_type || 'unknown'}`);
  return full;
}
function signToken(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const enc = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  const body = `${enc(header)}.${enc(payload)}`;
  const sig = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function verifyToken(token, secret) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('Token invalide');
  const [h, p, sig] = parts;
  const body = `${h}.${p}`;
  const expected = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  if (sig !== expected) throw new Error('Signature invalide');
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  if (payload.exp && Date.now() > payload.exp * 1000) throw new Error('Session expirée');
  return payload;
}
function requireAdmin(req) {
  const auth = req.headers.authorization || '';
  const token = auth.replace(/^Bearer\s+/i, '').trim();
  if (!token || token !== ADMIN_TOKEN) throw new Error('Accès admin refusé');
}
function pickClientIp(req) { return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || ''; }

app.get('/health', async (_req, res) => {
  try {
    const licenses = await readLicenses();
    res.json({ ok: true, status: 'up', licenses: licenses.length, dataDir: BASE_DATA_DIR, githubSync: GITHUB_SYNC_ENABLED, githubRepo: GITHUB_REPO || null, githubBranch: GITHUB_SYNC_ENABLED ? GITHUB_BRANCH : null });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/license/portal', async (req, res) => {
  try {
    const key = normalizeKey(req.body?.key);
    const deviceId = String(req.body?.deviceId || '').trim();
    const clientMeta = req.body?.clientMeta || {};
    if (!key) return res.status(400).json({ ok: false, error: 'Clé requise' });
    if (!deviceId) return res.status(400).json({ ok: false, error: 'Identifiant appareil requis' });

    if (key === ADMIN_MASTER_KEY) return res.json({ ok: true, mode: 'admin', adminToken: ADMIN_TOKEN, redirect: '/admin.html' });

    let license = await getLicense(key);
    if (!license) return res.status(404).json({ ok: false, error: 'Licence introuvable' });
    refreshComputedStatus(license);
    const accessError = getLicenseAccessError(license);
    if (accessError) {
      await putLicense(license, `Persist denied access for ${license.license_key}`);
      return res.status(403).json({ ok: false, error: accessError });
    }
    if (license.device_locked && license.device_id && license.device_id !== deviceId) {
      return res.status(403).json({ ok: false, error: 'Licence déjà liée à un autre appareil' });
    }

    const firstActivation = !license.activated_at || String(license.status || '').toLowerCase() === 'unused';
    license.status = 'active';
    license.device_id = deviceId;
    license.device_locked = true;
    license.activated_at = license.activated_at || nowIso();
    license.last_seen_at = nowIso();
    license.last_ip_hash = safeIpHash(pickClientIp(req));
    license.session_count = Number(license.session_count || 0) + 1;
    license.client_meta = clientMeta;
    await putLicense(license, `License portal access ${license.license_key}`);
    await appendEvent({
      created_at: nowIso(), event_type: firstActivation ? 'license_activation' : 'license_login',
      license_key: license.license_key, device_id: deviceId, details: { clientMeta }
    });

    const token = signToken({ sub: license.license_key, device_id: deviceId, role: 'client', exp: Math.floor(Date.now() / 1000) + 60 * 60 * 12 }, LICENSE_SECRET);
    res.json({ ok: true, mode: 'app', token, redirect: '/app.html', license: sanitizeLicenseForClient(license) });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/license/validate', async (req, res) => {
  try {
    const token = String(req.body?.token || '').trim();
    const claimedDevice = String(req.body?.deviceId || '').trim();
    const payload = verifyToken(token, LICENSE_SECRET);
    const license = await getLicense(payload.sub);
    if (!license) return res.status(404).json({ ok: false, error: 'Licence introuvable' });
    refreshComputedStatus(license);
    const accessError = getLicenseAccessError(license);
    if (accessError) {
      await putLicense(license, `Persist denied validate for ${license.license_key}`);
      return res.status(403).json({ ok: false, error: accessError });
    }
    if (payload.device_id !== claimedDevice || license.device_id !== claimedDevice) {
      return res.status(403).json({ ok: false, error: 'Appareil non autorisé' });
    }
    license.last_seen_at = nowIso();
    await putLicense(license, `Validate session ${license.license_key}`);
    res.json({ ok: true, license: sanitizeLicenseForClient(license) });
  } catch (err) {
    res.status(401).json({ ok: false, error: err.message });
  }
});

app.post('/api/license/report', async (req, res) => {
  try {
    const token = String(req.body?.token || '').trim();
    const type = String(req.body?.type || req.body?.eventType || 'analysis_run').trim();
    const detail = req.body?.detail || req.body?.payload || {};
    const deviceId = String(req.body?.deviceId || '').trim();
    const payload = verifyToken(token, LICENSE_SECRET);
    const license = await getLicense(payload.sub);
    if (!license) return res.status(404).json({ ok: false, error: 'Licence introuvable' });
    refreshComputedStatus(license);
    const accessError = getLicenseAccessError(license);
    if (accessError) {
      await putLicense(license, `Persist denied report for ${license.license_key}`);
      return res.status(403).json({ ok: false, error: accessError });
    }
    if (license.device_id !== deviceId) return res.status(403).json({ ok: false, error: 'Appareil non autorisé' });

    if (type === 'analysis_run') {
      if (license.mode === 'count' && isCountExhausted(license)) {
        refreshComputedStatus(license);
        await putLicense(license, `Quota reached for ${license.license_key}`);
        return res.status(403).json({ ok: false, error: 'Quota de captures atteint' });
      }
      license.analysis_count = Number(license.analysis_count || 0) + 1;
      restoreLicenseStatus(license);
      if (license.mode === 'count' && isCountExhausted(license)) {
        license.status = 'quota_reached';
      }
    }
    if (type === 'error_report') license.error_reports = Number(license.error_reports || 0) + 1;
    if (type === 'sos_report') license.sos_reports = Number(license.sos_reports || 0) + 1;

    license.last_seen_at = nowIso();
    await putLicense(license, `Record ${type} for ${license.license_key}`);
    const event = await appendEvent({ created_at: nowIso(), event_type: type, license_key: license.license_key, device_id: deviceId, details: detail });
    res.json({ ok: true, event, license: sanitizeLicenseForClient(license) });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.get('/api/license/list', async (req, res) => {
  try {
    requireAdmin(req);
    const q = normalizeKey(req.query.q || '');
    const status = String(req.query.status || '').trim();
    const plan = String(req.query.plan || '').trim();
    const limit = Math.min(Number(req.query.limit || 200), 1000);
    let items = await listLicenses();
    if (q) items = items.filter((x) => normalizeKey(x.license_key).includes(q) || normalizeKey(x.device_id || '').includes(q));
    if (status) items = items.filter((x) => String(x.status || '') === status);
    if (plan) items = items.filter((x) => String(x.plan_id || '') === plan);
    res.json({ ok: true, items: items.slice(0, limit).map(sanitizeLicenseForClient) });
  } catch (err) {
    res.status(401).json({ ok: false, error: err.message });
  }
});

app.get('/api/license/stats', async (req, res) => {
  try {
    requireAdmin(req);
    const licenses = await listLicenses();
    const events = await readEvents();
    const totals = {
      licenses: licenses.length,
      activated: licenses.filter((x) => { refreshComputedStatus(x); return x.status === 'active'; }).length,
      blocked: licenses.filter((x) => { refreshComputedStatus(x); return x.status === 'blocked'; }).length,
      expired: licenses.filter((x) => x.mode === 'duration' && isExpired(x)).length,
      quotaReached: licenses.filter((x) => x.mode === 'count' && isCountExhausted(x)).length,
      totalRemaining: licenses.reduce((s, x) => s + Number(x.analyses_remaining || 0), 0)
    };
    const byPlan = licenses.reduce((acc, x) => { const k = x.plan_id || 'UNKNOWN'; acc[k] = (acc[k] || 0) + 1; return acc; }, {});
    const eventCounts = events.reduce((acc, e) => { acc[e.event_type] = (acc[e.event_type] || 0) + 1; return acc; }, {});
    const recent = [...events].reverse().slice(0, 20);
    res.json({ ok: true, totals, byPlan, eventCounts, recent, githubSync: GITHUB_SYNC_ENABLED, githubRepo: GITHUB_REPO || null, githubBranch: GITHUB_SYNC_ENABLED ? GITHUB_BRANCH : null });
  } catch (err) {
    res.status(401).json({ ok: false, error: err.message });
  }
});

app.post('/api/license/block', async (req, res) => {
  try {
    requireAdmin(req);
    const key = normalizeKey(req.body?.key);
    const action = String(req.body?.action || '').trim();
    const reason = String(req.body?.reason || '').trim();
    const days = Number(req.body?.days || 0);
    let license = await getLicense(key);
    if (!license) return res.status(404).json({ ok: false, error: 'Licence introuvable' });

    if (action === 'block') {
      license.status = 'blocked';
    } else if (action === 'unblock') {
      restoreLicenseStatus(license);
    } else if (action === 'reset_device') {
      license.device_id = null;
      license.device_locked = false;
      license.activated_at = null;
      license.last_seen_at = null;
      license.last_ip_hash = null;
      license.session_count = 0;
      restoreLicenseStatus(license);
    } else if (action === 'extend_days') {
      const anchor = (license.mode === 'duration' && isExpired(license))
        ? new Date(`${dateOnlyUtc(nowIso())}T00:00:00Z`)
        : (license.expiration ? new Date(`${dateOnlyUtc(license.expiration)}T00:00:00Z`) : new Date());
      anchor.setUTCDate(anchor.getUTCDate() + Math.max(days, 1));
      license.expiration = anchor.toISOString().slice(0, 10);
      restoreLicenseStatus(license);
    } else {
      return res.status(400).json({ ok: false, error: 'Action inconnue' });
    }
    await putLicense(license, `Admin action ${action} on ${license.license_key}`);
    await appendEvent({ created_at: nowIso(), event_type: 'admin_' + action, license_key: license.license_key, device_id: license.device_id || '', details: { reason, days } });
    res.json({ ok: true, license: sanitizeLicenseForClient(license) });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, async () => {
  try {
    await ensureFiles();
    await reconcileLicenses({ forcePull: true, persist: true });
    console.log(`Forex app listening on ${PORT}`);
    console.log(`Data dir: ${BASE_DATA_DIR}`);
    console.log(`GitHub sync: ${GITHUB_SYNC_ENABLED ? `enabled (${GITHUB_REPO}@${GITHUB_BRANCH})` : 'disabled'}`);
  } catch (err) {
    console.error('Startup error:', err);
    process.exit(1);
  }
});
