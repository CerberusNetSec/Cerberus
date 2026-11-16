/* The static demo: answers the dashboard's API calls from files recorded by
   tools/build_demo.py. Loaded before app.js; nothing here is used by a real install.

   - GET /api/...   -> the recorded answer (api/NNN.json, looked up in api/manifest.json).
     Alert and event searches are filtered here from one recorded list, as the server would.
   - anything else  -> refused: the demo is read-only.
   - Times: the recording has a date; everything is moved forward by the time since, so
     "2 min ago" stays true however old the recording is. */
(() => {
  'use strict';
  const realFetch = window.fetch.bind(window);
  const READ_ONLY = 'This is a read-only demo on simulated data: nothing is saved. Install Cerberus to try it for real.';
  const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
  let manifest = null;
  const cache = new Map();

  const json = (data, status = 200) => new Response(JSON.stringify(data),
    { status, headers: { 'Content-Type': 'application/json' } });

  function keyFor(path, params) {
    const query = [...params.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([k, v]) => `${k}=${v}`).join('&');
    return path + (query ? `?${query}` : '');
  }

  /* Move every timestamp in a recorded answer forward by the age of the recording. A number
     counts as a timestamp if it is a moment in the fortnight before the recording was made. */
  function shifted(value, delta, recorded) {
    if (typeof value === 'number') {
      return value > recorded - 14 * 86400 && value < recorded + 3600 ? value + delta : value;
    }
    if (Array.isArray(value)) return value.map((v) => shifted(v, delta, recorded));
    if (value && typeof value === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(value)) out[k] = shifted(v, delta, recorded);
      return out;
    }
    return value;
  }

  async function load(key) {
    if (!manifest) manifest = await (await realFetch('api/manifest.json')).json();
    const file = manifest.files[key];
    if (!file) return null;
    if (!cache.has(key)) {
      const data = await (await realFetch(`api/${file}`)).json();
      const delta = Math.floor((Date.now() / 1000 - manifest.recorded_at) / 60) * 60;  // whole minutes: charts stay aligned
      cache.set(key, shifted(data, delta, manifest.recorded_at));
    }
    return structuredClone(cache.get(key));
  }

  const has = (text, q) => String(text ?? '').toLowerCase().includes(q);

  async function alerts(p) {
    const all = (await load('/alerts?limit=1000&status=')).alerts;
    const status = p.has('status') ? p.get('status') : 'open';
    const floor = SEVERITIES.indexOf(p.get('severity') || '');
    const q = (p.get('q') || '').trim().toLowerCase();
    const id = Number(p.get('id') || 0);
    const detectors = (p.get('detector') || '').split(',').map((d) => d.trim()).filter(Boolean);
    const limit = Math.max(1, Math.min(Number(p.get('limit') || 200), 1000));
    const rows = all.filter((a) => {
      if (id) return a.id === id;
      if (status === 'active' ? !['open', 'ack'].includes(a.status) : status && a.status !== status) return false;
      if (floor > 0 && SEVERITIES.indexOf(a.severity) < floor) return false;
      if (detectors.length && !detectors.includes(a.detector)) return false;
      return !q || [a.title, a.description, a.src_ip, a.device, a.entity].some((t) => has(t, q));
    });
    return { alerts: rows.slice(0, limit) };
  }

  async function events(p) {
    const all = (await load('/events?hours=8760&limit=1000')).events;
    const since = Date.now() / 1000 - Math.max(0.1, Number(p.get('hours') || 24)) * 3600;
    const before = Number(p.get('before') || 0);
    const q = (p.get('q') || '').trim().toLowerCase();
    const ip = (p.get('ip') || '').trim(), port = (p.get('port') || '').trim();
    const limit = Math.max(1, Math.min(Number(p.get('limit') || 200), 1000));
    const rows = all.filter((e) => e.ts >= since
      && (!before || e.id < before)
      && (!p.get('device') || e.device === p.get('device'))
      && (!p.get('type') || e.event_type === p.get('type'))
      && (!p.get('action') || e.action === p.get('action'))
      && (!ip || e.src_ip === ip || e.dst_ip === ip)
      && (!/^\d+$/.test(port) || e.dst_port === Number(port))
      && (!q || has(e.message, q) || has(e.raw, q)));
    return { events: rows.slice(0, limit) };
  }

  async function get(path, p) {
    if (path === '/alerts') return alerts(p);
    if (path === '/events') return events(p);
    if (path === '/audit') {
      if (p.get('before')) return { audit: [] };  // the recording holds the whole log
      const log = await load('/audit?limit=500');
      const alertId = Number(p.get('alert_id') || 0);
      if (alertId) log.audit = log.audit.filter((e) => e.alert_id === alertId);
      return log;
    }
    const exact = await load(keyFor(path, p));
    if (exact) return exact;
    if (path === '/summary') return load('/summary?range=24h');
    if (path === '/riskports') return load('/riskports?range=24h');
    if (path === '/attack') return load('/attack?range=30d&status=real');
    return null;
  }

  window.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.url;
    if (!url.startsWith('/api/')) return realFetch(input, init);
    const { pathname, searchParams } = new URL(url, 'https://demo.invalid');
    const path = pathname.slice(4);
    const method = (init.method || 'GET').toUpperCase();
    if (method !== 'GET') {
      if (path === '/logout') return json({ ok: true });
      return json({ detail: READ_ONLY }, 403);
    }
    try {
      const data = await get(path, searchParams);
      return data ? json(data) : json({ detail: 'This part of Cerberus is not in the demo.' }, 404);
    } catch (err) {
      return json({ detail: `The demo's recorded data could not be loaded (${err.message}).` }, 503);
    }
  };

  /* A strip that says what this is. */
  document.addEventListener('DOMContentLoaded', () => {
    const style = document.createElement('style');
    style.textContent = `.demo-strip { background: #1b4f96; color: #fff; font-size: 13.5px; padding: 7px 16px; text-align: center; }
      .demo-strip a { color: #fff; font-weight: 600; margin-left: 6px; white-space: nowrap; }`;
    document.head.append(style);
    const strip = document.createElement('div');
    strip.className = 'demo-strip';
    strip.setAttribute('role', 'note');
    strip.innerHTML = 'Read-only demo: every device, address and alert here is simulated, and nothing you change is saved.'
      + '<a href="../">About Cerberus</a><a href="https://github.com/CerberusNetSec/Cerberus#quick-start">Get it &rarr;</a>';
    document.body.prepend(strip);
  });
})();
