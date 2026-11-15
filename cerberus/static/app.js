'use strict';
/* Cerberus dashboard. Everything that originates in a syslog message is
   attacker-controlled text, so all of it goes through esc() before it
   reaches innerHTML. */

const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];
const main = $('#main');
const SEVS = ['info', 'low', 'medium', 'high', 'critical'];
const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ESC[c]);
const num = (n) => Number(n || 0).toLocaleString();
const sevBadge = (s) => `<span class="sev ${SEVS.includes(s) ? s : 'info'}">${esc(s)}</span>`;

function compact(n) {
  n = Number(n || 0);
  if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e4) return (n / 1e3).toFixed(1) + 'K';
  return n.toLocaleString();
}
function ago(ts) {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + ' min ago';
  if (s < 86400) return Math.floor(s / 3600) + ' h ago';
  return Math.floor(s / 86400) + ' d ago';
}
function span(seconds) {
  if (seconds < 5400) return Math.max(1, Math.round(seconds / 60)) + ' min';
  if (seconds < 172800) return (seconds / 3600).toFixed(seconds < 36000 ? 1 : 0) + ' h';
  return (seconds / 86400).toFixed(seconds < 864000 ? 1 : 0) + ' d';
}
/* One line on whether the collector is keeping up. */
function health(d) {
  const notes = [];
  if (d.dropped) notes.push('queue overflowed since start');
  if (d.queue > d.queue_size * 0.5) notes.push(`falling behind: queue ${Math.round((d.queue / d.queue_size) * 100)}% full`);
  if (d.unwritten) notes.push(`disk too slow: ${compact(d.unwritten)} events analysed but not stored`);
  else if (d.flush_ms > 700) notes.push(`disk is slow: ${num(d.flush_ms)} ms per write`);
  if (d.refused_tcp) notes.push(`${num(d.refused_tcp)} TCP connections refused at the limit`);
  if (d.refused_devices) notes.push('device limit reached, new sources ignored');
  return notes.join(' · ') || 'none since start · keeping up';
}
/* Processor mode: how the collectors in front of it are doing. */
function collectorsTile(d, tile) {
  const all = d.collectors.filter((c) => c.role !== 'detector'), up = all.filter((c) => c.state === 'reporting');
  const spooling = all.filter((c) => c.bus_down || c.spool_bytes > 0);
  const dropped = all.reduce((n, c) => n + (c.dropped || 0) + (c.spool_dropped || 0), 0);
  const notes = [];
  if (all.length > up.length) notes.push(`silent: ${all.filter((c) => c.state !== 'reporting').map((c) => c.name).join(', ')}`);
  if (spooling.length) notes.push(`${spooling.length} spooling while the bus is unreachable`);
  if (dropped) notes.push(`${compact(dropped)} messages dropped`);
  if (d.duplicates) notes.push(`${compact(d.duplicates)} resent copies ignored`);
  const value = all.length ? `${up.length} <span class="muted">/ ${all.length}</span>` : '—';
  return tile('Collectors reporting', all.length > up.length ? `<span class="error" style="font-size:inherit">${value}</span>` : value,
    esc(notes.join(' · ') || (all.length ? 'all forwarding to the bus' : 'waiting for the first heartbeat')));
}
function workersTile(d, tile) {
  const all = d.collectors.filter((c) => c.role === 'detector');
  if (!all.length) return '';
  const up = all.filter((c) => c.state === 'reporting');
  const families = {};
  for (const w of up) families[w.family] = (families[w.family] || 0) + 1;
  const notes = [];
  if (all.length > up.length) notes.push(`silent: ${all.filter((c) => c.state !== 'reporting').map((c) => c.name).join(', ')}`);
  notes.push(Object.keys(families).sort().map((f) => `${f} ×${families[f]}`).join(', '));
  const value = `${up.length} <span class="muted">/ ${all.length}</span>`;
  return tile('Detection workers', all.length > up.length ? `<span class="error" style="font-size:inherit">${value}</span>` : value,
    esc(notes.filter(Boolean).join(' · ')));
}
const pad = (n) => String(n).padStart(2, '0');
function clock(ts, withDate) {
  const d = new Date(ts * 1000);
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  return withDate ? `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${time}` : time;
}

let toastTimer;
function toast(message, bad) {
  const el = $('#toast');
  el.textContent = message;
  el.className = 'toast' + (bad ? ' bad' : '');
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, bad ? 6000 : 2500);
}

async function api(path, method = 'GET', body) {
  const res = await fetch('/api' + path, {
    method,
    credentials: 'same-origin',
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401 && path !== '/login') {
    showLogin();
    throw new Error('Not signed in');
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : res.statusText);
  return data;
}
/* Run an action from a click handler, reporting failure to the user. */
/* Ask for a name and a justification for an audited change. send({analyst, justification})
   does the change; its error is shown in the dialog, which stays open. Resolves true once
   sent, false if cancelled. */
function justify({ title, intro, confirm, send }) {
  const dlg = $('#justify'), form = $('#justify-form'), err = $('#justify-error');
  $('#justify-title').textContent = title;
  $('#justify-intro').textContent = intro;
  $('#justify-ok').textContent = confirm;
  err.textContent = '';
  let saved = '';
  try { saved = localStorage.getItem('cerberus.analyst') || ''; } catch { /* no storage: ask each time */ }
  $('#justify-analyst').value = saved;
  $('#justify-text').value = '';
  dlg.showModal();
  (saved ? $('#justify-text') : $('#justify-analyst')).focus();
  return new Promise((resolve) => {
    const finish = (sent) => {
      form.removeEventListener('submit', submit);
      $('#justify-cancel').removeEventListener('click', cancel);
      dlg.removeEventListener('cancel', cancel);
      if (dlg.open) dlg.close();
      resolve(sent);
    };
    const cancel = (e) => { e.preventDefault(); finish(false); };
    const submit = async (e) => {
      e.preventDefault();
      const analyst = $('#justify-analyst').value.trim(), justification = $('#justify-text').value.trim();
      if (!analyst) { err.textContent = 'Enter your name.'; return; }
      if (justification.length < 10) { err.textContent = 'Write a justification of at least 10 characters.'; return; }
      $('#justify-ok').disabled = true;
      try {
        await send({ analyst, justification });
        try { localStorage.setItem('cerberus.analyst', analyst); } catch { /* not kept */ }
        finish(true);
      } catch (e2) {
        err.textContent = e2.message;
      } finally {
        $('#justify-ok').disabled = false;
      }
    };
    form.addEventListener('submit', submit);
    $('#justify-cancel').addEventListener('click', cancel);
    dlg.addEventListener('cancel', cancel);
  });
}

async function act(fn, okMessage) {
  try {
    await fn();
    if (okMessage) toast(okMessage);
  } catch (err) {
    if (err.message !== 'Not signed in') toast(err.message, true);
  }
}

/* ------------------------------------------------------------------ chart */
function niceMax(v) {
  if (v <= 0) return 1;
  const pow = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (v <= m * pow) return m * pow;
  return 10 * pow;
}
function drawChart(el, series, bucketMinutes, names = ['All messages', 'Blocked']) {
  const W = Math.max(320, el.clientWidth), H = 240;
  const m = { l: 48, r: 14, t: 10, b: 26 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  if (!series.length) {
    el.innerHTML = '<div class="empty">No data in this range yet.</div>';
    return;
  }
  const t0 = series[0].t, t1 = series[series.length - 1].t;
  const yMax = niceMax(Math.max(...series.map((p) => p.events)));
  const x = (t) => m.l + (t1 === t0 ? iw / 2 : ((t - t0) / (t1 - t0)) * iw);
  const y = (v) => m.t + ih - (v / yMax) * ih;
  const line = (key) => series.map((p, i) => `${i ? 'L' : 'M'}${x(p.t).toFixed(1)},${y(p[key]).toFixed(1)}`).join('');
  const span = t1 - t0;
  const label = (t) => {
    const d = new Date(t * 1000);
    const hm = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
    return span > 86400 * 1.5 ? `${d.toLocaleDateString(undefined, { weekday: 'short' })} ${hm}` : hm;
  };
  let grid = '';
  for (let i = 0; i <= 4; i++) {
    const v = (yMax / 4) * i;
    grid += `<line class="${i ? 'gridline' : 'baseline'}" x1="${m.l}" x2="${W - m.r}" y1="${y(v)}" y2="${y(v)}"/>` +
      `<text class="axis-text" x="${m.l - 8}" y="${y(v) + 4}" text-anchor="end">${compact(v)}</text>`;
  }
  const ticks = Math.max(2, Math.min(7, Math.floor(iw / 110)));
  for (let i = 0; i <= ticks; i++) {
    const t = t0 + (span / ticks) * i;
    const anchor = i === 0 ? 'start' : i === ticks ? 'end' : 'middle';
    grid += `<text class="axis-text" x="${x(t)}" y="${H - 6}" text-anchor="${anchor}">${label(t)}</text>`;
  }
  el.innerHTML =
    `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(names.join(' and '))} per minute over time">${grid}` +
    `<path class="s1" d="${line('events')}"/><path class="s2" d="${line('blocked')}"/>` +
    `<g class="cross" visibility="hidden"><line class="crossline" y1="${m.t}" y2="${m.t + ih}"/>` +
    `<circle class="d1" r="4"/><circle class="d2" r="4"/></g>` +
    `<rect class="hit" x="${m.l}" y="${m.t}" width="${iw}" height="${ih}" fill="transparent"/></svg>` +
    `<div class="tip" hidden></div>`;
  const svg = $('svg', el), cross = $('.cross', el), tip = $('.tip', el);
  const move = (evt) => {
    const box = svg.getBoundingClientRect();
    const px = ((evt.clientX - box.left) / box.width) * W;
    let best = series[0];
    for (const p of series) if (Math.abs(x(p.t) - px) < Math.abs(x(best.t) - px)) best = p;
    const cx = x(best.t);
    cross.setAttribute('visibility', 'visible');
    $('.crossline', cross).setAttribute('x1', cx);
    $('.crossline', cross).setAttribute('x2', cx);
    $('.d1', cross).setAttribute('cx', cx); $('.d1', cross).setAttribute('cy', y(best.events));
    $('.d2', cross).setAttribute('cx', cx); $('.d2', cross).setAttribute('cy', y(best.blocked));
    const unit = bucketMinutes > 1 ? `avg / min over ${bucketMinutes} min` : 'per minute';
    tip.innerHTML = `<div class="t">${esc(label(best.t))} · ${unit}</div>` +
      `<div><i style="background:var(--series-1)"></i>${esc(names[0])} <b>${num(best.events)}</b></div>` +
      `<div><i style="background:var(--series-2)"></i>${esc(names[1])} <b>${num(best.blocked)}</b></div>`;
    tip.hidden = false;
    const left = (cx / W) * box.width;
    tip.style.left = (left > box.width / 2 ? left - tip.offsetWidth - 12 : left + 12) + 'px';
  };
  $('.hit', el).addEventListener('pointermove', move);
  $('.hit', el).addEventListener('pointerleave', () => { cross.setAttribute('visibility', 'hidden'); tip.hidden = true; });
}

/* ------------------------------------------------------------------ pages */
/* How often the Alerts table and the navigation badge refresh, in seconds (0: off). */
const REFRESH_CHOICES = [[0, 'Off'], [10, '10 s'], [30, '30 s'], [60, '1 min'], [300, '5 min']];
function savedRefresh() {
  try {
    const v = Number(localStorage.getItem('cerberus.alertsRefresh'));
    if (REFRESH_CHOICES.some(([s]) => s === v) && localStorage.getItem('cerberus.alertsRefresh') !== null) return v;
  } catch { /* default */ }
  return 10;
}

const state = {
  range: '24h',
  alerts: { status: 'open', severity: '', q: '', open: new Set(), every: savedRefresh(), seen: null },
  events: { hours: '24', type: '', action: '', ip: '', port: '', q: '', live: true, open: new Set(), rows: [] },
  devices: { q: '', status: '', connector: '', sort: 'recent', limit: 100 },
  riskports: { range: '24h', flagged: false, open: null },
  connectors: [],
};
const pages = {};

/* --- dashboard --- */
pages.dashboard = {
  interval: 5000,
  render() {
    main.innerHTML = `
      <div class="grid tiles" id="tiles"></div>
      <div class="card" style="margin-bottom:14px">
        <div class="chart-head">
          <h2 style="margin:0">Log messages per minute</h2>
          <div class="legend"><span><i style="background:var(--series-1)"></i>All messages</span>
            <span><i style="background:var(--series-2)"></i>Blocked traffic</span></div>
          <div class="seg" id="range">${['1h', '6h', '24h', '7d'].map((r) =>
            `<button type="button" data-range="${r}" class="${r === state.range ? 'on' : ''}">${r}</button>`).join('')}</div>
        </div>
        <div class="chart" id="chart"></div>
      </div>
      <div class="grid cols-2" style="margin-bottom:14px">
        <div class="card"><h2>Hosts needing attention <span class="muted">· unresolved alerts, last 24 h</span></h2><ul class="risk-list" id="risk"></ul></div>
        <div class="card"><h2>Alerts by attack stage <span class="muted">· last 24 h</span></h2><ul class="bars" id="stages"></ul></div>
      </div>
      <div class="grid cols-3">
        <div class="card"><h2>Recent alerts</h2><ul class="alert-list" id="recent"></ul></div>
        <div class="card"><h2>Top blocked sources <span class="muted">· last hour</span></h2><ul class="bars" id="top-src"></ul></div>
        <div class="card"><h2>Top blocked ports <span class="muted">· last hour</span></h2><ul class="bars" id="top-port"></ul></div>
      </div>`;
    $('#range').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-range]');
      if (!btn) return;
      state.range = btn.dataset.range;
      $$('#range button').forEach((b) => b.classList.toggle('on', b === btn));
      this.refresh();
    });
  },
  async refresh() {
    const d = await api('/summary?range=' + state.range);
    this.last = d;
    const open = d.open_alerts;
    const totalOpen = SEVS.reduce((n, s) => n + (open[s] || 0), 0);
    setNavCount(totalOpen);
    const breakdown = SEVS.slice().reverse().filter((s) => open[s]).map((s) => `${open[s]} ${s}`).join(' · ');
    const tile = (label, value, sub) =>
      `<div class="card tile"><div class="label">${label}</div><div class="value">${value}</div><div class="sub">${sub}</div></div>`;
    $('#tiles').innerHTML =
      tile('Open alerts', num(totalOpen), esc(breakdown) || 'Nothing needs attention') +
      tile('Messages / second', num(d.rate), 'averaged over the last minute') +
      tile('Messages, last 24 h', compact(d.events_24h), `${compact(d.blocked_24h)} blocked connections`) +
      tile('Devices reporting', `${d.devices_active} <span class="muted">/ ${d.devices_total}</span>`, 'sent logs in the last 15 min') +
      tile('Dropped messages', num(d.dropped), esc(health(d))) +
      (d.federation ? tile('Central console', d.federation.error
        ? `<span class="error" style="font-size:inherit">Not reaching it</span>` : 'Reporting',
        esc(d.federation.error ? `${d.federation.error}${d.federation.last_ok ? ` · last report ${ago(d.federation.last_ok)}` : ''}`
          : d.federation.last_ok ? `as ${d.federation.site} · last report ${ago(d.federation.last_ok)}` : `as ${d.federation.site} · first report pending`)) : '') +
      (d.collectors ? collectorsTile(d, tile) + workersTile(d, tile) : '') +
      tile('Searchable history', d.events_since ? span(Date.now() / 1000 - d.events_since) : '—', esc(
        `${compact(d.events_stored)} events stored · keeps ${compact(d.max_events)} or ${d.retention_days} days` +
        (d.traffic_sample === 0 ? ' · allowed traffic not stored' : d.traffic_sample > 1 ? ` · 1 in ${d.traffic_sample} allowed flows stored` : '')));
    drawChart($('#chart'), d.series, d.bucket_minutes);
    $('#recent').innerHTML = d.recent_alerts.length ? d.recent_alerts.map((a) => `
      <li class="${a.status === 'resolved' ? 'resolved' : ''}">${sevBadge(a.severity)}
        <div><div>${esc(a.title)}${a.count > 1 ? ` <span class="tag">×${num(a.count)}</span>` : ''}</div>
        <div class="desc">${esc(a.description)}</div></div>
        <span class="when">${ago(a.last_seen)}</span></li>`).join('')
      : '<li class="empty" style="display:block">No alerts yet.</li>';
    const bars = (rows, name) => {
      if (!rows.length) return '<li class="empty" style="display:block">Nothing blocked in the last hour.</li>';
      const max = rows[0].count;
      return rows.map((r) => `<li><span class="name mono">${name(r)}</span><span class="n">${num(r.count)}</span>
        <div class="bar"><span style="width:${(r.count / max) * 100}%"></span></div></li>`).join('');
    };
    $('#risk').innerHTML = d.risk.length ? d.risk.map((h) => `
      <li><a href="#/alerts" data-act="risk" data-q="${esc(h.host)}" title="Show this host's alerts">
        <span class="who"><span class="mono host">${esc(h.host)}</span>
          <span class="where">${h.is_device ? 'network device' : h.internal ? 'internal host' : 'internet address'}</span></span>
        ${sevBadge(h.severity)}
        <span class="what">${h.alerts} alert${h.alerts > 1 ? 's' : ''} · ${esc(h.kinds.join(', '))}</span>
        <span class="score" title="Risk score: severity of each alert, weighted up when a host shows several kinds of behaviour">${num(h.score)}</span>
      </a></li>`).join('') : '<li class="empty">No unresolved alerts in the last 24 hours.</li>';
    const stageMax = Math.max(1, ...d.stages.map((s) => s.count));
    $('#stages').innerHTML = d.stages.length ? d.stages.map((s) => `<li><span class="name">${esc(s.stage)}</span><span class="n">${num(s.count)}</span>
      <div class="bar"><span style="width:${(s.count / stageMax) * 100}%"></span></div></li>`).join('')
      : '<li class="empty" style="display:block">No unresolved alerts in the last 24 hours.</li>';
    $('#top-src').innerHTML = bars(d.top_sources, (r) => esc(r.ip));
    $('#top-port').innerHTML = bars(d.top_ports, (r) => `${esc(r.proto || '?')}/${esc(r.port)}`);
  },
};
pages.dashboard.actions = {
  risk(el) { Object.assign(state.alerts, { q: el.dataset.q, status: 'active', severity: '' }); },
};
window.addEventListener('resize', () => { if (current === 'riskports') pages.riskports.draw(); });
window.addEventListener('resize', () => {
  if (current === 'dashboard' && pages.dashboard.last && $('#chart')) {
    drawChart($('#chart'), pages.dashboard.last.series, pages.dashboard.last.bucket_minutes);
  }
});

/* --- alerts --- */
pages.alerts = {
  get interval() { return state.alerts.every * 1000; },
  render() {
    const s = state.alerts;
    const linked = Number(new URLSearchParams(location.hash.split('?')[1] || '').get('id'));
    s.only = linked || null;
    if (linked) s.open.add(linked);
    main.innerHTML = `
      <div class="page-head"><div><h1>Alerts</h1><p>Repeats of the same problem are folded into one alert and counted.</p></div>
        <button type="button" data-act="ack-all">Acknowledge all open</button></div>
      <div class="filters">
        <select id="f-status" aria-label="Status">
          ${[['open', 'Open'], ['ack', 'Acknowledged'], ['active', 'Open + acknowledged'], ['resolved', 'Resolved'],
             ['false_positive', 'False positives'], ['all', 'All']]
            .map(([v, l]) => `<option value="${v}" ${v === s.status ? 'selected' : ''}>${l}</option>`).join('')}
        </select>
        <select id="f-sev" aria-label="Minimum severity">
          <option value="">Any severity</option>
          ${SEVS.slice(1).map((v) => `<option value="${v}" ${v === s.severity ? 'selected' : ''}>${v} and above</option>`).join('')}
        </select>
        <input id="f-q" type="search" placeholder="Search title, IP, device" value="${esc(s.q)}">
        ${s.only ? '<a href="#/alerts">Showing one alert · show all</a>' : ''}
        <span class="spacer"></span>
        <label class="inline" for="f-every">Auto-refresh</label>
        <select id="f-every" aria-label="Auto-refresh the alerts and the count">
          ${REFRESH_CHOICES.map(([v, l]) => `<option value="${v}" ${v === s.every ? 'selected' : ''}>${l}</option>`).join('')}
        </select>
        <span class="muted small" id="f-updated" aria-live="polite"></span>
      </div>
      <div class="card table-wrap"><table>
        <thead><tr><th>Severity</th><th>Alert</th><th>Source</th><th>Reported by</th><th class="num">Count</th><th>First seen</th><th>Last seen</th><th></th></tr></thead>
        <tbody id="rows"></tbody></table></div>`;
    const change = () => {
      s.status = $('#f-status').value; s.severity = $('#f-sev').value; s.q = $('#f-q').value.trim();
      this.refresh().catch(() => {});
    };
    $('#f-status').addEventListener('change', change);
    $('#f-sev').addEventListener('change', change);
    $('#f-every').addEventListener('change', () => {
      s.every = Number($('#f-every').value);
      try { localStorage.setItem('cerberus.alertsRefresh', String(s.every)); } catch { /* this visit only */ }
      startPageTimer();
      startBadgeTimer();
      this.refresh().catch(() => {});
    });
    s.seen = null;  // rows that arrive after this first load are marked new
    $('#f-q').addEventListener('input', debounce(change, 300));
  },
  async refresh() {
    const s = state.alerts;
    const q = s.only ? new URLSearchParams({ id: s.only }) : new URLSearchParams({ status: s.status, severity: s.severity, q: s.q });
    const { alerts } = await api('/alerts?' + q);
    const body = $('#rows');
    if (!body) return;
    s.byId = new Map(alerts.map((a) => [a.id, a]));
    const fresh = new Set(s.seen ? alerts.filter((a) => !s.seen.has(a.id)).map((a) => a.id) : []);
    s.seen = new Set([...(s.seen || []), ...alerts.map((a) => a.id)]);
    $('#f-updated').textContent = `Updated ${clock(Date.now() / 1000)}`;
    updateBadge();
    body.innerHTML = alerts.length ? alerts.map((a) => {
      const btn = (status, label) => `<button type="button" class="small" data-act="status" data-id="${a.id}" data-status="${status}">${label}</button>`;
      const fp = a.status === 'false_positive', fpInfo = a.false_positive;
      const buttons = fp ? '' : (a.status === 'open' ? btn('ack', 'Acknowledge') : '') +
        (a.status !== 'resolved' ? btn('resolved', 'Resolve') : btn('open', 'Reopen'));
      const fpLines = fp ? (fpInfo ? `<dt>False positive</dt><dd>Marked by <b>${esc(fpInfo.analyst)}</b> ${ago(fpInfo.created)}:
            <div class="quote">${esc(fpInfo.justification)}</div>
            ${fpInfo.active ? `Held back since: ${num(fpInfo.hits)} time(s)${fpInfo.last_hit ? `, last ${ago(fpInfo.last_hit)}` : ''}.
              <a href="#/suppressions">Manage</a>` : 'The suppression has since been removed.'}</dd>` : '<dt>False positive</dt><dd>Yes</dd>')
        : `<dt>False positive?</dt><dd><button type="button" class="small" data-act="fp" data-id="${a.id}">Mark as false positive</button>
            <span class="muted">${esc(a.detector.replace(/_/g, ' '))} will not alert on <span class="mono">${esc(a.entity)}</span> again</span></dd>`;
      const g = a.advice || { actions: [] };
      const detail = s.open.has(a.id) ? `<tr class="detail"><td></td><td colspan="7">
          ${guidance(g)}
          <dl class="kv">
          ${stageLine(g)}
          <dt>Detector</dt><dd>${esc(a.detector)}</dd><dt>Status</dt><dd>${esc(a.status)}</dd>
          ${Object.entries(a.details || {}).map(([k, v]) =>
            `<dt>${esc(k.replace(/_/g, ' '))}</dt><dd class="mono">${esc(Array.isArray(v) ? v.join(', ') : v)}</dd>`).join('')}
          ${a.src_ip ? `<dt>Events</dt><dd><a href="#/events" data-act="see-events" data-ip="${esc(a.src_ip)}">Show events for ${esc(a.src_ip)}</a></dd>` : ''}
          ${Number.isInteger((a.details || {}).port) ? `<dt>High Risk Ports</dt><dd><a href="#/riskports?port=${a.details.port}">Show all traffic on port ${a.details.port}</a></dd>` : ''}
          ${a.device ? `<dt>Topology</dt><dd><a href="#/topology?select=${encodeURIComponent(a.device)}">Show ${esc(a.device)} on the map</a></dd>` : ''}
          ${fpLines}
          ${a.src_ip && !fp ? `<dt>Expected source?</dt><dd><button type="button" class="small" data-act="ignore" data-ip="${esc(a.src_ip)}">Stop alerting on ${esc(a.src_ip)} as a source</button></dd>` : ''}
        </dl></td></tr>` : '';
      return `<tr class="click ${a.status === 'resolved' || fp ? 'resolved' : ''} ${fresh.has(a.id) ? 'fresh' : ''}" data-act="toggle" data-id="${a.id}">
        <td>${sevBadge(a.severity)}</td>
        <td><div><b>${esc(a.title)}</b>${fp ? ' <span class="tag">False positive</span>' : ''}${g.stage && g.stage !== 'Network health' ? ` <span class="tag">${esc(g.stage)}</span>` : ''}</div><div class="muted">${esc(a.description)}</div></td>
        <td class="mono nowrap">${esc(a.src_ip || '—')}</td><td class="mono nowrap">${esc(a.device || '—')}</td>
        <td class="num">${num(a.count)}</td>
        <td class="nowrap" title="${clock(a.created, true)}">${ago(a.created)}</td>
        <td class="nowrap" title="${clock(a.last_seen, true)}">${ago(a.last_seen)}</td>
        <td class="nowrap">${buttons}</td></tr>${detail}`;
    }).join('') : `<tr><td colspan="8" class="empty">No alerts match.</td></tr>`;
  },
  actions: {
    toggle(el) {
      const id = Number(el.dataset.id), open = state.alerts.open;
      open.has(id) ? open.delete(id) : open.add(id);
      return pages.alerts.refresh();
    },
    async status(el) {
      await api('/alerts/status', 'POST', { ids: [Number(el.dataset.id)], status: el.dataset.status });
      await pages.alerts.refresh();  // also updates the badge
    },
    async 'ack-all'() {
      const r = await api('/alerts/status', 'POST', { all_open: true, status: 'ack' });
      toast(`${r.updated} alert(s) acknowledged`);
      await pages.alerts.refresh();
    },
    'see-events'(el) { seeEvents(el); },
    async fp(el) {
      const a = state.alerts.byId.get(Number(el.dataset.id));
      if (!a) return;
      const sent = await justify({
        title: 'Mark as false positive',
        intro: `"${a.title}". The ${a.detector.replace(/_/g, ' ')} detector will not raise an alert for ${a.entity} again, ` +
          'and nothing it finds there is notified. Other detectors still alert on it. You can undo this under False positives.',
        confirm: 'Mark as false positive',
        send: (who) => api('/alerts/false-positive', 'POST', { id: a.id, ...who }),
      });
      if (sent) { toast('Marked as a false positive'); await pages.alerts.refresh(); }
    },
    async ignore(el) {
      const ip = el.dataset.ip;
      if (!confirm(`Stop the source-based detectors alerting on ${ip}?\n\nUse this for scanners, management servers and other machines whose behaviour you have confirmed is expected. You can undo it under Settings → Detection → General.`)) return;
      await api('/ignore', 'POST', { ip, kind: 'source' });
      toast(`${ip} added to ignored sources`);
    },
  },
};

/* --- false positives: suppressions and the audit log --- */
const AUDIT_ACTIONS = {
  false_positive: 'Marked false positive',
  false_positive_again: 'Marked false positive (already suppressed)',
  suppression_removed: 'Suppression removed',
};
pages.suppressions = {
  interval: 15000,
  render() {
    main.innerHTML = `
      <div class="page-head"><div><h1>False positives</h1>
        <p>Alerts marked as false positives, and what has been held back since. A suppression matches one detector
          and one exact entity (an address, an address pair, an account); the same finding again raises no alert and
          sends no notification. Every marking and removal is kept in the audit log below.</p></div></div>
      <div class="card table-wrap"><h2>Active suppressions</h2><table>
        <thead><tr><th>Detector</th><th>Matches</th><th>Marked</th><th>Justification</th><th class="num">Held back</th><th>Last held back</th><th></th></tr></thead>
        <tbody id="sup-active"></tbody></table></div>
      <div class="card table-wrap" style="margin-top:16px"><h2>Removed suppressions</h2><table>
        <thead><tr><th>Detector</th><th>Matches</th><th>Marked</th><th>Removed</th><th>Reason for removal</th><th class="num">Held back</th></tr></thead>
        <tbody id="sup-removed"></tbody></table></div>
      <div class="card table-wrap" style="margin-top:16px"><h2>Audit log</h2><table>
        <thead><tr><th>When</th><th>Action</th><th>Analyst</th><th>From</th><th>Alert</th><th>Detector and entity</th><th>Justification</th></tr></thead>
        <tbody id="audit"></tbody></table></div>`;
  },
  async refresh() {
    const [{ suppressions }, { audit }] = await Promise.all([api('/suppressions'), api('/audit?limit=500')]);
    if (!$('#sup-active')) return;
    const det = (d) => esc(d.replace(/_/g, ' '));
    const when = (t) => `<span class="nowrap" title="${clock(t, true)}">${ago(t)}</span>`;
    const active = suppressions.filter((s) => s.active), removed = suppressions.filter((s) => !s.active);
    $('#sup-active').innerHTML = active.length ? active.map((s) => `<tr>
        <td>${det(s.detector)}</td><td class="mono">${esc(s.entity)}<div class="muted">${esc(s.title || '')}</div></td>
        <td>${esc(s.analyst)}<div class="muted">${when(s.created)}${s.alert_id ? ` · <a href="#/alerts?id=${s.alert_id}">alert</a>` : ''}</div></td>
        <td><div class="quote">${esc(s.justification)}</div></td>
        <td class="num">${num(s.hits)}</td><td>${s.last_hit ? when(s.last_hit) : '—'}</td>
        <td><button type="button" class="small danger" data-act="remove" data-id="${s.id}">Remove</button></td></tr>`).join('')
      : '<tr><td colspan="7" class="empty">No alerts are suppressed. Mark one from its details on the Alerts page.</td></tr>';
    $('#sup-removed').innerHTML = removed.length ? removed.map((s) => `<tr>
        <td>${det(s.detector)}</td><td class="mono">${esc(s.entity)}</td>
        <td>${esc(s.analyst)}<div class="muted">${when(s.created)}</div></td>
        <td>${esc(s.removed_by || '')}<div class="muted">${s.removed ? when(s.removed) : ''}</div></td>
        <td><div class="quote">${esc(s.removed_justification || '')}</div></td><td class="num">${num(s.hits)}</td></tr>`).join('')
      : '<tr><td colspan="6" class="empty">None.</td></tr>';
    $('#audit').innerHTML = audit.length ? audit.map((r) => {
      const d = r.detail || {};
      return `<tr><td>${when(r.ts)}</td><td>${esc(AUDIT_ACTIONS[r.action] || r.action)}</td><td>${esc(r.analyst || '')}</td>
        <td class="mono">${esc(r.source || '')}</td>
        <td>${r.alert_id ? `<a href="#/alerts?id=${r.alert_id}">#${r.alert_id}</a>` : '—'}</td>
        <td>${d.detector ? `${det(d.detector)}<div class="mono muted">${esc(d.entity || '')}</div>` : ''}</td>
        <td><div class="quote">${esc(d.justification || '')}</div></td></tr>`;
    }).join('') : '<tr><td colspan="7" class="empty">Nothing yet.</td></tr>';
    this.byId = new Map(suppressions.map((s) => [s.id, s]));
  },
  actions: {
    async remove(el) {
      const s = pages.suppressions.byId.get(Number(el.dataset.id));
      if (!s) return;
      const sent = await justify({
        title: 'Remove suppression',
        intro: `${s.detector.replace(/_/g, ' ')} will alert on ${s.entity} again from now on.`,
        confirm: 'Remove suppression',
        send: (who) => api('/suppressions/remove', 'POST', { id: s.id, ...who }),
      });
      if (sent) { toast('Suppression removed'); await pages.suppressions.refresh(); }
    },
  },
};

/* Follow a link to the Events page with its filters set from the link's data attributes. */
function seeEvents(el) {
  const d = el.dataset;
  Object.assign(state.events, { ip: d.ip || '', type: d.type || '', action: d.action || '', port: d.port || '', q: '', hours: d.hours || '24' });
}

/* --- high-risk ports --- */
/* 3389, or 161/udp for a port listed for one protocol (or 53/tcp/udp for both). */
const portText = (p) => (!p.protocols || p.protocols === 'any' ? String(p.port) : `${p.port}/${p.protocols}`);
const WAYS = [['inbound', 'From the internet'], ['outbound', 'To the internet'], ['internal', 'Inside the network']];
function sparkline(points, label) {
  const W = 132, H = 30, max = Math.max(1, ...points.map((p) => p[0] + p[1]));
  const x = (i) => 1 + (i / Math.max(1, points.length - 1)) * (W - 2), y = (v) => H - 2 - (v / max) * (H - 5);
  const path = (f) => points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(f(p)).toFixed(1)}`).join('');
  return `<svg class="spark" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="${esc(label)}">
    <path class="s1" d="${path((p) => p[0] + p[1])}"/><path class="s2" d="${path((p) => p[1])}"/></svg>`;
}
pages.riskports = {
  interval: 10000,
  render() {
    const s = state.riskports;
    const linked = Number(new URLSearchParams(location.hash.split('?')[1] || '').get('port'));
    if (linked) s.open = linked;  // links from alerts open their port
    main.innerHTML = `
      <div class="page-head"><div><h1>High Risk Ports</h1>
        <p>Traffic on the services attackers go for first: remote access, file sharing, clear-text protocols and databases.
          Ports with something to look at are listed first. <a href="#/settings/detection?focus=risk_ports">Edit the list of ports and protocols</a>.</p></div>
        <div class="row"><label class="check" style="margin:0"><input id="rp-flagged" type="checkbox" ${s.flagged ? 'checked' : ''}> Only ports with findings</label>
          <div class="seg" id="rp-range">${['1h', '6h', '24h', '7d'].map((r) =>
            `<button type="button" data-range="${r}" class="${r === s.range ? 'on' : ''}">${r}</button>`).join('')}</div></div></div>
      <div class="grid tiles" id="rp-tiles"></div>
      <div class="card table-wrap">
        <div class="chart-head" style="margin-bottom:6px"><h2 style="margin:0">Activity by port</h2>
          <div class="legend"><span><i style="background:var(--series-1)"></i>All connections</span>
            <span><i style="background:var(--series-2)"></i>Blocked</span></div><span></span></div>
        <table class="rp-table">
        <thead><tr><th>Service</th><th>Findings</th><th class="num" title="Allowed connections from internet addresses">Allowed in</th>
          <th class="num" title="Allowed connections to internet addresses">Allowed out</th>
          <th class="num" title="Allowed connections between internal addresses">Allowed inside</th>
          <th class="num">Blocked</th><th>Trend</th><th>Alerts</th></tr></thead>
        <tbody id="rp-rows"></tbody></table>
        <p class="muted" id="rp-quiet" style="margin:10px 6px 2px"></p></div>`;
    $('#rp-range').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-range]');
      if (!btn) return;
      s.range = btn.dataset.range;
      $$('#rp-range button').forEach((b) => b.classList.toggle('on', b === btn));
      act(() => this.refresh());
    });
    $('#rp-flagged').addEventListener('change', (e) => { s.flagged = e.target.checked; this.draw(); });
  },
  async refresh() {
    const s = state.riskports;
    const [d, detail] = await Promise.all([
      api('/riskports?range=' + s.range), s.open ? api('/riskports/port?port=' + s.open) : null]);
    this.data = d;
    this.detail = detail;
    this.draw();
  },
  draw() {
    const d = this.data, s = state.riskports;
    if (!d || !$('#rp-rows')) return;
    const sum = d.summary;
    const tile = (label, value, sub) =>
      `<div class="card tile"><div class="label">${label}</div><div class="value">${value}</div><div class="sub">${sub}</div></div>`;
    $('#rp-tiles').innerHTML =
      tile('Ports needing attention', num(sum.flagged), sum.flagged ? 'with a high or medium finding' : 'nothing stands out') +
      tile('Allowed in from the internet', compact(sum.exposed), sum.exposed ? `on ${sum.exposed_ports} port${sum.exposed_ports > 1 ? 's' : ''}, web excluded` : 'none on these ports, web excluded') +
      tile('Allowed out to the internet', compact(sum.egress), 'SMB, RDP, Telnet and the like; web and SSH excluded') +
      tile('Clear-text protocols allowed', compact(sum.cleartext), 'FTP, Telnet, POP3, IMAP, LDAP; web excluded') +
      tile('Blocked from the internet', compact(sum.blocked_inbound), 'attempts the firewall stopped');
    const shown = d.ports.filter((p) => !s.flagged || p.flags.length);
    const cell = (p, way) => p.totals[way][0] ? `<a href="#/events" data-act="see-events" data-port="${p.port}" data-action="allow" data-hours="${this.hours()}" title="Show these events">${num(p.totals[way][0])}</a>` : '<span class="muted">0</span>';
    $('#rp-rows').innerHTML = shown.length ? shown.map((p) => `
      <tr class="click ${s.open === p.port ? 'opened' : ''}" data-act="toggle" data-port="${p.port}" aria-expanded="${s.open === p.port}">
        <td class="nowrap"><b>${esc(p.name)}</b> <span class="mono muted">${esc(portText(p))}</span></td>
        <td>${p.flags.length ? p.flags.map((f) => `<span class="flag ${esc(f.severity)}" title="${esc(f.text)}">${esc(f.label)}</span>`).join(' ') : '<span class="muted">Nothing unusual</span>'}</td>
        <td class="num">${cell(p, 'inbound')}</td><td class="num">${cell(p, 'outbound')}</td><td class="num">${cell(p, 'internal')}</td>
        <td class="num">${p.blocked ? num(p.blocked) : '<span class="muted">0</span>'}</td>
        <td>${sparkline(p.series, `${p.name}: ${num(p.allowed + p.blocked)} connections, ${num(p.blocked)} blocked, over the last ${d.range}`)}</td>
        <td class="nowrap">${p.alerts ? `${sevBadge(p.alert_severity)} ${p.alerts}` : ''}</td>
      </tr>${s.open === p.port ? this.detailRow(p) : ''}`).join('')
      : `<tr><td colspan="8" class="empty">${d.ports.length ? 'No port has a finding in this range.'
        : !d.enabled ? 'High-risk port tracking is switched off under Settings → Detection.'
        : 'No traffic on these ports has been logged in this range. Firewalls must log connections (allowed as well as blocked) for anything to appear here.'}</td></tr>`;
    $('#rp-quiet').textContent = d.quiet.length ? `No traffic seen on: ${d.quiet.map((q) => `${q.name} ${portText(q)}`).join(', ')}.` : '';
    const chart = $('#rp-chart');
    const open = d.ports.find((p) => p.port === s.open);
    if (chart && open) {
      drawChart(chart, open.series.map((v, i) => ({ t: d.buckets[i],
        events: Math.round(((v[0] + v[1]) / d.bucket_minutes) * 10) / 10, blocked: Math.round((v[1] / d.bucket_minutes) * 10) / 10 })),
        d.bucket_minutes, ['All connections', 'Blocked']);
    }
  },
  hours() { return { '1h': '1', '6h': '24', '24h': '24', '7d': '168' }[state.riskports.range]; },
  detailRow(p) {
    const t = this.detail && this.detail.port === p.port ? this.detail : null;
    const who = (rows, way, role) => rows.length ? `<ul class="rp-who">${rows.map((r) => `
      <li><a class="mono" href="#/events" data-act="see-events" data-port="${p.port}" data-ip="${esc(r.ip)}" data-hours="24" title="Show this address's events on port ${p.port}">${esc(r.ip)}</a>
        ${r.new ? '<span class="flag medium">new</span>' : ''}
        <span class="muted">${r.internal ? 'internal' : 'internet'}</span>
        <span class="n">${r.allowed ? `${num(r.allowed)} allowed` : ''}${r.allowed && r.blocked ? ' · ' : ''}${r.blocked ? `${num(r.blocked)} blocked` : ''}</span></li>`).join('')}</ul>`
      : `<p class="muted">No ${role} recorded.</p>`;
    const ways = WAYS.filter(([way]) => p.totals[way][0] + p.totals[way][1]);
    return `<tr class="detail"><td colspan="8">
      <div class="advice"><p><b>Why this port is watched.</b> ${esc(p.why || 'Added to the list under Settings → Detection.')}</p>
        ${p.flags.length ? `<p><b>Findings</b></p><ul>${p.flags.map((f) => `<li><span class="flag ${esc(f.severity)}">${esc(f.label)}</span> ${esc(f.text)}</li>`).join('')}</ul>` : ''}</div>
      <div class="chart" id="rp-chart"></div>
      ${t ? `<div class="grid rp-ways">${ways.map(([way, label]) => `<div>
          <h2>${label} <span class="muted">· ${num(p.totals[way][0])} allowed, ${num(p.totals[way][1])} blocked</span></h2>
          <h3>Busiest sources <span class="muted">· last 24 h</span></h3>${who(t.directions[way].sources, way, 'sources')}
          <h3>Busiest destinations</h3>${who(t.directions[way].destinations, way, 'destinations')}</div>`).join('')}</div>
        ${t.alerts.length ? `<h2>Open alerts naming this port</h2><ul class="alert-list">${t.alerts.map((a) => `
          <li>${sevBadge(a.severity)}<div><a href="#/alerts?id=${a.id}">${esc(a.title)}</a></div><span class="when">${ago(a.last_seen)}</span></li>`).join('')}</ul>` : ''}
        <p class="muted">Sources and destinations are counted since Cerberus last started; totals and the chart come from stored history.</p>`
        : '<p class="muted">Loading…</p>'}
    </td></tr>`;
  },
  actions: {
    async toggle(el) {
      const s = state.riskports, port = Number(el.dataset.port);
      s.open = s.open === port ? null : port;
      pages.riskports.detail = null;
      pages.riskports.draw();
      if (s.open) {
        pages.riskports.detail = await api('/riskports/port?port=' + port);
        if (s.open === port) pages.riskports.draw();
      }
    },
    'see-events'(el) { seeEvents(el); },
  },
};

/* Why an alert matters and what to do: shared by the local and the site alert lists. */
function guidance(g) {
  return g.why ? `<div class="advice"><p><b>Why it matters.</b> ${esc(g.why)}</p>
    ${g.actions.length ? `<p><b>What to do</b></p><ol>${g.actions.map((x) => `<li>${esc(x)}</li>`).join('')}</ol>` : ''}</div>` : '';
}
function stageLine(g) {
  return g.stage ? `<dt>Attack stage</dt><dd>${esc(g.stage)}${g.technique ? ` · <a href="${esc(g.technique.url)}" target="_blank" rel="noopener noreferrer">ATT&amp;CK ${esc(g.technique.id)} ${esc(g.technique.name)}</a>` : ''}</dd>` : '';
}

/* --- sites (central console) --- */
state.sites = { site: '', status: 'open', severity: '', q: '', open: new Set(), only: null };
pages.sites = {
  interval: 10000,
  render() {
    const s = state.sites;
    const linked = Number(new URLSearchParams(location.hash.split('?')[1] || '').get('alert'));
    s.only = linked || null;
    if (linked) s.open.add(linked);
    main.innerHTML = `
      <div class="page-head"><div><h1>Sites</h1>
        <p>Every site runs its own Cerberus against its own devices and reports here. Acknowledging or resolving a site's
          alert here is passed back to that site.</p></div>
        <button type="button" class="primary" data-act="add-site">Add a site</button></div>
      <div id="site-token" hidden></div>
      <div class="grid tiles" id="site-tiles"></div>
      <div class="card table-wrap" style="margin-bottom:14px"><table>
        <thead><tr><th>Site</th><th>Status</th><th class="num">Messages / s</th><th class="num">Devices</th>
          <th>Open alerts</th><th>Health</th><th>Version</th><th></th></tr></thead>
        <tbody id="site-rows"></tbody></table></div>
      <h2>Alerts from all sites</h2>
      <div class="filters">
        <select id="sa-site" aria-label="Site"></select>
        <select id="sa-status" aria-label="Status">
          ${[['open', 'Open'], ['ack', 'Acknowledged'], ['active', 'Open + acknowledged'], ['resolved', 'Resolved'], ['all', 'All']]
            .map(([v, l]) => `<option value="${v}" ${v === s.status ? 'selected' : ''}>${l}</option>`).join('')}</select>
        <select id="sa-sev" aria-label="Minimum severity"><option value="">Any severity</option>
          ${SEVS.slice(1).map((v) => `<option value="${v}" ${v === s.severity ? 'selected' : ''}>${v} and above</option>`).join('')}</select>
        <input id="sa-q" type="search" placeholder="Search title, IP, device" value="${esc(s.q)}">
        ${s.only ? '<a href="#/sites">Showing one alert · show all</a>' : ''}
        <button type="button" data-act="ack-shown">Acknowledge all shown</button>
      </div>
      <div class="card table-wrap"><table>
        <thead><tr><th>Severity</th><th>Site</th><th>Alert</th><th>Source</th><th class="num">Count</th><th>Last seen</th><th></th></tr></thead>
        <tbody id="sa-rows"></tbody></table></div>`;
    const change = () => {
      Object.assign(s, { site: $('#sa-site').value, status: $('#sa-status').value, severity: $('#sa-sev').value, q: $('#sa-q').value.trim() });
      act(() => this.loadAlerts());
    };
    $$('.filters select').forEach((el) => el.addEventListener('change', change));
    $('#sa-q').addEventListener('input', debounce(change, 300));
  },
  async refresh() {
    const { sites, silent_minutes: silent } = await api('/sites');
    this.sites = sites;
    if (!$('#site-rows')) return;
    const s = state.sites, total = (o) => SEVS.reduce((n, k) => n + (o[k] || 0), 0);
    const open = {};
    sites.forEach((x) => SEVS.forEach((k) => { open[k] = (open[k] || 0) + (x.open_alerts[k] || 0); }));
    const tile = (label, value, sub) => `<div class="card tile"><div class="label">${label}</div><div class="value">${value}</div><div class="sub">${sub}</div></div>`;
    const silentCount = sites.filter((x) => x.state === 'silent').length;
    $('#site-tiles').innerHTML =
      tile('Sites', num(sites.length), `${num(sites.filter((x) => x.state === 'reporting').length)} reporting`) +
      tile('Not reporting', num(silentCount), silentCount ? `nothing for over ${silent} min` : 'all sites are in touch') +
      tile('Open alerts, all sites', num(total(open)), esc(SEVS.slice().reverse().filter((k) => open[k]).map((k) => `${open[k]} ${k}`).join(' · ')) || 'nothing needs attention') +
      tile('Messages / second, all sites', num(Math.round(sites.reduce((n, x) => n + (x.summary.rate || 0), 0))), 'sum of the sites\' last reports') +
      tile('Devices reporting', num(sites.reduce((n, x) => n + (x.summary.devices_active || 0), 0)),
        `of ${num(sites.reduce((n, x) => n + (x.summary.devices_total || 0), 0))} known across sites`);
    const stateLine = (x) => x.state === 'waiting' ? '<span class="muted">Waiting for first report</span>'
      : x.state === 'silent' ? `<span class="error">Silent since ${ago(x.last_seen)}</span>`
      : `<span class="dot on"></span>Reported ${ago(x.last_seen)}`;
    $('#site-rows').innerHTML = sites.length ? sites.map((x) => {
      const m = x.summary, sevs = SEVS.slice().reverse().filter((k) => x.open_alerts[k]);
      const health = [m.dropped ? `${compact(m.dropped)} dropped` : '', m.unwritten ? `${compact(m.unwritten)} not stored` : ''].filter(Boolean).join(' · ');
      return `<tr>
        <td><b>${esc(x.name)}</b>${x.managed ? ' <span class="tag" title="Set in CERBERUS_SITE_TOKENS_FILE">configured</span>' : ''}
          ${x.address ? `<div class="muted mono">${esc(x.address)}</div>` : ''}</td>
        <td class="nowrap">${stateLine(x)}</td>
        <td class="num">${x.last_seen ? num(m.rate) : '—'}</td>
        <td class="num">${x.last_seen ? `${num(m.devices_active)} <span class="muted">/ ${num(m.devices_total)}</span>` : '—'}</td>
        <td>${sevs.length ? sevs.map((k) => `<a href="#/sites" data-act="filter-site" data-site="${x.id}" data-sev="${k}">${sevBadge(k)} ${x.open_alerts[k]}</a>`).join(' ') : '<span class="muted">None</span>'}</td>
        <td>${health ? `<span class="error">${esc(health)}</span>` : x.last_seen ? '<span class="muted">Keeping up</span>' : ''}</td>
        <td class="mono">${esc(x.version || '')}</td>
        <td class="nowrap">${x.managed ? '' : `<button type="button" class="small" data-act="rotate" data-id="${x.id}" data-name="${esc(x.name)}">New token</button>
          <button type="button" class="small danger" data-act="delete-site" data-id="${x.id}" data-name="${esc(x.name)}">Remove</button>`}</td></tr>`;
    }).join('') : '<tr><td colspan="8" class="empty">No sites yet. Add one, then start Cerberus at that site with the settings shown.</td></tr>';
    const picked = String(s.site);
    $('#sa-site').innerHTML = '<option value="">All sites</option>' + sites.map((x) =>
      `<option value="${x.id}" ${String(x.id) === picked ? 'selected' : ''}>${esc(x.name)}</option>`).join('');
    await this.loadAlerts();
  },
  async loadAlerts() {
    const s = state.sites;
    const q = s.only ? new URLSearchParams({ id: s.only })
      : new URLSearchParams({ site: s.site || 0, status: s.status === 'all' ? '' : s.status, severity: s.severity, q: s.q });
    const { alerts } = await api('/site-alerts?' + q);
    this.alerts = alerts;
    const body = $('#sa-rows');
    if (!body) return;
    body.innerHTML = alerts.length ? alerts.map((a) => {
      const btn = (status, label) => `<button type="button" class="small" data-act="site-status" data-id="${a.id}" data-status="${status}">${label}</button>`;
      const buttons = (a.status === 'open' ? btn('ack', 'Acknowledge') : '') + (a.status !== 'resolved' ? btn('resolved', 'Resolve') : btn('open', 'Reopen'));
      const g = a.advice || { actions: [] };
      const detail = s.open.has(a.id) ? `<tr class="detail"><td></td><td colspan="6">${guidance(g)}<dl class="kv">${stageLine(g)}
          <dt>Site</dt><dd>${esc(a.site)}</dd>${a.device ? `<dt>Reported by</dt><dd class="mono">${esc(a.device)}</dd>` : ''}
          <dt>Status</dt><dd>${esc(a.status)}${a.pending ? ' <span class="muted">(waiting for the site to apply it)</span>' : ''}</dd>
          <dt>First seen</dt><dd>${clock(a.created, true)}</dd>
          ${Object.entries(a.details || {}).map(([k, v]) => `<dt>${esc(k.replace(/_/g, ' '))}</dt><dd class="mono">${esc(Array.isArray(v) ? v.join(', ') : v)}</dd>`).join('')}
          <dt>Investigate</dt><dd class="muted">Events, devices and maps stay at the site: open that site's own dashboard.</dd>
        </dl></td></tr>` : '';
      return `<tr class="click ${a.status === 'resolved' ? 'resolved' : ''}" data-act="toggle" data-id="${a.id}">
        <td>${sevBadge(a.severity)}</td><td class="nowrap"><b>${esc(a.site)}</b></td>
        <td><div><b>${esc(a.title)}</b>${g.stage && g.stage !== 'Network health' ? ` <span class="tag">${esc(g.stage)}</span>` : ''}</div><div class="muted">${esc(a.description)}</div></td>
        <td class="mono nowrap">${esc(a.src_ip || '—')}</td><td class="num">${num(a.count)}</td>
        <td class="nowrap" title="${clock(a.last_seen, true)}">${ago(a.last_seen)}</td><td class="nowrap">${buttons}</td></tr>${detail}`;
    }).join('') : `<tr><td colspan="7" class="empty">${this.sites && this.sites.length ? 'No alerts match.' : 'Alerts appear here once a site reports.'}</td></tr>`;
  },
  showToken(name, token, fresh) {
    const box = $('#site-token');
    const origin = location.origin;
    box.innerHTML = `<div class="card token-card">
      <h2>${fresh ? 'Site added' : 'New token'}: ${esc(name)}</h2>
      <p>This token is shown only once. Give the site's Cerberus these settings (for example in its <span class="mono">.env</span>),
        then restart it. ${fresh ? '' : 'The previous token stops working now.'}</p>
      <pre class="mono" id="token-text">CERBERUS_SITE_NAME=${esc(name)}
CERBERUS_CENTRAL_URL=${esc(origin)}
CERBERUS_CENTRAL_TOKEN=${esc(token)}</pre>
      <p class="muted">Use the address the site can reach this console on, over HTTPS in production. See deploy/README.md.</p>
      <div class="actions"><button type="button" data-act="copy-token">Copy</button><button type="button" data-act="hide-token">Done</button></div></div>`;
    box.hidden = false;
  },
  actions: {
    async 'add-site'() {
      const name = prompt('Name for the new site (letters, digits, dashes; no spaces), e.g. london-dc1');
      if (!name) return;
      const r = await api('/sites', 'POST', { name: name.trim() });
      pages.sites.showToken(r.site.name, r.token, true);
      await pages.sites.refresh();
    },
    async rotate(el) {
      if (!confirm(`Issue a new token for ${el.dataset.name}? The site stops reporting until it is given the new one.`)) return;
      const r = await api(`/sites/${el.dataset.id}/token`, 'POST');
      pages.sites.showToken(el.dataset.name, r.token, false);
    },
    async 'delete-site'(el) {
      if (!confirm(`Remove ${el.dataset.name} and every alert it has reported here? The site itself is not changed.`)) return;
      await api(`/sites/${el.dataset.id}`, 'DELETE');
      toast(`${el.dataset.name} removed`);
      await pages.sites.refresh();
    },
    async 'copy-token'() {
      await navigator.clipboard.writeText($('#token-text').textContent);
      toast('Copied');
    },
    'hide-token'() { $('#site-token').hidden = true; $('#site-token').innerHTML = ''; },
    'filter-site'(el) {
      Object.assign(state.sites, { site: el.dataset.site, severity: el.dataset.sev, status: 'open', only: null });
      return pages.sites.render() || pages.sites.refresh();
    },
    toggle(el) {
      const id = Number(el.dataset.id), open = state.sites.open;
      open.has(id) ? open.delete(id) : open.add(id);
      return pages.sites.loadAlerts();
    },
    async 'site-status'(el) {
      await api('/site-alerts/status', 'POST', { ids: [Number(el.dataset.id)], status: el.dataset.status });
      toast('Saved; the site applies it with its next report');
      await pages.sites.refresh();
    },
    async 'ack-shown'() {
      const ids = (pages.sites.alerts || []).filter((a) => a.status === 'open').map((a) => a.id);
      if (!ids.length) return toast('No open alerts shown');
      if (!confirm(`Acknowledge ${ids.length} open alert${ids.length > 1 ? 's' : ''}?`)) return;
      await api('/site-alerts/status', 'POST', { ids, status: 'ack' });
      await pages.sites.refresh();
    },
  },
};

/* --- events --- */
const EVENT_TYPES = ['traffic', 'threat', 'auth_failure', 'auth_success', 'link_state', 'config_change',
  'security_violation', 'stp_guard', 'loop_detected', 'stp_change', 'mac_flap', 'system', 'system_restart', 'other'];
pages.events = {
  interval: 5000,
  render() {
    const s = state.events;
    const opt = (v, l, cur) => `<option value="${v}" ${v === cur ? 'selected' : ''}>${l}</option>`;
    main.innerHTML = `
      <div class="page-head"><div><h1>Events</h1><p>Every syslog message received, after the connector parsed it. Click a row for all fields.</p></div></div>
      <div class="filters">
        <select id="e-hours" aria-label="Time range">${[['1', 'Last hour'], ['24', 'Last 24 hours'], ['168', 'Last 7 days'], ['8760', 'Everything kept']].map(([v, l]) => opt(v, l, s.hours)).join('')}</select>
        <select id="e-type" aria-label="Event type">${opt('', 'Any type', s.type)}${EVENT_TYPES.map((t) => opt(t, t.replace(/_/g, ' '), s.type)).join('')}</select>
        <select id="e-action" aria-label="Action">${opt('', 'Any action', s.action)}${opt('block', 'Blocked', s.action)}${opt('allow', 'Allowed', s.action)}</select>
        <input id="e-ip" type="text" placeholder="IP (source or destination)" value="${esc(s.ip)}">
        <input id="e-port" type="text" inputmode="numeric" placeholder="Dest. port" style="min-width:0;width:100px" value="${esc(s.port)}">
        <input id="e-q" type="search" placeholder="Text in message" value="${esc(s.q)}">
        <label class="check" style="margin:0"><input id="e-live" type="checkbox" ${s.live ? 'checked' : ''}> Live</label>
      </div>
      <div class="card table-wrap"><table>
        <thead><tr><th>Time</th><th>Device</th><th>Type</th><th>Action</th><th>Source</th><th>Destination</th><th>Message</th></tr></thead>
        <tbody id="rows"></tbody></table>
        <div class="actions"><button type="button" data-act="older">Load older</button></div></div>`;
    const change = () => {
      Object.assign(s, { hours: $('#e-hours').value, type: $('#e-type').value, action: $('#e-action').value,
        ip: $('#e-ip').value.trim(), port: $('#e-port').value.trim(), q: $('#e-q').value.trim(), live: $('#e-live').checked });
      act(() => this.load(false));
    };
    $$('.filters select, #e-live').forEach((el) => el.addEventListener('change', change));
    $$('.filters input[type=text], .filters input[type=search]').forEach((el) => el.addEventListener('input', debounce(change, 350)));
  },
  refresh() {
    // While paused, or while the reader has rows expanded or has paged back, leave the table alone.
    if (this.loaded && (!state.events.live || this.paged)) return Promise.resolve();
    return this.load(false);
  },
  async load(older) {
    const s = state.events;
    const q = new URLSearchParams({ hours: s.hours, type: s.type, action: s.action, ip: s.ip, port: s.port, q: s.q });
    if (older && s.rows.length) q.set('before', s.rows[s.rows.length - 1].id);
    let events;
    try {
      ({ events } = await api('/events?' + q));
    } catch (err) {
      // A search that was too slow would be just as slow five seconds from now.
      if (/stopped after/.test(err.message)) { s.live = false; if ($('#e-live')) $('#e-live').checked = false; }
      throw err;
    }
    s.rows = older ? s.rows.concat(events) : events;
    this.paged = older ? true : false;
    this.loaded = true;
    this.draw();
    if (older && !events.length) toast('No older events');
  },
  draw() {
    const s = state.events, body = $('#rows');
    if (!body) return;
    const ep = (ip, port) => ip ? esc(ip.includes(':') && port != null ? `[${ip}]` : ip) + (port != null ? ':' + esc(port) : '') : '—';
    body.innerHTML = s.rows.length ? s.rows.map((e) => {
      const detail = s.open.has(e.id) ? `<tr class="detail"><td colspan="7"><dl class="kv">
        <dt>Message</dt><dd class="mono">${esc(e.message)}</dd>
        ${[['Hostname', e.hostname], ['Connector', e.connector], ['Program', e.app], ['Syslog severity', e.sev], ['Protocol', e.proto],
          ['Bytes', e.bytes], ['User', e.user], ['Interface', e.interface]].filter(([, v]) => v !== null && v !== '')
          .map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join('')}
        ${Object.entries(e.extra || {}).map(([k, v]) => `<dt>${esc(k.replace(/_/g, ' '))}</dt><dd class="mono">${esc(v)}</dd>`).join('')}
      </dl></td></tr>` : '';
      return `<tr class="click" data-act="toggle" data-id="${e.id}">
        <td class="nowrap mono" title="${clock(e.ts, true)}">${clock(e.ts, Date.now() / 1000 - e.ts > 86400)}</td>
        <td class="nowrap">${esc(e.hostname || e.device)}</td>
        <td class="nowrap">${esc((e.event_type || '').replace(/_/g, ' '))}</td>
        <td>${e.action ? `<span class="tag ${e.action === 'block' ? 'block' : 'allow'}">${e.action === 'block' ? 'blocked' : 'allowed'}</span>` : ''}</td>
        <td class="mono nowrap">${ep(e.src_ip, e.src_port)}</td><td class="mono nowrap">${ep(e.dst_ip, e.dst_port)}</td>
        <td class="msg mono">${esc(e.message)}</td></tr>${detail}`;
    }).join('') : `<tr><td colspan="7" class="empty">No events match.</td></tr>`;
  },
  actions: {
    toggle(el) {
      const id = Number(el.dataset.id), open = state.events.open;
      open.has(id) ? open.delete(id) : open.add(id);
      pages.events.draw();
    },
    older() { return pages.events.load(true); },
  },
};

/* --- devices --- */
pages.devices = {
  render() {
    main.innerHTML = `
      <div class="page-head"><div><h1>Devices</h1>
        <p>Every source that has sent syslog. The connector is chosen per message automatically; pin one only if a device's logs are being misread.</p></div>
        <button type="button" data-act="reload">Refresh</button></div>
      <div class="filters">
        <input id="d-q" type="search" placeholder="Search address, hostname or label" value="${esc(state.devices.q)}">
        <select id="d-status" aria-label="Status">${[['', 'Any status'], ['reporting', 'Reporting'], ['quiet', 'Quiet for over 15 min'],
          ['snmp-failed', 'SNMP failing'], ['snmp-ok', 'SNMP answering'], ['snmp-none', 'Not polled']].map(([v, l]) =>
          `<option value="${v}" ${v === state.devices.status ? 'selected' : ''}>${l}</option>`).join('')}</select>
        <select id="d-connector" aria-label="Connector"></select>
        <select id="d-sort" aria-label="Sort">${[['recent', 'Newest activity first'], ['quiet', 'Longest quiet first'], ['name', 'By name'],
          ['volume', 'Most messages first']].map(([v, l]) => `<option value="${v}" ${v === state.devices.sort ? 'selected' : ''}>Sort: ${l}</option>`).join('')}</select>
        <span class="muted" id="d-count"></span>
      </div>
      <div class="card table-wrap"><table>
        <thead><tr><th>Device</th><th>Hostname</th><th>Label</th><th>Connector</th><th>SNMP polling</th><th class="num">Messages</th><th>Last seen</th><th></th></tr></thead>
        <tbody id="rows"></tbody></table>
        <div class="actions" id="d-more" hidden><button type="button" data-act="more">Show more</button></div></div>`;
    if (!this.bound) main.addEventListener('change', this.onMode);
    this.bound = true;
    const change = () => {
      Object.assign(state.devices, { q: $('#d-q').value.trim().toLowerCase(), status: $('#d-status').value,
        connector: $('#d-connector').value, sort: $('#d-sort').value, limit: 100 });
      this.draw();
    };
    $$('.filters select').forEach((el) => el.addEventListener('change', change));
    $('#d-q').addEventListener('input', debounce(change, 200));
  },
  onMode(e) {
    // Show the community box only while "own community" is selected.
    if (current !== 'devices' || !e.target.classList.contains('d-snmp')) return;
    $('.d-community', e.target.closest('tr')).hidden = e.target.value !== 'custom';
  },
  snmpStatus(s) {
    if (!s.pollable) return `<span class="muted">${esc(s.reason)}</span>`;
    if (!s.polled) return '<span class="muted">Waiting for first poll</span>';
    if (s.ok) return `<span class="dot on"></span>Answered ${ago(s.polled)}`;
    const wait = s.next_try ? s.next_try - Date.now() / 1000 : 0;
    return `<span class="error">Failed ${ago(s.polled)}: ${esc(s.error)}</span>` +
      (wait > 600 ? ` <span class="muted">· next try in ${span(wait)}</span>` : '');
  },
  async refresh() {
    const [{ devices }, { connectors }] = await Promise.all([api('/devices'), api('/connectors')]);
    this.rows = devices;
    this.connectors = connectors;
    const used = [...new Set(devices.map((d) => d.connector_pin || d.connector_seen).filter(Boolean))].sort();
    const names = Object.fromEntries(connectors.map((c) => [c.id, c.name]));
    $('#d-connector').innerHTML = '<option value="">Any connector</option>' + used.map((id) =>
      `<option value="${esc(id)}" ${id === state.devices.connector ? 'selected' : ''}>${esc(names[id] || id)}</option>`).join('');
    this.draw();
  },
  draw() {
    const s = state.devices, connectors = this.connectors, now = Date.now() / 1000;
    if (!this.rows || !$('#rows')) return;
    const quiet = (d) => now - d.last_seen >= 900;
    const status = {
      reporting: (d) => !quiet(d), quiet,
      'snmp-failed': (d) => d.snmp.pollable && d.snmp.polled && !d.snmp.ok,
      'snmp-ok': (d) => d.snmp.pollable && d.snmp.ok,
      'snmp-none': (d) => !d.snmp.pollable,
    }[s.status];
    const order = {
      recent: (a, b) => b.last_seen - a.last_seen, quiet: (a, b) => a.last_seen - b.last_seen,
      name: (a, b) => (a.name || a.hostname || a.id).localeCompare(b.name || b.hostname || b.id, undefined, { numeric: true }),
      volume: (a, b) => b.events - a.events,
    }[s.sort];
    const matching = this.rows.filter((d) => (!status || status(d)) && (!s.connector || (d.connector_pin || d.connector_seen) === s.connector)
      && (!s.q || [d.id, d.ip, d.hostname, d.name].some((v) => String(v || '').toLowerCase().includes(s.q)))).sort(order);
    const devices = matching.slice(0, s.limit);
    const failing = this.rows.filter(status ? () => false : (d) => d.snmp.pollable && d.snmp.polled && !d.snmp.ok).length;
    $('#d-count').textContent = this.rows.length === 0 ? '' : matching.length === this.rows.length
      ? `${num(this.rows.length)} devices · ${num(this.rows.filter(quiet).length)} quiet` + (failing ? ` · ${num(failing)} failing SNMP` : '')
      : `${num(matching.length)} of ${num(this.rows.length)} devices`;
    $('#d-more').hidden = matching.length <= s.limit;
    $('#rows').innerHTML = devices.length ? devices.map((d) => `
      <tr data-id="${esc(d.id)}">
        <td class="mono nowrap"><span class="dot ${now - d.last_seen < 900 ? 'on' : ''}" title="${now - d.last_seen < 900 ? 'Reporting' : 'Quiet for over 15 minutes'}"></span>${esc(d.id)}${d.ip !== d.id ? ` <span class="muted">(${esc(d.ip)})</span>` : ''}</td>
        <td>${esc(d.hostname || '—')}</td>
        <td><input type="text" class="d-name" aria-label="Label" placeholder="e.g. Core switch" value="${esc(d.name)}"></td>
        <td><select class="d-pin" aria-label="Connector">
          <option value="">Auto${d.connector_seen ? ` (${esc(d.connector_seen)})` : ''}</option>
          ${connectors.map((c) => `<option value="${esc(c.id)}" ${c.id === d.connector_pin ? 'selected' : ''}>${esc(c.name)}</option>`).join('')}
        </select></td>
        <td class="snmp-cell"><div class="snmp-status">${this.snmpStatus(d.snmp)}</div>
          <div class="row"><select class="d-snmp" aria-label="SNMP community">
            ${[['default', 'Default community'], ['custom', 'Own community'], ['off', 'Do not poll']].map(([v, l]) =>
              `<option value="${v}" ${v === d.snmp_mode ? 'selected' : ''}>${l}</option>`).join('')}</select>
          <input type="password" class="d-community" aria-label="Community string" autocomplete="new-password"
            placeholder="${d.snmp_has_community ? 'unchanged' : 'community'}" ${d.snmp_mode === 'custom' ? '' : 'hidden'}>
          <input type="text" class="d-host" aria-label="SNMP address" placeholder="address, if not ${esc(d.ip)}" value="${esc(d.snmp_host)}"></div></td>
        <td class="num">${num(d.events)}</td><td class="nowrap" title="${clock(d.last_seen, true)}">${ago(d.last_seen)}</td>
        <td class="nowrap"><button type="button" class="small" data-act="save">Save</button>
          <button type="button" class="small danger" data-act="forget">Forget</button></td>
      </tr>`).join('')
      : `<tr><td colspan="8" class="empty">${this.rows.length ? 'No device matches these filters.'
        : 'Nothing has sent syslog yet. Point a device at this host on UDP or TCP port 514.'}</td></tr>`;
  },
  actions: {
    reload() { return pages.devices.refresh(); },
    more() { state.devices.limit += 200; pages.devices.draw(); },
    async save(el) {
      const row = el.closest('tr');
      const d = await api('/devices', 'PUT', {
        id: row.dataset.id, name: $('.d-name', row).value, connector_pin: $('.d-pin', row).value,
        snmp_mode: $('.d-snmp', row).value, snmp_host: $('.d-host', row).value.trim(),
        // An empty box means "keep what is stored"; the server never sends the secret back.
        snmp_community: $('.d-community', row).value || '********',
      });
      $('.snmp-status', row).innerHTML = pages.devices.snmpStatus(d.snmp);
      const kept = pages.devices.rows.findIndex((x) => x.id === d.id);
      if (kept >= 0) pages.devices.rows[kept] = d;
      toast('Saved');
    },
    async forget(el) {
      const id = el.closest('tr').dataset.id;
      if (!confirm(`Forget ${id}? Its stored events and alerts are kept, and it will reappear if it sends logs again.`)) return;
      await api('/devices/forget', 'POST', { id });
      await pages.devices.refresh();
    },
  },
};

/* --- topology --- */
const KIND = { firewall: ['FW', 'Firewall'], switch: ['SW', 'Switch'], ap: ['AP', 'Access point'], device: ['', 'Device'] };
const bps = (v) => v == null ? '—' : v >= 1e9 ? (v / 1e9).toFixed(1) + ' Gbps' : v >= 1e6 ? (v / 1e6).toFixed(1) + ' Mbps' : v >= 1e3 ? (v / 1e3).toFixed(0) + ' kbps' : v + ' bps';
const speed = (m) => !m ? '' : m >= 1000 ? (m / 1000) + ' Gbps' : m + ' Mbps';
function uptime(s) {
  if (!s) return '—';
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
  return d ? `${d} d ${h} h` : `${h} h ${Math.floor((s % 3600) / 60)} min`;
}
function loadPins() { try { return JSON.parse(localStorage.getItem('cerberus-topology') || '{}'); } catch { return {}; } }
function savePins(pins) { try { localStorage.setItem('cerberus-topology', JSON.stringify(pins)); } catch { /* private mode */ } }

/* Fruchterman-Reingold on the linked nodes. Deterministic: same graph, same picture. */
function layoutGraph(nodes, links, W, H, pins) {
  const pos = {}, n = nodes.length, pad = 70;
  nodes.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / Math.max(n, 1);
    pos[node.id] = pins[node.id] ? { x: pins[node.id].x * W, y: pins[node.id].y * H, pin: true }
      : { x: W / 2 + Math.cos(angle) * W * 0.3, y: H / 2 + Math.sin(angle) * H * 0.3 };
  });
  const big = n > 60;
  const k = Math.sqrt(((W - 2 * pad) * (H - 2 * pad)) / Math.max(n, 1)) * (big ? 0.5 : 0.9);
  // The repulsion pass compares every pair of nodes, so big maps get fewer rounds.
  const steps = n > 900 ? 50 : n > 400 ? 110 : n > 150 ? 200 : 300;
  for (let step = 0; step < steps; step++) {
    const temp = (W / 8) * (1 - step / steps), move = {};
    nodes.forEach((a) => { move[a.id] = { x: 0, y: 0 }; });
    for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) {
      const a = pos[nodes[i].id], b = pos[nodes[j].id];
      let dx = a.x - b.x, dy = a.y - b.y;
      const d = Math.max(Math.hypot(dx, dy), 0.01), f = (k * k) / d;
      dx = (dx / d) * f; dy = (dy / d) * f;
      move[nodes[i].id].x += dx; move[nodes[i].id].y += dy;
      move[nodes[j].id].x -= dx; move[nodes[j].id].y -= dy;
    }
    links.forEach((l) => {
      const a = pos[l.a], b = pos[l.b];
      if (!a || !b) return;
      const dx = a.x - b.x, dy = a.y - b.y, d = Math.max(Math.hypot(dx, dy), 0.01), f = (d * d) / k;
      move[l.a].x -= (dx / d) * f; move[l.a].y -= (dy / d) * f;
      move[l.b].x += (dx / d) * f; move[l.b].y += (dy / d) * f;
    });
    nodes.forEach((node) => {
      const p = pos[node.id], mv = move[node.id];
      if (p.pin) return;
      const pull = big ? 0.12 : 0.05;
      mv.x += (W / 2 - p.x) * pull; mv.y += (H / 2 - p.y) * pull;
      const d = Math.max(Math.hypot(mv.x, mv.y), 0.01);
      p.x = Math.min(W - pad, Math.max(pad, p.x + (mv.x / d) * Math.min(d, temp)));
      p.y = Math.min(H - pad, Math.max(40, p.y + (mv.y / d) * Math.min(d, temp)));
    });
  }
  return pos;
}

pages.topology = {
  interval: 15000,
  render() {
    this.selected = null; this.graph = null; this.formFilled = false;
    main.innerHTML = `
      <div class="page-head"><div><h1>Topology</h1>
        <p>Built from what each device reports about its neighbours over SNMP (LLDP and CDP). Drag devices to arrange them; a ring and count mark devices with open alerts.</p></div>
        <div class="row"><span class="muted" id="topo-status"></span><button type="button" data-act="poll">Poll now</button></div></div>
      <div class="grid topo-grid">
        <div class="card">
          <div class="filters topo-tools" id="topo-tools">
            <input id="topo-find" type="search" placeholder="Find a device (Enter to go to it)" aria-label="Find a device on the map">
            <div class="seg"><button type="button" data-act="zoom-out" title="Zoom out" aria-label="Zoom out">−</button>
              <button type="button" data-act="zoom-fit" title="Show the whole map">Fit</button>
              <button type="button" data-act="zoom-in" title="Zoom in" aria-label="Zoom in">+</button></div>
            <label class="check" style="margin:0" id="topo-ends-label" hidden><input id="topo-ends" type="checkbox"> <span></span></label>
            <span class="muted">Drag the background to pan · Ctrl + scroll to zoom</span>
          </div>
          <div class="topo-map" id="topo-map"><svg id="topo-svg" role="img" aria-label="Network topology map"></svg></div>
          <div class="legend topo-legend">
            <span><svg width="26" height="14"><rect class="node-shape" x="1" y="1" width="24" height="12" rx="3"/></svg>Log source</span>
            <span><svg width="26" height="14"><rect class="node-shape unmanaged" x="1" y="1" width="24" height="12" rx="3"/></svg>Seen by a neighbour only</span>
            <span><svg width="26" height="14"><line class="link" x1="0" x2="26" y1="7" y2="7"/></svg>Link up</span>
            <span><svg width="26" height="14"><line class="link down" x1="0" x2="26" y1="7" y2="7"/></svg>Link down</span>
          </div>
          <div id="topo-shelf"></div>
        </div>
        <div class="card" id="topo-panel"><p class="muted">Select a device on the map to see its interfaces and neighbours.</p></div>
      </div>
      <form class="card" id="snmp-form" style="margin-top:14px">
        <h2>SNMP polling</h2>
        <p class="muted" style="margin-top:-6px">SNMP v2c, read-only. Every device that sends logs is polled with the default community unless you change that per device on the Devices page.</p>
        <label class="check"><input id="s-enabled" type="checkbox"> Poll devices over SNMP</label>
        <div class="form-grid">
          <div><label for="s-community">Default community string</label><input id="s-community" type="password" autocomplete="new-password"></div>
          <div><label for="s-interval">Poll every (minutes)</label><input id="s-interval" type="number" min="1" max="1440"></div>
          <div><label for="s-concurrency">Devices polled at the same time</label><input id="s-concurrency" type="number" min="1" max="64"></div>
        </div>
        <label for="s-networks">Only poll devices in these networks (one per line). The community string is sent unencrypted, and a syslog source address can be forged, so keep this to networks you control.</label>
        <textarea id="s-networks" rows="3" class="mono" spellcheck="false"></textarea>
        <div class="actions"><button class="primary" type="submit">Save</button></div>
      </form>`;
    $('#snmp-form').addEventListener('submit', (e) => { e.preventDefault(); act(() => this.saveSettings()); });
    const svg = $('#topo-svg');
    this.find = ''; this.showEnds = null; this.pos = null; this.signature = null;
    $('#topo-find').addEventListener('input', debounce(() => { this.find = $('#topo-find').value.trim().toLowerCase(); this.draw(); }, 150));
    $('#topo-find').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); act(() => this.goTo()); } });
    $('#topo-ends').addEventListener('change', (e) => { this.showEnds = e.target.checked; this.show(); });
    svg.addEventListener('wheel', (e) => {
      if (!e.ctrlKey && !e.metaKey) return;  // plain scrolling still scrolls the page
      e.preventDefault();
      const at = this.world(e);
      this.zoom(e.deltaY > 0 ? 1.2 : 1 / 1.2, at.x, at.y);
    }, { passive: false });
    svg.addEventListener('pointerdown', (e) => {
      if (!this.view) return;
      const g = e.target.closest('[data-node]');
      this.drag = g ? { id: g.dataset.node, x: e.clientX, y: e.clientY, moved: false }
        : { pan: true, x: e.clientX, y: e.clientY, vx: this.view.x, vy: this.view.y, scale: svg.getScreenCTM().a };
      svg.setPointerCapture(e.pointerId);
    });
    svg.addEventListener('pointermove', (e) => {
      const d = this.drag;
      if (!d) return;
      if (d.pan) {
        this.view.x = d.vx - (e.clientX - d.x) / d.scale;  // scale: screen pixels per map unit
        this.view.y = d.vy - (e.clientY - d.y) / d.scale;
        this.applyView();
        return;
      }
      if (!d.moved && Math.hypot(e.clientX - d.x, e.clientY - d.y) < 4) return;
      d.moved = true;
      const at = this.world(e), p = this.pos[d.id];
      p.x = Math.min(this.W - 30, Math.max(30, at.x));
      p.y = Math.min(this.H - 40, Math.max(30, at.y));
      // One redraw per frame, however fast the pointer moves.
      if (!this.frame) this.frame = requestAnimationFrame(() => { this.frame = 0; this.draw(); });
    });
    svg.addEventListener('pointerup', () => {
      const d = this.drag;
      this.drag = null;
      if (!d || d.pan) return;
      if (d.moved) {
        const pins = loadPins(), p = this.pos[d.id];
        pins[d.id] = { x: p.x / this.W, y: p.y / this.H };
        savePins(pins);
      } else {
        act(() => this.select(d.id));
      }
    });
    svg.addEventListener('keydown', (e) => {
      const g = e.target.closest('[data-node]');
      if (g && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); act(() => this.select(g.dataset.node)); }
    });
  },
  async refresh() {
    const g = await api('/topology');
    if (!$('#topo-svg')) return;
    if (!this.formFilled) { this.fillForm(g.settings); this.formFilled = true; }
    const s = g.settings;
    $('#topo-status').textContent = !s.enabled ? 'SNMP polling is off'
      : `${g.polled_ok} of ${g.pollable} polled devices answering`
        + (g.sweeping ? ` · polling now, ${g.in_flight} in progress` : g.last_poll ? ` · last poll ${ago(g.last_poll)}` : '');
    this.graph = g;
    this.show();
    const wanted = new URLSearchParams(location.hash.split('?')[1] || '').get('select');
    if (wanted && !this.selected && g.nodes.some((n) => n.id === 'dev:' + wanted)) {
      this.centre('dev:' + wanted);
      await this.select('dev:' + wanted);
    }
    const shelf = g.nodes.filter((n) => !n.linked);
    const hasMap = g.nodes.some((n) => n.linked);
    $('#topo-map').hidden = !hasMap;
    $('.topo-legend').hidden = !hasMap;
    const why = !s.enabled ? 'Switch on SNMP polling below to build the map.'
      : !hasMap ? 'No neighbour information yet. Devices need SNMP v2c enabled with this community, and LLDP or CDP running.' : '';
    $('#topo-shelf').innerHTML = (why ? `<p class="empty">${why}</p>` : '') + (shelf.length ? `
      <h2 class="shelf-title">Not on the map <span class="muted">· no neighbour data for ${shelf.length > 1 ? `these ${num(shelf.length)} devices` : 'this device'}</span></h2>
      <div class="row">${shelf.sort((a, b) => b.alerts - a.alerts).slice(0, 60).map((n) => `<button type="button" class="chip ${n.severity ? 'alerting' : ''}" data-act="pick" data-id="${esc(n.id)}">
        ${esc(n.label)}${n.alerts ? ` <span class="pill sev-${esc(n.severity)}">${n.alerts}</span>` : ''}</button>`).join('')}
        ${shelf.length > 60 ? `<a href="#/devices">and ${num(shelf.length - 60)} more on the Devices page</a>` : ''}</div>` : '');
  },
  /* Work out what is on the map, lay it out again only if that changed, and draw. */
  show() {
    const g = this.graph;
    // An endpoint is something only one neighbour reports and that sends us nothing:
    // phones, access points, PCs. On a big network they outnumber everything else.
    const isEnd = (n) => n.linked && !n.managed && n.links <= 1;
    const ends = g.nodes.filter(isEnd).length;
    if (this.showEnds === null) this.showEnds = ends <= 40;
    $('#topo-ends-label').hidden = !ends;
    $('#topo-ends').checked = this.showEnds;
    $('#topo-ends-label span').textContent = `Show ${num(ends)} endpoint${ends > 1 ? 's' : ''}`;
    const nodes = g.nodes.filter((n) => n.linked && (this.showEnds || !isEnd(n)));
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const folded = {};
    g.links.forEach((l) => {
      if (byId.has(l.a) !== byId.has(l.b)) { const kept = byId.has(l.a) ? l.a : l.b; folded[kept] = (folded[kept] || 0) + 1; }
    });
    this.vis = { nodes, byId, folded, links: g.links.filter((l) => byId.has(l.a) && byId.has(l.b)) };
    const signature = JSON.stringify([nodes.map((n) => n.id), this.vis.links.map((l) => l.a + l.b)]);
    if (signature !== this.signature || !this.pos) this.layout();
    this.signature = signature;
    this.draw();
  },
  layout() {
    const svg = $('#topo-svg'), vis = this.vis;
    this.baseW = Math.max(480, $('#topo-map').clientWidth || 800);
    const baseH = Math.max(360, Math.min(680, 220 + vis.nodes.length * 42));
    // The canvas grows with the network so devices keep their spacing; the view
    // starts zoomed out to show all of it.
    const grow = Math.max(1, Math.sqrt(vis.nodes.length / 9) - 0.8);
    this.W = this.baseW * grow; this.H = baseH * grow;
    svg.style.height = baseH + 'px';
    this.pos = layoutGraph(vis.nodes, vis.links, this.W, this.H, loadPins());
    this.view = { x: 0, y: 0, w: this.W, h: this.H };
    this.applyView();
  },
  world(e) {
    const svg = $('#topo-svg');
    const at = new DOMPoint(e.clientX, e.clientY).matrixTransform(svg.getScreenCTM().inverse());
    return { x: at.x, y: at.y };
  },
  applyView() {
    const v = this.view, svg = $('#topo-svg');
    v.x = Math.min(this.W - v.w, Math.max(0, v.x));
    v.y = Math.min(this.H - v.h, Math.max(0, v.y));
    svg.setAttribute('viewBox', `${v.x} ${v.y} ${v.w} ${v.h}`);
    svg.classList.toggle('far', v.w / this.baseW > 1.8);  // too small to read: drop the fine print
  },
  zoom(factor, cx, cy) {
    const v = this.view;
    if (!v) return;
    const w = Math.min(this.W, Math.max(this.baseW * 0.5, v.w * factor)), k = w / v.w;
    cx = cx ?? v.x + v.w / 2; cy = cy ?? v.y + v.h / 2;
    Object.assign(v, { x: cx - (cx - v.x) * k, y: cy - (cy - v.y) * k, w, h: v.h * k });
    this.applyView();
  },
  matches(n) {
    return this.find && [n.label, n.ip, n.device].some((v) => String(v || '').toLowerCase().includes(this.find));
  },
  async goTo() {
    if (!this.graph || !this.find) return;
    const hit = this.vis.nodes.find((n) => this.matches(n)) || this.graph.nodes.find((n) => this.matches(n));
    if (!hit) throw new Error('No device on the map matches that.');
    this.centre(hit.id);
    await this.select(hit.id);
  },
  /* Zoom to reading size around one device, if it is on the map. */
  centre(id) {
    const p = this.pos && this.pos[id];
    if (!p) return;
    const w = Math.min(this.W, this.baseW), h = w * (this.H / this.W);
    this.view = { x: p.x - w / 2, y: p.y - h / 2, w, h };
    this.applyView();
  },
  draw() {
    const g = this.vis, pos = this.pos, svg = $('#topo-svg');
    if (!g || !pos || !svg) return;
    svg.classList.toggle('searching', Boolean(this.find));
    let out = '';
    g.links.forEach((l) => {
      const a = pos[l.a], b = pos[l.b];
      if (!a || !b) return;
      const A = g.byId.get(l.a), B = g.byId.get(l.b);
      const down = l.oper && l.oper !== 'up';
      const tip = `${A.label} ${l.a_port || '?'} ↔ ${B.label} ${l.b_port || '?'}` + (l.speed_mbps ? ` · ${speed(l.speed_mbps)}` : '') +
        (down ? ` · ${l.oper}` : '') + ` · ${l.proto.toUpperCase()}` +
        (l.in_bps != null ? ` · in ${bps(l.in_bps)} / out ${bps(l.out_bps)} at ${A.label}` : '');
      const width = l.speed_mbps >= 10000 ? 3.5 : l.speed_mbps >= 1000 || !l.speed_mbps ? 2 : 1.25;
      const at = (t) => ({ x: a.x + (b.x - a.x) * t, y: a.y + (b.y - a.y) * t });
      const len = Math.hypot(b.x - a.x, b.y - a.y) || 1, near = Math.min(0.4, 68 / len);
      const pa = at(near), pb = at(1 - near);
      out += `<g class="link-g"><title>${esc(tip)}</title>
        <line class="link-hit" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"/>
        <line class="link ${down ? 'down' : ''}" stroke-width="${width}" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"/>
        ${len > 190 ? `<text class="port" x="${pa.x}" y="${pa.y + 3}">${esc(shortPort(l.a_port))}</text>
        <text class="port" x="${pb.x}" y="${pb.y + 3}">${esc(shortPort(l.b_port))}</text>` : ''}</g>`;
    });
    g.nodes.forEach((n) => {
      const p = pos[n.id];
      if (!p) return;
      const [glyph, kind] = KIND[n.kind] || KIND.device;
      const alert = n.alerts ? `${n.alerts} open alert${n.alerts > 1 ? 's' : ''}, worst ${n.severity}` : 'no open alerts';
      const shape = n.kind === 'firewall' ? '<rect class="node-shape" x="-22" y="-17" width="44" height="34" rx="6"/>'
        : n.kind === 'switch' ? '<rect class="node-shape" x="-28" y="-13" width="56" height="26" rx="4"/>'
        : '<circle class="node-shape" r="17"/>';
      const ends = g.folded[n.id] ? ` · ${g.folded[n.id]} endpoint${g.folded[n.id] > 1 ? 's' : ''} not shown` : '';
      out += `<g class="node ${n.managed ? '' : 'unmanaged'} ${n.severity ? 'sev-' + esc(n.severity) : ''} ${this.selected === n.id ? 'selected' : ''} ${this.matches(n) ? 'found' : ''}"
          data-node="${esc(n.id)}" transform="translate(${p.x},${p.y})" tabindex="0" role="button"
          aria-label="${esc(`${n.label}, ${kind}, ${alert}`)}">
        <title>${esc(`${n.label} · ${kind}${n.managed ? '' : ' (not a log source)'} · ${alert}${ends}`)}</title>
        ${this.selected === n.id ? '<circle class="sel-ring" r="36"/>' : ''}${shape}<text class="glyph" y="4">${glyph || '•'}</text>
        <text class="node-label" y="${n.kind === 'switch' ? 30 : 34}">${esc(n.label)}</text>
        ${n.ip && n.ip !== n.label ? `<text class="node-sub" y="${n.kind === 'switch' ? 44 : 48}">${esc(n.ip)}</text>` : ''}
        ${n.alerts ? `<g transform="translate(${n.kind === 'switch' ? 28 : 21},-15)"><circle class="badge" r="9"/><text class="badge-text" y="3.5">${n.alerts > 99 ? '99+' : n.alerts}</text></g>` : ''}
      </g>`;
    });
    svg.innerHTML = out;
  },
  async select(id) {
    this.selected = id;
    this.draw();
    const n = this.graph.nodes.find((x) => x.id === id), panel = $('#topo-panel');
    if (!n) return;
    const kind = (KIND[n.kind] || KIND.device)[1];
    const links = this.graph.links.filter((l) => l.a === id || l.b === id).map((l) => {
      const mine = l.a === id, other = this.graph.nodes.find((x) => x.id === (mine ? l.b : l.a));
      return `<tr><td class="mono">${esc((mine ? l.a_port : l.b_port) || '?')}</td><td>${esc(other.label)}</td>
        <td class="mono">${esc((mine ? l.b_port : l.a_port) || '?')}</td><td class="nowrap">${esc(speed(l.speed_mbps))}</td></tr>`;
    }).join('');
    const neighbours = links ? `<h2>Connected to</h2><div class="table-wrap"><table><thead><tr><th>Port</th><th>Neighbour</th><th>Its port</th><th>Speed</th></tr></thead><tbody>${links}</tbody></table></div>` : '';
    const alertLine = n.alerts ? `<dt>Open alerts</dt><dd>${sevBadge(n.severity)} ${n.alerts} · <a href="#/alerts" data-act="see-alerts" data-q="${esc(n.device)}">show</a></dd>` : '';
    if (!n.managed) {
      panel.innerHTML = `<h2>${esc(n.label)}</h2><dl class="kv"><dt>Type</dt><dd>${kind}</dd>
        ${n.ip ? `<dt>Address</dt><dd class="mono">${esc(n.ip)}</dd>` : ''}${n.descr ? `<dt>Describes itself as</dt><dd>${esc(n.descr)}</dd>` : ''}</dl>
        <p class="muted">Known only because a neighbour sees it. It is not sending logs to Cerberus, so nothing here is watching it.</p>${neighbours}`;
      return;
    }
    const d = await api('/topology/device?id=' + encodeURIComponent(n.device));
    if (this.selected !== id) return;
    const sys = d.system, st = d.snmp;
    const snmpLine = !st.pollable ? esc(st.reason) : st.ok ? `Answered ${ago(st.polled)}` : st.polled ? `<span class="error">Failed ${ago(st.polled)}: ${esc(st.error)}</span>` : 'Waiting for first poll';
    const up = d.interfaces.filter((i) => i.oper === 'up');
    panel.innerHTML = `<h2>${esc(n.label)}</h2><dl class="kv">
      <dt>Type</dt><dd>${kind}</dd><dt>Address</dt><dd class="mono">${esc(d.device.ip)}</dd>${alertLine}
      <dt>SNMP</dt><dd>${snmpLine}</dd>
      ${sys.descr ? `<dt>System</dt><dd>${esc(sys.descr)}</dd><dt>Uptime</dt><dd>${uptime(sys.uptime_seconds)}</dd>` : ''}
      ${sys.location ? `<dt>Location</dt><dd>${esc(sys.location)}</dd>` : ''}
      ${d.ips.length ? `<dt>Addresses</dt><dd class="mono">${esc(d.ips.slice(0, 12).join(', '))}${d.ips.length > 12 ? ' …' : ''}</dd>` : ''}</dl>
      ${neighbours}
      ${d.interfaces.length ? `<h2>Interfaces <span class="muted">· ${up.length} of ${d.interfaces.length} up</span></h2>
      <div class="table-wrap iface-table"><table><thead><tr><th>Name</th><th>Speed</th><th class="num">In</th><th class="num">Out</th></tr></thead><tbody>
      ${up.map((i) => `<tr><td><span class="mono">${esc(i.name)}</span>${i.alias ? ` <span class="muted">${esc(i.alias)}</span>` : ''}</td>
        <td class="nowrap">${esc(speed(i.speed_mbps))}</td><td class="num nowrap">${bps(i.in_bps)}</td><td class="num nowrap">${bps(i.out_bps)}</td></tr>`).join('')
        || '<tr><td colspan="4" class="empty">No interface is up.</td></tr>'}</tbody></table></div>
      <p class="muted">Rates are averages between the last two polls.</p>` : ''}`;
  },
  fillForm(s) {
    $('#s-enabled').checked = s.enabled;
    $('#s-community').value = s.community;
    $('#s-interval').value = Math.round(s.interval / 60);
    $('#s-concurrency').value = s.concurrency;
    $('#s-networks').value = s.networks.join('\n');
  },
  async saveSettings() {
    const r = await api('/snmp', 'PUT', {
      enabled: $('#s-enabled').checked, community: $('#s-community').value,
      interval: Number($('#s-interval').value) * 60, concurrency: Number($('#s-concurrency').value), networks: $('#s-networks').value.split(/[\s,]+/).filter(Boolean),
    });
    this.fillForm(r.settings);
    if (r.rejected.length) throw new Error(`Saved, but these are not valid networks and were dropped: ${r.rejected.join(', ')}`);
    if (r.settings.enabled && !r.settings.community) throw new Error('Saved. Polling starts once a community string is set here or on a device.');
    toast(r.settings.enabled ? 'Saved. Devices are being polled now.' : 'Saved');
    setTimeout(() => this.refresh().catch(() => {}), 2500);
  },
  actions: {
    async poll(el) {
      el.disabled = true; el.textContent = 'Polling…';
      try {
        const r = await api('/snmp/poll', 'POST', {});
        if (r.background) toast(`Polling ${num(r.started)} devices in the background. The map updates as they answer.`);
        else toast(`${r.ok} of ${r.polled} device${r.polled > 1 ? 's' : ''} answered`, r.ok === 0);
        await pages.topology.refresh();
      } finally { el.disabled = false; el.textContent = 'Poll now'; }
    },
    pick(el) { return pages.topology.select(el.dataset.id); },
    'zoom-in'() { pages.topology.zoom(1 / 1.4); },
    'zoom-out'() { pages.topology.zoom(1.4); },
    'zoom-fit'() { pages.topology.zoom(1e9); },
    'see-alerts'(el) { Object.assign(state.alerts, { q: el.dataset.q, status: 'open', severity: '' }); },
  },
};
function shortPort(name) {
  return String(name || '').replace(/^(?:Ten|Forty|Hundred|TwentyFive)?Gig(?:abitEthernet|E)/i, (m) => /^ten/i.test(m) ? 'Te' : 'Gi')
    .replace(/^FastEthernet/i, 'Fa').replace(/^ethernet/i, 'eth').slice(0, 14);
}

/* --- connectors --- */
pages.connectors = {
  render() {
    main.innerHTML = `
      <div class="page-head"><div><h1>Connectors</h1>
        <p>Connectors are YAML definitions that turn a vendor's log text into fields the detectors understand. Add your own to <code id="user-dir"></code> and reload.</p></div>
        <button type="button" data-act="reload">Reload definitions</button></div>
      <div id="conn-errors"></div>
      <div class="grid cols-2" id="conn-list"></div>
      <div class="card" style="margin-top:14px">
        <h2>Test a log line</h2>
        <label for="t-raw">Paste one raw syslog message, including the &lt;PRI&gt; if you have it</label>
        <textarea id="t-raw" rows="3" class="mono" spellcheck="false"></textarea>
        <div class="actions">
          <select id="t-conn" aria-label="Connector"></select>
          <button type="button" class="primary" data-act="test">Parse</button>
        </div>
        <pre id="t-out" hidden></pre>
      </div>`;
  },
  async refresh() { this.show(await api('/connectors')); },
  show(d) {
    if (d.user_dir) $('#user-dir').textContent = d.user_dir;
    $('#conn-errors').innerHTML = d.errors.map((e) => `<p class="error">Failed to load ${esc(e)}</p>`).join('');
    $('#conn-list').innerHTML = d.connectors.map((c) => `
      <div class="card"><div class="row"><h2 style="margin:0">${esc(c.name)}</h2><span class="tag">${esc(c.origin)}</span>
        <span class="spacer"></span><code>${esc(c.id)}</code></div>
        <p class="muted">${esc(c.description)}</p>
        <div class="row">${c.rules.map((r) => `<span class="tag">${esc(r)}</span>`).join('')}</div></div>`).join('');
    $('#t-conn').innerHTML = '<option value="">Auto-detect connector</option>' +
      d.connectors.map((c) => `<option value="${esc(c.id)}">${esc(c.name)}</option>`).join('');
  },
  actions: {
    async reload() {
      const d = await api('/connectors/reload', 'POST');
      pages.connectors.show(d);
      toast(d.errors.length ? `${d.errors.length} file(s) failed to load` : 'Connectors reloaded', d.errors.length > 0);
    },
    async test() {
      const { event } = await api('/connectors/test', 'POST', { raw: $('#t-raw').value, connector: $('#t-conn').value });
      const out = $('#t-out');
      out.textContent = JSON.stringify(event, null, 2);
      out.hidden = false;
    },
  },
};

/* --- detection --- */
/* The High Risk Ports list: one row per port and protocol. */
const PROTOCOL_LABELS = [['any', 'Any'], ['tcp', 'TCP'], ['udp', 'UDP']];
function portRow(e, catalog) {
  const known = catalog[String(e.port)];
  return `<tr>
    <td><input type="number" class="pe-port mono" min="1" max="65535" value="${esc(e.port ?? '')}" aria-label="Port"></td>
    <td><select class="pe-proto" aria-label="Protocol">${PROTOCOL_LABELS.map(([v, l]) =>
      `<option value="${v}" ${v === e.proto ? 'selected' : ''}>${l}</option>`).join('')}</select></td>
    <td><input class="pe-name" maxlength="40" value="${esc(e.name || '')}" placeholder="${esc(known ? known.name : 'Service name')}" aria-label="Service name"></td>
    <td><button type="button" class="small ghost" data-act="port-remove" aria-label="Remove this port">Remove</button></td></tr>`;
}
function portsEditor(p) {
  return `<div class="wide ports-editor" data-key="${esc(p.key)}" data-type="ports">
    <h3>High Risk Ports</h3>
    <p class="muted">Traffic to these ports is counted on the <a href="#/riskports">High Risk Ports</a> page and watched for surges.
      One row per port and protocol: <b>Any</b> counts every protocol; <b>TCP</b> or <b>UDP</b> counts only that one
      (and traffic whose protocol the device does not log). The service name is optional; leave it empty to use the built-in one.</p>
    <div class="table-wrap"><table class="ports-table">
      <thead><tr><th>Port</th><th>Protocol</th><th>Service name</th><th></th></tr></thead>
      <tbody>${p.entries.map((e) => portRow(e, p.catalog)).join('')}</tbody></table></div>
    <div class="row" style="margin-top:8px">
      <button type="button" data-act="port-add">Add port</button>
      <button type="button" class="ghost" data-act="port-defaults">Restore the default list</button>
      <span class="muted" id="ports-count"></span></div>
  </div>`;
}
function portEntries(editor) {
  const out = [], seen = new Set();
  for (const tr of $$('tbody tr', editor)) {
    const raw = $('.pe-port', tr).value.trim();
    if (!raw) continue;  // an empty new row
    const port = Number(raw), proto = $('.pe-proto', tr).value;
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`"${raw}" is not a port number (1 to 65535).`);
    const key = `${port}/${proto}`;
    if (seen.has(key)) throw new Error(`Port ${port} (${proto === 'any' ? 'any protocol' : proto.toUpperCase()}) is listed twice.`);
    seen.add(key);
    const name = $('.pe-name', tr).value.replace(/[,;=\n\r]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 40);
    out.push(`${port}${proto === 'any' ? '' : '/' + proto}${name ? '=' + name : ''}`);
  }
  return out.join(',');
}

pages.detection = {
  render() {
    this.focus = new URLSearchParams(location.hash.split('?')[1] || '').get('focus');
    main.innerHTML = `
      <div class="page-head"><div><h1>Detection</h1><p>Which patterns raise alerts, and how sensitive each one is.</p></div></div>
      <form id="det-form">
        <div class="card" id="det-list"></div>
        <div class="card" style="margin-top:14px">
          <h2>General</h2>
          <div class="form-grid">
            <div><label for="g-cooldown">Fold repeats into one alert for (minutes)</label>
              <input id="g-cooldown" type="number" min="1" max="1440"></div>
          </div>
          <label for="g-ignore">Ignored sources: IPs or CIDR ranges, one per line (your vulnerability scanner, management and backup servers)</label>
          <textarea id="g-ignore" rows="3" class="mono" spellcheck="false"></textarea>
          <label for="g-ignore-dst">Ignored destinations: servers that are public on purpose, and internet services you have confirmed are legitimate (applies to exposure, risky outbound, beaconing and large transfers)</label>
          <textarea id="g-ignore-dst" rows="3" class="mono" spellcheck="false"></textarea>
        </div>
        <div class="actions"><button class="primary" type="submit">Save changes</button></div>
      </form>`;
    $('#det-form').addEventListener('submit', (e) => { e.preventDefault(); act(() => this.save(), 'Detection settings saved'); });
  },
  async refresh() { this.show(await api('/detectors')); },
  show({ detectors, general }) {
    $('#det-list').innerHTML = detectors.map((d) => `
      <div class="setting" data-id="${esc(d.id)}">
        <div class="setting-head"><label class="check"><input type="checkbox" class="d-enabled" ${d.enabled ? 'checked' : ''}> ${esc(d.name)}</label></div>
        <p>${esc(d.description)}</p>
        <div class="params">${d.params.map((p) => p.type === 'ports'
          ? portsEditor(p)
          : p.type === 'text'
          ? `<div class="wide"><label>${esc(p.label)}<textarea rows="4" class="mono" spellcheck="false" data-key="${esc(p.key)}" data-type="str">${esc(p.value)}</textarea></label></div>`
          : p.type === 'bool'
          ? `<label class="check"><input type="checkbox" data-key="${esc(p.key)}" data-type="bool" ${p.value ? 'checked' : ''}> ${esc(p.label)}</label>`
          : `<div><label>${esc(p.label)}<input type="${p.type === 'str' ? 'text' : 'number'}" ${p.type === 'float' ? 'step="0.1"' : ''} min="0"
               data-key="${esc(p.key)}" data-type="${esc(p.type)}" value="${esc(p.value)}"></label></div>`).join('')}</div>
      </div>`).join('');
    $('#g-cooldown').value = general.cooldown_minutes;
    $('#g-ignore').value = general.ignore_sources.join('\n');
    $('#g-ignore-dst').value = general.ignore_destinations.join('\n');
    const ports = detectors.flatMap((d) => d.params).find((p) => p.type === 'ports');
    this.ports = ports ? { catalog: ports.catalog, defaults: ports.default_entries } : null;
    this.countPorts();
    $$('.ports-editor').forEach((ed) => ed.addEventListener('input', (e) => {
      if (e.target.classList.contains('pe-port')) {  // suggest the built-in name for the port typed
        const known = this.ports && this.ports.catalog[String(Number(e.target.value))];
        $('.pe-name', e.target.closest('tr')).placeholder = known ? known.name : 'Service name';
      }
      this.countPorts();
    }));
    if (this.focus) {
      const el = $(`.setting[data-id="${CSS.escape(this.focus)}"]`);
      if (el) { el.classList.add('focus'); el.scrollIntoView({ block: 'start' }); }
      this.focus = null;
    }
  },
  countPorts() {
    const ed = $('.ports-editor');
    if (ed) $('#ports-count').textContent = `${$$('tbody tr', ed).filter((tr) => $('.pe-port', tr).value.trim()).length} entries`;
  },
  actions: {
    'port-add'(el) {
      const body = $('tbody', el.closest('.ports-editor'));
      body.insertAdjacentHTML('beforeend', portRow({ port: '', proto: 'tcp', name: '' }, pages.detection.ports.catalog));
      $('tr:last-child .pe-port', body).focus();
      pages.detection.countPorts();
    },
    'port-remove'(el) { el.closest('tr').remove(); pages.detection.countPorts(); },
    'port-defaults'(el) {
      if (!confirm('Replace the list with the built-in high risk ports? Your changes are lost when you save.')) return;
      const { defaults, catalog } = pages.detection.ports;
      $('tbody', el.closest('.ports-editor')).innerHTML = defaults.map((e) => portRow(e, catalog)).join('');
      pages.detection.countPorts();
    },
  },
  async save() {
    const detectors = {};
    $$('#det-list .setting').forEach((el) => {
      const cfg = { enabled: $('.d-enabled', el).checked };
      $$('[data-key]', el).forEach((inp) => {
        cfg[inp.dataset.key] = inp.dataset.type === 'ports' ? portEntries(inp)
          : inp.dataset.type === 'bool' ? inp.checked : inp.dataset.type === 'str' ? inp.value : Number(inp.value);
      });
      detectors[el.dataset.id] = cfg;
    });
    const wanted = $('#g-ignore').value.split(/[\s,]+/).filter(Boolean);
    const wantedDst = $('#g-ignore-dst').value.split(/[\s,]+/).filter(Boolean);
    const saved = await api('/detectors', 'PUT', { detectors, general: {
      cooldown_minutes: Number($('#g-cooldown').value), ignore_sources: wanted, ignore_destinations: wantedDst } });
    this.show(saved);
    const lost = wanted.length + wantedDst.length - saved.general.ignore_sources.length - saved.general.ignore_destinations.length;
    if (lost > 0) throw new Error(`Saved, but ${lost} ignore-list entr${lost > 1 ? 'ies were' : 'y was'} not a valid IP or CIDR and was dropped.`);
  },
};

/* --- syslog listeners (Settings → Syslog) --- */
const LISTENERS = [['udp', 'UDP', 'Plain syslog (RFC 3164/5424). Most devices send this by default.'],
  ['tcp', 'TCP', 'Plain syslog over TCP: nothing is lost to a full network, and it gets through Docker Desktop.'],
  ['tls', 'TLS', 'Syslog over TLS (RFC 5425): encrypted, and optionally only from devices with a certificate.']];
pages.syslog = {
  render() {
    main.innerHTML = `
      <div class="page-head"><div><h1>Syslog</h1>
        <p>Where Cerberus listens for your devices' logs. Changes take effect at once: a new port is opened before the
          old one closes, so a port that cannot be used leaves the listener as it was.</p></div></div>
      <div id="sys-notes"></div>
      <form id="sys-form" class="card">
        <div class="table-wrap"><table class="listeners">
          <thead><tr><th>Listener</th><th>On</th><th>Port</th><th>Status</th></tr></thead>
          <tbody id="sys-rows"></tbody></table></div>
        <div class="actions"><button class="primary" type="submit" id="sys-save">Save changes</button>
          <span class="muted" id="sys-source"></span></div>
      </form>`;
    $('#sys-form').addEventListener('submit', (e) => { e.preventDefault(); act(() => this.save()); });
  },
  async refresh() { this.show(await api('/listeners')); },
  show(d) {
    this.data = d;
    const notes = [];
    if (!d.available) {
      notes.push(`<div class="note">This Cerberus does not receive syslog itself (it runs as the <b>${esc(d.mode)}</b>).
        In a scale-out deployment the collectors receive it, on the ports in their environment
        (<code>CERBERUS_SYSLOG_UDP_PORT</code>, <code>_TCP_PORT</code>, <code>_TLS_PORT</code>), so that every collector
        behind the load balancer listens on the same ones.</div>`);
    } else if (d.container) {
      notes.push(`<div class="note"><b>Running in a container.</b> These are the ports inside it. Devices reach them through
        the ports the container publishes (in <code>docker-compose.yml</code>, <code>514:5514</code> sends host port 514 to 5514).
        When you change a port here, change the mapping to match and run <code>docker compose up -d</code>.</div>`);
    }
    $('#sys-notes').innerHTML = notes.join('');
    $('#sys-rows').innerHTML = LISTENERS.map(([kind, label, help]) => {
      const l = d.listeners[kind], tlsMissing = kind === 'tls' && !d.tls_certificate;
      const status = l.error ? `<span class="error-text">${esc(l.error)}</span>`
        : l.listening ? `<span class="dot on"></span>Listening on ${esc(d.bind)}:${l.listening_port}`
        : tlsMissing ? '<span class="muted">Needs a certificate: set <code>CERBERUS_SYSLOG_TLS_CERT</code> and <code>_KEY</code></span>'
        : '<span class="muted">Off</span>';
      return `<tr data-kind="${kind}">
        <td><b>${label}</b><div class="muted small">${esc(help)}${kind === 'tls' && d.client_certificates ? ' Device certificates are required.' : ''}</div></td>
        <td><input type="checkbox" class="l-on" aria-label="${label} listener on" ${l.enabled && !tlsMissing ? 'checked' : ''}
          ${!d.available || tlsMissing ? 'disabled' : ''}></td>
        <td><input type="number" class="l-port mono" min="1" max="65535" value="${l.port}" aria-label="${label} port"
          ${!d.available || tlsMissing ? 'disabled' : ''}></td>
        <td>${status}</td></tr>`;
    }).join('');
    $('#sys-save').disabled = !d.available;
    $('#sys-source').textContent = !d.available ? '' : d.saved ? 'Saved here; these replace the CERBERUS_SYSLOG_* environment variables.'
      : 'From the CERBERUS_SYSLOG_* environment variables until you save here.';
  },
  async save() {
    const listeners = {};
    for (const tr of $$('#sys-rows tr')) {
      const port = Number($('.l-port', tr).value);
      if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`The ${tr.dataset.kind.toUpperCase()} port must be a number from 1 to 65535.`);
      listeners[tr.dataset.kind] = { enabled: $('.l-on', tr).checked, port };
    }
    const d = await api('/listeners', 'PUT', { listeners });
    this.show(d);
    const failed = LISTENERS.filter(([k]) => d.listeners[k].error).map(([, label]) => label);
    if (failed.length) toast(`Saved, but ${failed.join(' and ')} could not change: see Status.`, true);
    else toast('Syslog listeners saved');
  },
};

/* --- notifications --- */
pages.notifications = {
  render() {
    main.innerHTML = `
      <div class="page-head"><div><h1>Notifications</h1>
        <p>Each channel receives alerts at or above its minimum severity, at most 10 per minute; anything beyond that arrives as one summary.</p></div>
        <div class="row"><select id="n-type" aria-label="Channel type"></select><button type="button" class="primary" data-act="add">Add channel</button></div></div>
      <div id="n-form"></div>
      <div class="card table-wrap"><table>
        <thead><tr><th>Channel</th><th>Type</th><th>Minimum severity</th><th>Last delivery</th><th></th></tr></thead>
        <tbody id="rows"></tbody></table></div>`;
  },
  async refresh() {
    const d = await api('/channels');
    this.data = d;
    $('#n-type').innerHTML = Object.entries(d.types).map(([k, t]) => `<option value="${k}">${esc(t.label)}</option>`).join('');
    $('#rows').innerHTML = d.channels.length ? d.channels.map((c) => `
      <tr data-id="${c.id}">
        <td><span class="dot ${c.enabled ? 'on' : ''}"></span><b>${esc(c.name)}</b>${c.enabled ? '' : ' <span class="muted">(disabled)</span>'}</td>
        <td>${esc(d.types[c.type]?.label || c.type)}</td><td>${sevBadge(c.min_severity)}</td>
        <td>${c.last_ts ? (c.last_ok ? `Delivered ${ago(c.last_ts)}` : `<span class="error">Failed ${ago(c.last_ts)}: ${esc(c.last_error)}</span>`) : '<span class="muted">Nothing sent yet</span>'}</td>
        <td class="nowrap"><button type="button" class="small" data-act="send-test">Send test</button>
          <button type="button" class="small" data-act="edit">Edit</button>
          <button type="button" class="small danger" data-act="remove">Delete</button></td></tr>`).join('')
      : `<tr><td colspan="5" class="empty">No channels yet. Add one to be told about alerts.</td></tr>`;
  },
  form(type, channel) {
    const spec = this.data.types[type], cfg = channel ? channel.config : {};
    const field = (f) => {
      const value = cfg[f.key] ?? f.default, id = 'c-' + f.key;
      const req = spec.required.includes(f.key) ? 'required' : '';
      let input;
      if (f.kind.startsWith('select:')) {
        input = `<select id="${id}" data-key="${f.key}">${f.kind.slice(7).split(',').map((o) =>
          `<option ${o === value ? 'selected' : ''}>${o}</option>`).join('')}</select>`;
      } else {
        const kind = f.kind === 'secret' ? 'password' : f.kind;
        input = `<input id="${id}" data-key="${f.key}" type="${kind}" value="${esc(value)}" ${req} autocomplete="${f.kind === 'secret' ? 'new-password' : 'off'}">`;
      }
      return `<div><label for="${id}">${esc(f.label)}</label>${input}</div>`;
    };
    $('#n-form').innerHTML = `
      <form class="card" id="channel-form" style="margin-bottom:14px">
        <h2>${channel ? 'Edit' : 'New'} ${esc(spec.label)} channel</h2>
        <div class="form-grid">
          <div><label for="c-name">Name</label><input id="c-name" type="text" value="${esc(channel ? channel.name : spec.label)}" required></div>
          <div><label for="c-sev">Minimum severity</label><select id="c-sev">${SEVS.map((s) =>
            `<option ${s === (channel ? channel.min_severity : 'medium') ? 'selected' : ''}>${s}</option>`).join('')}</select></div>
          ${spec.fields.map(field).join('')}
        </div>
        <label class="check"><input id="c-enabled" type="checkbox" ${!channel || channel.enabled ? 'checked' : ''}> Enabled</label>
        <div class="actions"><button class="primary" type="submit">Save channel</button>
          <button type="button" data-act="cancel">Cancel</button></div>
      </form>`;
    $('#channel-form').addEventListener('submit', (e) => {
      e.preventDefault();
      act(async () => {
        const config = {};
        $$('#channel-form [data-key]').forEach((el) => { config[el.dataset.key] = el.value; });
        const body = { type, name: $('#c-name').value, min_severity: $('#c-sev').value, enabled: $('#c-enabled').checked, config };
        await (channel ? api('/channels/' + channel.id, 'PUT', body) : api('/channels', 'POST', body));
        $('#n-form').innerHTML = '';
        await this.refresh();
      }, 'Channel saved. Use "Send test" to check it.');
    });
    $('#c-name').focus();
  },
  find(el) { return this.data.channels.find((c) => c.id === Number(el.closest('tr').dataset.id)); },
  actions: {
    add() { pages.notifications.form($('#n-type').value); },
    edit(el) { const c = pages.notifications.find(el); pages.notifications.form(c.type, c); },
    cancel() { $('#n-form').innerHTML = ''; },
    async remove(el) {
      const c = pages.notifications.find(el);
      if (!confirm(`Delete the channel "${c.name}"?`)) return;
      await api('/channels/' + c.id, 'DELETE');
      await pages.notifications.refresh();
    },
    async 'send-test'(el) {
      const c = pages.notifications.find(el);
      el.disabled = true;
      el.textContent = 'Sending…';
      try {
        await api(`/channels/${c.id}/test`, 'POST');
        toast('Test sent. Check that it arrived.');
      } finally {
        await pages.notifications.refresh().catch(() => {});
      }
    },
  },
};

/* ----------------------------------------------------------------- router */
let current = null, timer = null;
function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}
function setNavCount(n) {
  const el = $('#nav-alerts');
  el.hidden = !n;
  el.textContent = n > 99 ? '99+' : n;
  el.title = `${n} open alert${n === 1 ? '' : 's'}`;
}
/* The open-alert count next to "Alerts", on every page, as often as the Alerts page refreshes. */
let badgeTimer = null;
function updateBadge() {
  return api('/alerts/counts').then((d) => setNavCount(d.total)).catch(() => {});
}
function startBadgeTimer() {
  clearInterval(badgeTimer);
  const every = state.alerts.every * 1000;
  if (every) badgeTimer = setInterval(() => { if (!document.hidden && !$('#shell').hidden) updateBadge(); }, every);
}
/* The current page's own refresh, at its interval (which the Alerts page lets you choose). */
function startPageTimer() {
  clearInterval(timer);
  const page = pages[current];
  if (!page || !page.interval) return;
  timer = setInterval(() => {
    if (!document.hidden) page.refresh().catch((err) => { if (err.message !== 'Not signed in') console.warn(err); });
  }, page.interval);
}
/* Settings: Detection, Connectors and Notifications, as sections of one page.
   #/settings/<section>; the older #/detection and the like still work. */
const SETTINGS_TABS = [['detection', 'Detection'], ['connectors', 'Connectors'], ['syslog', 'Syslog'], ['notifications', 'Notifications']];
function settingsSection(name) {
  if (name === 'settings') {
    let last = '';
    try { last = localStorage.getItem('cerberus.settingsTab') || ''; } catch { /* first one */ }
    return SETTINGS_TABS.some(([id]) => id === last) ? last : 'detection';
  }
  const id = name.startsWith('settings/') ? name.slice(9) : name;
  return SETTINGS_TABS.some(([t]) => t === id) ? id : null;
}
function settingsChrome(tab) {
  // The section's own heading becomes the tabs; its description stays.
  const head = $('.page-head', main);
  const title = head && $('h1', head);
  if (title) title.remove();
  const v = state.version;
  main.insertAdjacentHTML('afterbegin', `<div class="page-head"><div><h1>Settings</h1></div>
    ${v ? `<div class="muted version">Cerberus <a href="https://github.com/wrcrooks/Cerberus/releases/tag/v${esc(v)}" target="_blank"
      rel="noopener noreferrer" title="Release notes for this version">v${esc(v)}</a></div>` : ''}</div>
    <nav class="tabs" aria-label="Settings sections">${SETTINGS_TABS.map(([id, label]) =>
      `<a href="#/settings/${id}" class="${id === tab ? 'on' : ''}" ${id === tab ? 'aria-current="page"' : ''}>${label}</a>`).join('')}</nav>`);
  try { localStorage.setItem('cerberus.settingsTab', tab); } catch { /* not kept */ }
}

function route() {
  const name = location.hash.replace(/^#\/?/, '').split('?')[0] || 'dashboard';
  const tab = settingsSection(name);
  current = tab || (pages[name] ? name : 'dashboard');
  const page = pages[current];
  $$('#nav a').forEach((a) => a.classList.toggle('active', a.dataset.page === (tab ? 'settings' : current)));
  clearInterval(timer);
  page.loaded = false;
  page.render();
  if (tab) settingsChrome(tab);
  const run = () => page.refresh().catch((err) => {
    if (err.message !== 'Not signed in') console.warn(err);
  });
  run();
  startPageTimer();
}
main.addEventListener('click', (e) => {
  const el = e.target.closest('[data-act]');
  if (!el) return;
  // Clicks on controls inside a clickable row belong to the control, not the row.
  if (el.tagName === 'TR' && e.target.closest('button, a, input, select')) return;
  const handler = pages[current].actions?.[el.dataset.act];
  if (handler) act(() => handler(el));
});

function showLogin() {
  clearInterval(timer);
  $('#shell').hidden = true;
  $('#login').hidden = false;
  $('#login-password').focus();
}
$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#login-error').textContent = '';
  try {
    await api('/login', 'POST', { password: $('#login-password').value });
    $('#login-password').value = '';
    start();
  } catch (err) {
    $('#login-error').textContent = err.message;
  }
});
$('#logout').addEventListener('click', async () => {
  await api('/logout', 'POST').catch(() => {});
  showLogin();
});

async function start() {
  const me = await api('/me');
  state.version = me.version || '';
  if (!me.signed_in) return showLogin();
  $('#login').hidden = true;
  $('#shell').hidden = false;
  $('#logout').hidden = !me.auth;
  $('#nav-sites').hidden = !me.central;
  if (me.central && !location.hash) location.hash = '#/sites';  // a console opens on its sites
  route();
  updateBadge();
  startBadgeTimer();
}
window.addEventListener('hashchange', () => { if (!$('#shell').hidden) route(); });
start();
