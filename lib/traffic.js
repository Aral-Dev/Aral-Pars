/** Aral Pars — per-protocol traffic accounting (persisted to aral-data/traffic.json). */
'use strict';

const fs = require('fs');
const path = require('path');
const Logger = require('./logger');

const KEYS = ['VLESS-WS', 'VMess-WS', 'Trojan-WS', 'VLESS-XHTTP', 'VLESS-HTTPUpgrade', 'VMess-HTTPUpgrade', 'Trojan-HTTPUpgrade', 'VLESS-gRPC', 'Shadowsocks-WS', 'Other'];
const GIB = 1024 * 1024 * 1024;
const utcDay = (d = new Date()) => d.toISOString().slice(0, 10);
const utcMonth = (d = new Date()) => d.toISOString().slice(0, 7);

const Traffic = (() => {
  let file = null;
  let st = null;
  let dirty = false;
  let lastSave = 0;
  let writable = false;
  const live = { up: 0, down: 0 };
  let samples = [];
  const active = {};
  const warned = {};

  const fresh = () => ({ v: 1, since: new Date().toISOString(), allTime: {}, day: { key: utcDay(), per: {} }, month: { key: utcMonth(), per: {}, baseBytes: 0 } });
  const norm = (label) => (KEYS.includes(label) ? label : 'Other');
  const bump = (bucket, k, up, down) => { const e = bucket[k] || (bucket[k] = { up: 0, down: 0 }); e.up += up; e.down += down; };
  const sum = (per) => {
    let up = 0, down = 0;
    for (const k of Object.keys(per || {})) { up += per[k].up; down += per[k].down; }
    return { up, down, total: up + down };
  };
  const limitBytes = () => {
    const g = parseFloat(process.env.TRAFFIC_LIMIT_GB || '');
    return isFinite(g) && g > 0 ? Math.round(g * GIB) : 0;
  };

  function roll() {
    if (!st) return;
    const d = utcDay();
    const m = utcMonth();
    if (st.day.key !== d) { st.day = { key: d, per: {} }; dirty = true; }
    if (st.month.key !== m) { st.month = { key: m, per: {}, baseBytes: 0 }; dirty = true; }
  }

  function save() {
    if (!file || !st) return;
    try {
      const tmp = file + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(st), 'utf8');
      fs.renameSync(tmp, file);
      dirty = false;
      lastSave = Date.now();
      writable = true;
    } catch (err) {
      writable = false;
      if (!warned.save) { warned.save = 1; Logger.warn('Could not save traffic.json: ' + err.message); }
    }
  }

  function checkLimit() {
    const lim = limitBytes();
    if (!lim) return;
    const used = sum(st.month.per).total + (st.month.baseBytes || 0);
    const pct = used / lim * 100;
    if (pct >= 100 && !warned.p100) { warned.p100 = 1; Logger.warn(`Traffic: 100% of TRAFFIC_LIMIT_GB used this month.`); }
    else if (pct >= 80 && !warned.p80) { warned.p80 = 1; Logger.warn(`Traffic: 80% of TRAFFIC_LIMIT_GB used this month.`); }
  }

  function tick() {
    const now = Date.now();
    samples.push({ t: now, up: live.up, down: live.down });
    if (samples.length > 6) samples.shift();
    roll();
    if (dirty && now - lastSave > 30000) { save(); checkLimit(); }
  }

  return {
    KEYS,
    init(dataDir) {
      file = path.join(dataDir, 'traffic.json');
      try {
        st = JSON.parse(fs.readFileSync(file, 'utf8'));
        if (!st || st.v !== 1) st = fresh();
      } catch { st = fresh(); }
      st.allTime = st.allTime || {};
      st.day = st.day || { key: utcDay(), per: {} };
      st.month = st.month || { key: utcMonth(), per: {}, baseBytes: 0 };
      roll();
      save();
      const t = setInterval(tick, 1000);
      if (t.unref) t.unref();
      process.once('exit', () => { try { save(); } catch {} });
      const lim = limitBytes();
      Logger.info(`Traffic meter: ${file}${lim ? ` (limit ${(lim / GIB).toFixed(2)} GiB/month)` : ''}`);
    },
    add(label, up, down) {
      if (!st || (!up && !down)) return;
      const k = norm(label);
      bump(st.allTime, k, up, down);
      bump(st.day.per, k, up, down);
      bump(st.month.per, k, up, down);
      live.up += up;
      live.down += down;
      dirty = true;
    },
    /** Count bytes of a proxied duplex pair: client->backend = upload, backend->client = download. */
    meter(label, client, backend) {
      const k = norm(label);
      active[k] = (active[k] || 0) + 1;
      let done = false;
      const end = () => { if (!done) { done = true; active[k] = Math.max(0, (active[k] || 1) - 1); } };
      client.on('data', (b) => Traffic.add(k, b.length, 0));
      backend.on('data', (b) => Traffic.add(k, 0, b.length));
      client.once('close', end);
      backend.once('close', end);
    },
    open(label) {
      const k = norm(label);
      active[k] = (active[k] || 0) + 1;
      let done = false;
      return () => { if (!done) { done = true; active[k] = Math.max(0, (active[k] || 1) - 1); } };
    },
    save,
    reset() { st = fresh(); for (const k of Object.keys(warned)) delete warned[k]; save(); },
    setMonthUsedGB(gb) { roll(); st.month.baseBytes = Math.round(gb * GIB) - sum(st.month.per).total; dirty = true; save(); },
    snapshot() {
      if (!st) return { ok: false, error: 'not started' };
      roll();
      let upBps = 0, downBps = 0;
      if (samples.length >= 2) {
        const a = samples[0];
        const b = samples[samples.length - 1];
        const dt = Math.max(1, (b.t - a.t) / 1000);
        const dUp = b.up - a.up, dDown = b.down - a.down;
        if (dUp >= 0 && dDown >= 0) { upBps = dUp / dt; downBps = dDown / dt; }
      }
      const month = sum(st.month.per);
      const base = st.month.baseBytes || 0;
      const lim = limitBytes();
      const used = month.total + base;
      const n = new Date();
      const next = new Date(Date.UTC(n.getUTCFullYear(), n.getUTCMonth() + 1, 1));
      return {
        ok: true,
        keys: KEYS,
        now: n.toISOString(),
        since: st.since,
        persisted: writable,
        file: path.basename(file || ''),
        day: { key: st.day.key, per: st.day.per, ...sum(st.day.per) },
        month: { key: st.month.key, per: st.month.per, ...month, baseBytes: base, used, resetsAt: next.toISOString() },
        allTime: { per: st.allTime, ...sum(st.allTime) },
        live: { upBps, downBps },
        active: { ...active },
        limit: lim ? { bytes: lim, used, remaining: Math.max(0, lim - used), pct: used / lim * 100 } : null
      };
    }
  };
})();

module.exports = Traffic;
