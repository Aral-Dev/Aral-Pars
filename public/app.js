/* Aral Pars — panel client application (vanilla JS, no dependencies). */
'use strict';

// ---------- helpers ----------
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }));

// Base path of the panel (e.g. "/aral") — derived from the current URL.
const BASE = (() => {
  const m = location.pathname.match(/^(\/[^/]+)\/?/);
  return (m && m[1] !== '/login') ? m[1] : '';
})();

function toast(msg, ms = 2200) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(t._h);
  t._h = setTimeout(() => t.classList.remove('show'), ms);
}

async function api(path, opts) {
  const res = await fetch(BASE + '/' + path.replace(/^\//, ''), { headers: { 'X-Aral-Req': '1' }, ...opts });
  if (res.status === 401) { location.href = BASE + '/login'; throw new Error('unauthorized'); }
  return res.json();
}

function copyText(txt) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(txt).then(() => true, () => legacyCopy(txt));
  }
  return Promise.resolve(legacyCopy(txt));
}
function legacyCopy(txt) {
  const ta = document.createElement('textarea');
  ta.value = txt;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch { ok = false; }
  ta.remove();
  return ok;
}
function copyFromInput(id) {
  const v = $(id).value;
  copyText(v).then((ok) => toast(ok ? 'کپی شد ✓' : 'کپی ناموفق'));
}

const fmtBytes = (b) => {
  if (!isFinite(b) || b <= 0) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(u.length - 1, Math.floor(Math.log(b) / Math.log(1024)));
  return (b / Math.pow(1024, i)).toFixed(i >= 2 ? 2 : 0) + ' ' + u[i];
};
const fmtBps = (b) => fmtBytes(b) + '/s';

// ---------- tabs ----------
function switchTab(name) {
  document.querySelectorAll('nav.tabs button[data-tab]').forEach((b) => b.classList.toggle('on', b.dataset.tab === name));
  document.querySelectorAll('.section').forEach((s) => s.classList.toggle('on', s.id === 'sec-' + name));
}
document.querySelectorAll('nav.tabs button[data-tab]').forEach((b) => {
  b.addEventListener('click', () => switchTab(b.dataset.tab));
});

// ---------- copy buttons ----------
document.querySelectorAll('[data-copy]').forEach((b) => {
  b.addEventListener('click', () => copyFromInput(b.dataset.copy));
});

// ---------- state ----------
let H = {}; // health snapshot

async function loadHealth() {
  H = await api('api/health');
  $('info-host').value = H.host || '-';
  $('info-port').value = String(H.port || '-');
  $('info-uuid').value = H.uuid || '-';
  $('sub-main').value = H.subUrl || '';
  $('sub-clash').value = H.subClashUrl || '';
  $('sub-sb').value = H.subSbUrl || '';

  $('pill-singbox').classList.toggle('ok', !!H.engines.singbox);
  $('pill-xray').classList.toggle('ok', !!H.engines.xray);
  $('pill-https').classList.toggle('ok', !!H.engines.https);
  renderProtoTable();
}

function renderProtoTable() {
  const rows = (H.protocols || []).map((p) =>
    `<tr>
      <td>${esc(p.name)}</td>
      <td class="mono">${esc(p.path || '-')}</td>
      <td>${p.enabled ? '<span class="badge" style="border-color:#2ECC71;color:#7DDBA0">فعال</span>' : '<span class="badge" style="border-color:#C0392B;color:#e08a94">غیرفعال</span>'}</td>
      <td>${esc(p.note || '')}</td>
    </tr>`);
  $('proto-body').innerHTML = rows.join('') || '<tr><td colspan="4" class="muted">پروتکلی فعال نیست.</td></tr>';
}

// ---------- traffic ----------
async function loadTraffic() {
  const t = await api('api/traffic');
  if (!t.ok) return;
  $('st-day').textContent = fmtBytes(t.day.total);
  $('st-day-sub').textContent = 'از ' + t.since.slice(0, 10);
  $('st-month').textContent = fmtBytes(t.month.used);
  $('st-month-sub').textContent = 'بازنشانی: ' + String(t.month.resetsAt).slice(0, 10);
  $('st-live').textContent = fmtBps(t.live.upBps) + ' / ' + fmtBps(t.live.downBps);
  const act = Object.values(t.active || {}).reduce((a, b) => a + b, 0);
  $('st-active').textContent = String(act);
}

// ---------- configs ----------
async function loadConfigs() {
  const list = await api('api/nodes');
  const el = $('cfg-list');
  if (!Array.isArray(list) || !list.length) {
    el.innerHTML = '<div class="muted">کانفیگی تولید نشد — موتورها را بررسی کنید.</div>';
    return;
  }
  el.innerHTML = list.map((n, i) => `
    <div class="cfg">
      <div class="cfg-head">
        <span class="nm">${esc(n.name)}</span>
        <span class="tp">${esc(n.type)}</span>
        <button class="btn sm" data-cfg-copy="${i}">کپی لینک</button>
      </div>
      ${n.note ? `<div class="note">${esc(n.note)}</div>` : ''}
      <div class="uri">${esc(n.uri)}</div>
    </div>`).join('');
  el.querySelectorAll('[data-cfg-copy]').forEach((b) => {
    b.addEventListener('click', () => {
      copyText(list[Number(b.dataset.cfgCopy)].uri).then((ok) => toast(ok ? 'لینک کپی شد ✓' : 'کپی ناموفق'));
    });
  });
  window.__cfgLinks = list.map((n) => n.uri);
}

// ---------- settings ----------
const PROTO_META = [
  ['vlessWs', 'VLESS-WS', 'WebSocket مستقیم'],
  ['vlessWsTls', 'VLESS-WS-TLS', 'WebSocket + TLS'],
  ['vmessWs', 'VMess-WS', 'WebSocket مستقیم'],
  ['vmessWsTls', 'VMess-WS-TLS', 'WebSocket + TLS'],
  ['trojanWs', 'Trojan-WS', 'WebSocket مستقیم'],
  ['trojanWsTls', 'Trojan-WS-TLS', 'WebSocket + TLS'],
  ['vlessHttpUpgrade', 'VLESS-HTTPUpgrade', 'HTTPUpgrade'],
  ['vmessHttpUpgrade', 'VMess-HTTPUpgrade', 'HTTPUpgrade'],
  ['trojanHttpUpgrade', 'Trojan-HTTPUpgrade', 'HTTPUpgrade'],
  ['vlessGrpc', 'VLESS-gRPC', 'gRPC (h2c)'],
  ['vlessGrpcTls', 'VLESS-gRPC-TLS', 'gRPC + TLS (ALPN h2)'],
  ['ssWs', 'Shadowsocks-WS', 'Shadowsocks روی WebSocket'],
  ['vlessXhttp', 'VLESS-XHTTP', 'فقط کلاینت‌های Xray']
];

function renderProtoSwitches() {
  const en = H.enable || {};
  $('proto-switches').innerHTML = PROTO_META.map(([k, n, d]) => `
    <div class="switch-row">
      <div>
        <div class="lbl">${n}</div>
        <div class="desc">${d}</div>
      </div>
      <label class="switch">
        <input type="checkbox" data-proto="${k}" ${en[k] ? 'checked' : ''}>
        <span class="sl"></span>
      </label>
    </div>`).join('');
}

async function saveProtocols() {
  const payload = { enable: {} };
  document.querySelectorAll('[data-proto]').forEach((c) => { payload.enable[c.dataset.proto] = c.checked; });
  await api('api/settings/protocols', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
  toast('ذخیره شد — با ری‌استارت سرور اعمال می‌شود ✓');
}

async function saveGeneral() {
  const payload = {
    password: $('set-password').value || undefined,
    domain: $('set-domain').value || undefined
  };
  const r = await api('api/settings/general', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
  if (r && r.ok) {
    toast(r.relogin ? 'رمز تغییر کرد — دوباره وارد شوید…' : 'ذخیره شد ✓');
    if (r.relogin) setTimeout(() => { location.href = BASE + '/login'; }, 900);
  }
}

async function saveAdvanced() {
  const payload = {
    ssPassword: $('set-ss-pass').value || undefined,
    ssMethod: $('set-ss-method').value || undefined
  };
  const r = await api('api/settings/advanced', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
  if (r && r.ok) toast('ذخیره شد — با ری‌استارت سرور اعمال می‌شود ✓');
}

async function fillSettings() {
  $('set-domain').value = H.domain || '';
  $('set-ss-pass').value = H.ss && H.ss.password ? '••••••••' : '';
  $('set-ss-pass').dataset.filled = H.ss && H.ss.password ? '1' : '';
  $('set-ss-method').value = (H.ss && H.ss.method) || 'aes-256-gcm';
}

// ---------- wire up ----------
$('btn-copy-uuid').addEventListener('click', () => copyFromInput('info-uuid'));
$('btn-copy-all').addEventListener('click', () => {
  copyText((window.__cfgLinks || []).join('\n')).then((ok) => toast(ok ? 'همهٔ لینک‌ها کپی شد ✓' : 'کپی ناموفق'));
});
$('btn-refresh-configs').addEventListener('click', loadConfigs);
$('btn-traffic-reset').addEventListener('click', async () => {
  await api('api/traffic/reset', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  toast('شمارندهٔ ترافیک بازنشانی شد ✓');
  loadTraffic();
});
$('btn-save-settings').addEventListener('click', saveGeneral);
$('btn-save-advanced').addEventListener('click', saveAdvanced);
$('btn-logout').addEventListener('click', async () => {
  await api('logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  location.href = BASE + '/login';
});

// ---------- boot ----------
(async function boot() {
  await loadHealth();
  renderProtoSwitches();
  await fillSettings();
  await loadTraffic();
  await loadConfigs();
  setInterval(loadTraffic, 5000);
})();
