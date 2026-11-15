/**
 * Aral Pars — HTTP panel (Express).
 * Password login (created on first visit), dashboard APIs, subscriptions
 * (base64 / Clash / sing-box) and the XHTTP streaming reverse proxy.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const Logger = require('../logger');
const { PATHS, BRAND, normalizeHost } = require('../constants');
const { LinkGenerator } = require('./links');
const Traffic = require('../traffic');

const HOP_HEADERS = new Set(['connection', 'keep-alive', 'proxy-connection', 'upgrade', 'te', 'trailer', 'proxy-authorization', 'proxy-authenticate', 'transfer-encoding']);

function createHttpPanel(config, stateManager, engineStatusGetter, resolvedHostGetter, settings) {
  const app = express();
  const panelPath = config.panelPath.replace(/^\//, '') || 'aral';
  const pubDir = path.join(__dirname, '..', '..', 'public');

  // ===== XHTTP -> Xray-core streaming reverse proxy (registered before any auth / static route) =====
  const XHTTP_PATH = PATHS.xhttp;
  let xhttpLogged = 0;
  app.use((req, res, next) => {
    let p = String(req.url || '').split('?')[0];
    try { p = decodeURIComponent(p); } catch {}
    if (!(p === XHTTP_PATH || p.startsWith(XHTTP_PATH + '/'))) return next();
    const port = config.xhttpPort;
    if (!port) { res.statusCode = 404; return res.end(); }
    if (xhttpLogged < 10) { xhttpLogged++; Logger.info(`XHTTP ${req.method} ${p.slice(XHTTP_PATH.length) || '/'}`); }

    for (const sock of [req.socket]) {
      try { sock.setTimeout(0); sock.setNoDelay(true); sock.setKeepAlive(true, 10000); } catch {}
    }
    const headers = {};
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const k = req.rawHeaders[i];
      if (HOP_HEADERS.has(k.toLowerCase())) continue;
      headers[k] = headers[k] === undefined ? req.rawHeaders[i + 1] : [].concat(headers[k], req.rawHeaders[i + 1]);
    }
    const up = http.request({ host: '127.0.0.1', port, method: req.method, path: req.url, headers, agent: false });
    up.on('socket', (sk) => { try { sk.setTimeout(0); sk.setNoDelay(true); } catch {} });
    up.on('response', (pr) => {
      const out = {};
      for (let i = 0; i < pr.rawHeaders.length; i += 2) {
        const k = pr.rawHeaders[i];
        if (HOP_HEADERS.has(k.toLowerCase())) continue;
        out[k] = out[k] === undefined ? pr.rawHeaders[i + 1] : [].concat(out[k], pr.rawHeaders[i + 1]);
      }
      res.removeHeader('X-Powered-By');
      res.writeHead(pr.statusCode, pr.statusMessage, out);
      if (typeof res.flushHeaders === 'function') res.flushHeaders();
      pr.on('data', (b) => Traffic.add('VLESS-XHTTP', 0, b.length));
      pr.pipe(res);
      pr.on('error', () => { try { res.destroy(); } catch {} });
    });
    up.on('error', () => {
      if (!res.headersSent) { res.statusCode = 502; res.end(); } else { try { res.destroy(); } catch {} }
    });
    const xhDone = Traffic.open('VLESS-XHTTP');
    res.once('close', xhDone);
    req.on('data', (b) => Traffic.add('VLESS-XHTTP', b.length, 0));
    req.pipe(up);
    req.on('error', () => { try { up.destroy(); } catch {} });
    res.on('close', () => { if (!res.writableFinished) { try { up.destroy(); } catch {} } });
  });

  // ===== Auth: scrypt password (created on first visit) + signed session cookie =====
  const authFile = path.join(stateManager.paths.dataDir, 'auth.json');
  const loadAuth = () => {
    try { return JSON.parse(fs.readFileSync(authFile, 'utf8')) || {}; } catch { return {}; }
  };
  const saveAuth = (a) => {
    try {
      fs.mkdirSync(path.dirname(authFile), { recursive: true });
      fs.writeFileSync(authFile, JSON.stringify(a, null, 2), { encoding: 'utf8', mode: 0o600 });
    } catch (err) { Logger.warn('Could not save auth.json: ' + err.message); }
  };
  (function initAuth() {
    const a = loadAuth();
    if (process.env.RESET_PANEL_PASSWORD === 'true') {
      delete a.hash;
      delete a.salt;
      Logger.warn('Panel password was reset. Open the panel to create a new one, then delete RESET_PANEL_PASSWORD.');
    }
    if (!a.secret) a.secret = crypto.randomBytes(32).toString('hex');
    const envTok = String(process.env.SUB_TOKEN || '').trim();
    if (envTok) a.subToken = envTok;
    if (!a.subToken) a.subToken = crypto.randomBytes(18).toString('base64url');
    const envPw = String(process.env.PANEL_PASSWORD || '');
    if (envPw && process.env.RESET_PANEL_PASSWORD !== 'true') {
      const same = a.hash && a.salt && crypto.scryptSync(envPw, String(a.salt), 64).toString('hex') === a.hash;
      if (!same) {
        if (envPw.length < 8) Logger.warn('PANEL_PASSWORD is shorter than 8 characters - ignored.');
        else { a.salt = crypto.randomBytes(16).toString('hex'); a.hash = crypto.scryptSync(envPw, a.salt, 64).toString('hex'); }
      }
    }
    saveAuth(a);
  })();
  const hashPw = (pw, salt) => crypto.scryptSync(String(pw), String(salt), 64).toString('hex');
  const safeEq = (a, b) => {
    const x = Buffer.from(String(a));
    const y = Buffer.from(String(b));
    return x.length === y.length && crypto.timingSafeEqual(x, y);
  };
  const sign = (secret, v) => crypto.createHmac('sha256', secret).update(String(v)).digest('hex');
  const cookies = (req) => {
    const out = {};
    String(req.headers.cookie || '').split(';').forEach((p) => {
      const i = p.indexOf('=');
      if (i > 0) { try { out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); } catch {} }
    });
    return out;
  };
  const SESSION_DAYS = 30;
  const setSession = (res, a) => {
    const exp = String(Date.now() + SESSION_DAYS * 86400000);
    const val = exp + '.' + sign(a.secret, exp);
    res.setHeader('Set-Cookie', `aral_session=${val}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`);
  };
  const hasSession = (req) => {
    const a = loadAuth();
    if (!a.hash || !a.secret) return false;
    const parts = String(cookies(req).aral_session || '').split('.');
    if (parts.length !== 2 || !parts[0] || !parts[1] || Number(parts[0]) < Date.now()) return false;
    return safeEq(parts[1], sign(a.secret, parts[0]));
  };

  // login brute-force throttle
  const fails = new Map();
  const ipOf = (req) => String(req.headers['x-forwarded-for'] || (req.socket && req.socket.remoteAddress) || '').split(',')[0].trim();
  const blocked = (ip) => { const r = fails.get(ip); return !!r && r.count >= 8 && Date.now() - r.first < 15 * 60000; };
  const fail = (ip) => {
    const r = fails.get(ip);
    if (!r || Date.now() - r.first > 15 * 60000) fails.set(ip, { first: Date.now(), count: 1 });
    else r.count++;
  };

  // ===== Static assets =====
  app.use('/assets', express.static(path.join(pubDir, 'assets'), { maxAge: '5m' }));

  // ===== Login pages =====
  const renderLogin = (mode, msg) => {
    const setup = mode === 'setup';
    let html = fs.readFileSync(path.join(pubDir, 'login.html'), 'utf8');
    const action = `/${panelPath}/login`;
    const fields = setup
      ? `<div class="field"><label>رمز عبور جدید</label><input class="ltr" name="password" type="password" minlength="8" required autocomplete="new-password"></div>
         <div class="field"><label>تکرار رمز عبور</label><input class="ltr" name="confirm" type="password" minlength="8" required autocomplete="new-password"></div>`
      : `<div class="field"><label>رمز عبور</label><input class="ltr" name="password" type="password" required autocomplete="current-password"></div>`;
    html = html
      .replace('__SUB__', setup ? 'برای شروع، رمز عبور پنل را بسازید (حداقل ۸ کاراکتر).' : 'رمز عبور پنل را وارد کنید.')
      .replace('__ACTION__', action)
      .replace('__FIELDS__', fields)
      .replace('__BTN__', setup ? 'ساخت رمز و ورود' : 'ورود به پنل')
      .replace('__ERR__', msg || '');
    if (msg) html = html.replace('<div id="err" class="err" style="display:none">', '<div class="err">');
    return html;
  };

  app.get(`/${panelPath}/login`, (req, res) => {
    const a = loadAuth();
    if (a.hash && hasSession(req)) return res.redirect(302, `/${panelPath}`);
    const page = renderLogin(a.hash ? 'login' : 'setup', '');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(page);
  });

  app.post(`/${panelPath}/login`, express.urlencoded({ extended: false, limit: '10kb' }), (req, res) => {
    const a = loadAuth();
    const ip = ipOf(req);
    if (blocked(ip)) { res.status(429); return res.send(renderLogin(a.hash ? 'login' : 'setup', 'تلاش‌های ناموفق زیاد؛ چند دقیقه بعد دوباره امتحان کنید.')); }
    const b = req.body || {};
    const mode = a.hash ? 'login' : 'setup';

    if (mode === 'setup') {
      const pw = String(b.password || '');
      if (pw.length < 8 || pw !== String(b.confirm || '')) {
        return res.send(renderLogin('setup', 'رمز باید حداقل ۸ کاراکتر باشد و با تأییدش یکی باشد.'));
      }
      a.salt = crypto.randomBytes(16).toString('hex');
      a.hash = hashPw(pw, a.salt);
      saveAuth(a);
      setSession(res, a);
      Logger.success('Panel password created.');
      return res.redirect(302, `/${panelPath}`);
    }

    if (!safeEq(hashPw(String(b.password || ''), a.salt), a.hash)) {
      fail(ip);
      return res.send(renderLogin('login', 'رمز عبور نادرست است.'));
    }
    setSession(res, a);
    return res.redirect(302, `/${panelPath}`);
  });

  app.get(`/${panelPath}/logout`, (req, res) => {
    res.setHeader('Set-Cookie', 'aral_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
    res.redirect(302, `/${panelPath}/login`);
  });

  // Auth: logged-in session cookie, or ?token=<subscription token> for VPN client subscriptions
  const authMiddleware = (req, res, next) => {
    const q = String(req.query.token || req.query.key || '');
    const a = loadAuth();
    if (q && a.hash && a.subToken && safeEq(q, a.subToken)) return next();
    if (hasSession(req)) return next();
    if (req.method === 'GET' && (req.path === '/' || req.path === `/${panelPath}`)) {
      return res.redirect(302, `/${panelPath}/login`);
    }
    res.status(401).send('Unauthorized');
  };
  const sessionOnly = (req, res, next) => (hasSession(req) ? next() : res.status(401).json({ ok: false, error: 'session required' }));
  const sameOrigin = (req, res, next) => (req.get('x-aral-req') === '1' ? next() : res.status(403).json({ ok: false, error: 'cross-site rejected' }));

  // ===== Main panel page =====
  const renderPanel = (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    const html = fs.readFileSync(path.join(pubDir, 'index.html'), 'utf8')
      .replace('__PANELPATH__', panelPath);
    res.send(html);
  };
  app.get('/', authMiddleware, renderPanel);
  app.get(`/${panelPath}`, authMiddleware, renderPanel);
  // panel client script (served from the panel path)
  app.get(`/${panelPath}/app.js`, (req, res) => {
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.send(fs.readFileSync(path.join(pubDir, 'app.js'), 'utf8'));
  });

  // ===== Helper: active host for links =====
  const getRequestHost = (req) => {
    const explicit = normalizeHost(process.env.DOMAIN || '');
    if (explicit) return explicit;
    const h = normalizeHost(req.headers.host || req.headers['x-forwarded-host'] || '');
    return h || resolvedHostGetter();
  };

  const subBaseFor = (req) => {
    const a = loadAuth();
    const host = getRequestHost(req);
    const proto = req.headers['x-forwarded-proto'] === 'https' || req.secure ? 'https' : 'http';
    const portPart = (proto === 'http' && req.socket && ![80, 443].includes(req.socket.localPort || 0)) ? ':' + req.socket.localPort : '';
    return `${proto}://${host}${portPart}`;
  };

  // ===== Dashboard APIs =====
  app.get(`/${panelPath}/api/health`, sessionOnly, (req, res) => {
    const a = loadAuth();
    const host = getRequestHost(req);
    const linkGen = new LinkGenerator(config, stateManager.state, host);
    const engines = engineStatusGetter();
    res.setHeader('Cache-Control', 'no-store');
    res.json({
      ok: true,
      brand: BRAND.name,
      version: '1.0.0',
      host,
      port: config.publicPort,
      uuid: stateManager.state.uuid,
      engines,
      enable: config.enable,
      domain: config.domain || '',
      ss: { method: config.shadowsocks.method || 'aes-256-gcm', password: stateManager.state.shadowsocksPassword ? 'set' : '' },
      protocols: [
        { name: 'VLESS-WS', path: PATHS.vlessWs, enabled: !!config.enable.vlessWs, note: 'WebSocket مستقیم' },
        { name: 'VLESS-WS-TLS', path: PATHS.vlessWs, enabled: !!config.enable.vlessWsTls && !!config.enable.vlessWs, note: 'TLS با گواهی self-signed' },
        { name: 'VMess-WS', path: PATHS.vmessWs, enabled: !!config.enable.vmessWs, note: '' },
        { name: 'VMess-WS-TLS', path: PATHS.vmessWs, enabled: !!config.enable.vmessWsTls && !!config.enable.vmessWs, note: '' },
        { name: 'Trojan-WS', path: PATHS.trojanWs, enabled: !!config.enable.trojanWs, note: '' },
        { name: 'Trojan-WS-TLS', path: PATHS.trojanWs, enabled: !!config.enable.trojanWsTls && !!config.enable.trojanWs, note: 'Clash: فقط این مدل' },
        { name: 'VLESS-HTTPUpgrade', path: PATHS.vlessHu, enabled: !!config.enable.vlessHttpUpgrade, note: '' },
        { name: 'VMess-HTTPUpgrade', path: PATHS.vmessHu, enabled: !!config.enable.vmessHttpUpgrade, note: '' },
        { name: 'Trojan-HTTPUpgrade', path: PATHS.trojanHu, enabled: !!config.enable.trojanHttpUpgrade, note: '' },
        { name: 'VLESS-gRPC', path: '/' + PATHS.grpcService, enabled: !!config.enable.vlessGrpc, note: 'h2c' },
        { name: 'VLESS-gRPC-TLS', path: '/' + PATHS.grpcService, enabled: !!config.enable.vlessGrpcTls, note: 'ALPN h2' },
        { name: 'Shadowsocks-WS', path: PATHS.ssWs, enabled: !!config.enable.ssWs && !!config.ssWsPort, note: 'v2ray-plugin websocket' },
        { name: 'VLESS-XHTTP', path: PATHS.xhttp, enabled: !!config.enable.vlessXhttp && config.xhttpPort !== null, note: 'فقط کلاینت‌های Xray' }
      ],
      subUrl: `${subBaseFor(req)}/${panelPath}/sub?token=${a.subToken}`,
      subClashUrl: `${subBaseFor(req)}/${panelPath}/clash?token=${a.subToken}`,
      subSbUrl: `${subBaseFor(req)}/${panelPath}/sb?token=${a.subToken}`,
      tls: { insecure: linkGen.insecure, pcs: linkGen.pcs ? 'set' : '' }
    });
  });

  app.get(`/${panelPath}/api/nodes`, sessionOnly, (req, res) => {
    const host = getRequestHost(req);
    const linkGen = new LinkGenerator(config, stateManager.state, host);
    const nodes = linkGen.getAllNodes({ compat: 'full', allowLocalHostLinks: true });
    res.setHeader('Cache-Control', 'no-store');
    res.json(nodes.map((n) => ({ name: n.name, type: n.type, uri: n.uri, note: n.note || '' })));
  });

  // ===== Settings APIs =====
  app.post(`/${panelPath}/api/settings/general`, sessionOnly, sameOrigin, express.json({ limit: '8kb' }), (req, res) => {
    const body = req.body || {};
    let relogin = false;
    const a = loadAuth();
    if (body.password !== undefined && body.password !== '') {
      const pw = String(body.password);
      if (pw.length < 8) return res.status(400).json({ ok: false, error: 'password must be at least 8 characters' });
      a.salt = crypto.randomBytes(16).toString('hex');
      a.hash = hashPw(pw, a.salt);
      saveAuth(a);
      relogin = true;
      Logger.info('Panel password changed from the panel.');
    }
    if (body.domain !== undefined) {
      const d = normalizeHost(String(body.domain || ''));
      settings.setDomain(d);
      Logger.info(`Link domain set to "${d || '(auto)'}" from the panel (applies after restart).`);
    }
    res.json({ ok: true, relogin });
  });

  app.post(`/${panelPath}/api/settings/protocols`, sessionOnly, sameOrigin, express.json({ limit: '4kb' }), (req, res) => {
    const enable = (req.body && req.body.enable) || {};
    const applied = settings.setProtocols(enable);
    res.json({ ok: true, applied });
  });

  app.post(`/${panelPath}/api/settings/advanced`, sessionOnly, sameOrigin, express.json({ limit: '4kb' }), (req, res) => {
    const body = req.body || {};
    const applied = settings.setAdvanced({
      ssPassword: body.ssPassword,
      ssMethod: body.ssMethod
    });
    res.json({ ok: true, applied });
  });

  // ===== Traffic APIs =====
  app.get(`/${panelPath}/api/traffic`, sessionOnly, (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.json(Traffic.snapshot());
  });
  app.post(`/${panelPath}/api/traffic/reset`, sessionOnly, sameOrigin, (req, res) => {
    Traffic.reset();
    Logger.warn('Traffic counter reset from the panel.');
    res.setHeader('Cache-Control', 'no-store');
    res.json(Traffic.snapshot());
  });
  app.post(`/${panelPath}/api/traffic/baseline`, sessionOnly, sameOrigin, express.json({ limit: '2kb' }), (req, res) => {
    const gb = Number(req.body && req.body.gb);
    if (!isFinite(gb) || gb < 0 || gb > 1000000) return res.status(400).json({ ok: false, error: 'invalid value' });
    Traffic.setMonthUsedGB(gb);
    res.setHeader('Cache-Control', 'no-store');
    res.json(Traffic.snapshot());
  });

  // ===== Subscriptions =====
  // Base64 & Raw (v2rayN, v2rayNG, Hiddify)
  app.get([`/${panelPath}/sub`, `/${panelPath}/base64`, `/${panelPath}/raw`, '/sub', '/base64'], authMiddleware, (req, res) => {
    const isBase64 = req.path.endsWith('/base64') || req.path.endsWith('/sub') || req.path === '/sub';
    const compatMode = req.query.compat || 'v2ray';
    const host = getRequestHost(req);
    const linkGen = new LinkGenerator(config, stateManager.state, host);
    const allowLocal = Boolean(config.allowLocalHostLinks || host === '127.0.0.1' || host === 'localhost');
    const nodes = linkGen.getAllNodes({ compat: compatMode, allowLocalHostLinks: allowLocal });
    const text = nodes.map((n) => n.uri).join('\n');

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'inline; filename="AralPars.txt"');
    res.setHeader('Profile-Update-Interval', '24');
    res.setHeader('Subscription-Userinfo', 'upload=1073741824; download=2147483648; total=1099511627776; expire=0');
    res.send(isBase64 ? Buffer.from(text).toString('base64') : text);
  });

  // Clash Meta (Mihomo)
  app.get([`/${panelPath}/clash`, `/${panelPath}/clash.yaml`, '/clash'], authMiddleware, (req, res) => {
    const host = getRequestHost(req);
    const linkGen = new LinkGenerator(config, stateManager.state, host);
    const nodes = linkGen.getAllNodes({ compat: 'full', allowLocalHostLinks: true });
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Content-Type', 'text/yaml; charset=utf-8');
    res.setHeader('Content-Disposition', 'inline; filename="AralPars.yaml"');
    res.setHeader('Profile-Update-Interval', '24');
    res.send(linkGen.buildClashMetaYaml(nodes));
  });

  // sing-box client JSON
  app.get([`/${panelPath}/sb`, `/${panelPath}/sb/raw`, `/${panelPath}/sb/base64`, '/sb'], authMiddleware, (req, res) => {
    const isBase64 = req.path.endsWith('/base64');
    const host = getRequestHost(req);
    const linkGen = new LinkGenerator(config, stateManager.state, host);
    const nodes = linkGen.getAllNodes({ compat: 'full', allowLocalHostLinks: true });
    const jsonStr = linkGen.buildSingBoxClientJson(nodes);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Content-Type', isBase64 ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8');
    if (isBase64) res.send(Buffer.from(jsonStr).toString('base64'));
    else res.send(jsonStr);
  });

  const server = http.createServer(app);
  server.keepAliveTimeout = 120000;
  server.headersTimeout = 125000;
  server.requestTimeout = 0; // XHTTP stream-up / stream-one requests are long-lived
  server.timeout = 0;
  return { server, app };
}

module.exports = { createHttpPanel };
