/**
 * ====================================================================
 *   ARAL PARS — lightweight one-port multi-protocol proxy panel
 * --------------------------------------------------------------------
 *   Brand: Aral Pars · یک پورت، همهٔ مسیرها
 *
 *   Protocols (all on the single public PORT):
 *     VLESS-WS / VLESS-WS-TLS · VMess-WS / VMess-WS-TLS
 *     Trojan-WS / Trojan-WS-TLS · VLESS / VMess / Trojan HTTPUpgrade
 *     VLESS-gRPC / VLESS-gRPC-TLS · Shadowsocks-WS · VLESS-XHTTP
 *
 *   Engines: sing-box + Xray-core (downloaded automatically on first start)
 *   Storage: ./aral-data/  (keep this folder!)
 * ====================================================================
 */
'use strict';

const path = require('path');
const http = require('https');
const { BRAND, normalizeHost, mask, resolveDataDir } = require('./lib/constants');
const Logger = require('./lib/logger');
const { allocatePorts } = require('./lib/ports');
const { SettingsManager } = require('./lib/settings');

// --------------------------------------------------------------------------
// Default configuration
// --------------------------------------------------------------------------
const DEFAULT_CONFIG = {
  brand: BRAND.name,
  product: 'Aral Pars',
  publicPort: parseInt(process.env.PORT || process.env.SERVER_PORT || '8080', 10) || 8080,
  panelPath: 'aral',
  dataDirHint: 'aral-data',
  uuid: '',
  domain: '',
  forceHost: '',
  allowLocalHostLinks: false,
  singBoxVersion: '1.11.15',
  xrayVersion: '',
  enable: {
    vlessWs: true,
    vlessWsTls: true,
    vmessWs: true,
    vmessWsTls: true,
    trojanWs: true,
    trojanWsTls: true,
    vlessHttpUpgrade: true,
    vmessHttpUpgrade: true,
    trojanHttpUpgrade: true,
    vlessGrpc: true,
    vlessGrpcTls: true,
    ssWs: true,
    vlessXhttp: true
  },
  shadowsocks: {
    method: 'aes-256-gcm',
    password: ''
  }
};

/**
 * Merge defaults with environment variables.
 */
function buildConfig(userOverrides = {}) {
  const cfg = JSON.parse(JSON.stringify(DEFAULT_CONFIG));

  if (userOverrides && typeof userOverrides === 'object') {
    for (const [key, val] of Object.entries(userOverrides)) {
      if (val !== undefined && val !== null) {
        if (typeof val === 'object' && !Array.isArray(val) && cfg[key] && typeof cfg[key] === 'object') {
          cfg[key] = { ...cfg[key], ...val };
        } else {
          cfg[key] = val;
        }
      }
    }
  }

  const env = process.env;
  const parseBool = (v, defaultVal) => (v !== undefined ? v === '1' || v === 'true' : defaultVal);

  if (env.PORT || env.SERVER_PORT || env.ARAL_PORT) {
    const parsedPort = parseInt(env.PORT || env.SERVER_PORT || env.ARAL_PORT, 10);
    if (!isNaN(parsedPort) && parsedPort > 0) cfg.publicPort = parsedPort;
  }
  if (env.UUID) cfg.uuid = env.UUID;
  if (env.DOMAIN) cfg.domain = env.DOMAIN;
  if (env.FORCE_HOST) cfg.forceHost = env.FORCE_HOST;
  if (env.ALLOW_LOCALHOST_LINKS !== undefined) cfg.allowLocalHostLinks = parseBool(env.ALLOW_LOCALHOST_LINKS, cfg.allowLocalHostLinks);
  if (env.PANEL_PATH || env.ARAL_PATH) cfg.panelPath = (env.PANEL_PATH || env.ARAL_PATH).replace(/^\//, '');

  // Protocol switches via env
  const sw = {
    ENABLE_VLESS_WS: 'vlessWs',
    ENABLE_VLESS_WS_TLS: 'vlessWsTls',
    ENABLE_VMESS_WS: 'vmessWs',
    ENABLE_VMESS_WS_TLS: 'vmessWsTls',
    ENABLE_TROJAN_WS: 'trojanWs',
    ENABLE_TROJAN_WS_TLS: 'trojanWsTls',
    ENABLE_HTTPUPGRADE: 'vlessHttpUpgrade',
    ENABLE_VLESS_HTTPUPGRADE: 'vlessHttpUpgrade',
    ENABLE_VMESS_HTTPUPGRADE: 'vmessHttpUpgrade',
    ENABLE_TROJAN_HTTPUPGRADE: 'trojanHttpUpgrade',
    ENABLE_VLESS_GRPC: 'vlessGrpc',
    ENABLE_VLESS_GRPC_TLS: 'vlessGrpcTls',
    ENABLE_SS_WS: 'ssWs',
    ENABLE_XHTTP: 'vlessXhttp'
  };
  for (const [k, f] of Object.entries(sw)) {
    if (env[k] !== undefined) cfg.enable[f] = parseBool(env[k], cfg.enable[f]);
  }

  if (env.SS_METHOD) cfg.shadowsocks.method = env.SS_METHOD;
  if (env.SS_PASSWORD) cfg.shadowsocks.password = env.SS_PASSWORD;

  cfg.domain = normalizeHost(cfg.domain);
  cfg.forceHost = normalizeHost(cfg.forceHost);

  // Data paths (all inside aral-data/)
  const dataDir = resolveDataDir();
  const paths = {
    dataDir,
    stateFile: path.join(dataDir, 'state.json'),
    binDir: path.join(dataDir, 'bin'),
    certDir: path.join(dataDir, 'cert'),
    certPath: path.join(dataDir, 'cert', 'cert.pem'),
    keyPath: path.join(dataDir, 'cert', 'key.pem'),
    singboxBin: path.join(dataDir, 'bin', process.platform === 'win32' ? 'sing-box.exe' : 'sing-box'),
    singboxConfig: path.join(dataDir, 'sing-box.json'),
    singboxLog: path.join(dataDir, 'sing-box.log'),
    xrayBin: path.join(dataDir, 'bin', process.platform === 'win32' ? 'xray.exe' : 'xray'),
    xrayConfig: path.join(dataDir, 'xray.json'),
    xrayLog: path.join(dataDir, 'xray.log')
  };

  return { ...cfg, paths };
}

// --------------------------------------------------------------------------
// Resolve public host (domain / saved host / egress IP)
// --------------------------------------------------------------------------
async function resolvePublicHost(config, savedHost) {
  if (config.forceHost) return config.forceHost;
  if (config.domain) return config.domain;
  if (savedHost && savedHost !== '127.0.0.1' && savedHost !== 'localhost') {
    Logger.info('Using public domain saved from an earlier visit.');
    return savedHost;
  }

  // egress IP discovery (no external deps)
  const fetchText = (url) => new Promise((resolve) => {
    const req = http.get(url, { headers: { 'User-Agent': 'AralPars/1.0' }, timeout: 3500 }, (res) => {
      if (res.statusCode !== 200) { res.resume(); return resolve(null); }
      let s = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { s += c; });
      res.on('end', () => resolve(s));
    });
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
  });

  try {
    const t = await fetchText('https://api.ipify.org?format=text');
    if (t && t.trim()) return t.trim();
  } catch {}
  try {
    const t = await fetchText('https://1.1.1.1/cdn-cgi/trace');
    if (t) {
      const m = /ip=([^\r\n]+)/.exec(t);
      if (m && m[1]) return m[1].trim();
    }
  } catch {}
  return '127.0.0.1';
}

// --------------------------------------------------------------------------
// Boot
// --------------------------------------------------------------------------
const StateManager = require('./lib/state');
const Traffic = require('./lib/traffic');
const { BinaryManager } = require('./lib/binaries');
const SingBoxEngine = require('./lib/engines/singbox');
const XrayEngine = require('./lib/engines/xray');
const { LinkGenerator } = require('./lib/panel/links');
const { createHttpPanel } = require('./lib/panel/http-panel');
const TcpRouter = require('./lib/mux/tcp-router');

async function startPanel(userConfig = {}) {
  // 1. Banner
  Logger.banner();

  // 2. Configuration (+ persisted settings)
  const config = buildConfig(userConfig);
  const settingsMgr = new SettingsManager(config.paths.dataDir);
  settingsMgr.applyTo(config);
  Logger.section('Configuration');
  Logger.item('Public Port', config.publicPort);
  Logger.item('Panel Path', `/${config.panelPath}`);
  Logger.item('Data Directory', `${config.paths.dataDir} (${resolveDataDir.info ? resolveDataDir.info.source : 'default'})`);

  Traffic.init(config.paths.dataDir);

  // 3. Persistent state
  const stateMgr = new StateManager(config.paths, config);
  const state = stateMgr.loadOrCreate();
  Logger.item('UUID', mask(state.uuid) + (process.env.UUID ? ' (from env)' : ' (saved)'));

  // 4. Resolve host / IP
  const resolvedHost = await resolvePublicHost(config, state.publicIp || '');
  stateMgr.setPublicIp(resolvedHost);
  Logger.item('Resolved Host', resolvedHost);

  // 5. Allocate dynamic internal ports (all on 127.0.0.1)
  const allocatedPorts = {};
  if (config.enable.vlessWs) allocatedPorts.vlessWs = await allocatePorts();
  if (config.enable.vmessWs || config.enable.vmessWsTls) allocatedPorts.vmessWs = await allocatePorts();
  if (config.enable.vlessHttpUpgrade) allocatedPorts.vlessHu = await allocatePorts();
  if (config.enable.vmessHttpUpgrade) allocatedPorts.vmessHu = await allocatePorts();
  if (config.enable.trojanHttpUpgrade) allocatedPorts.trojanHu = await allocatePorts();
  if (config.enable.trojanWs) allocatedPorts.trojanWs = await allocatePorts();
  if (config.enable.vlessGrpc || config.enable.vlessGrpcTls) allocatedPorts.vlessGrpc = await allocatePorts();
  if (config.enable.vlessGrpcTls) allocatedPorts.vlessGrpcTls = await allocatePorts();
  if (config.enable.ssWs) allocatedPorts.ssWs = await allocatePorts();
  if (config.enable.vlessXhttp) allocatedPorts.xray = await allocatePorts();

  // 6. Binaries
  Logger.section('Engines & Binaries');
  const binManager = new BinaryManager(config);
  const hasSingBox = await binManager.ensureSingBox();
  let hasXray = false;
  if (config.enable.vlessXhttp || config.enable.ssWs) {
    hasXray = await binManager.ensureXray();
  }

  // 7. Start engines
  let singboxInstance = null;
  if (hasSingBox) {
    singboxInstance = new SingBoxEngine(config, stateMgr, allocatedPorts);
    singboxInstance.start();
  } else {
    Logger.warn('sing-box binary could not be started. (offline mode active)');
  }

  let xrayInstance = null;
  config.xhttpPort = null;
  config.ssWsPort = null;
  if (hasXray && (allocatedPorts.xray || allocatedPorts.ssWs)) {
    xrayInstance = new XrayEngine(config, stateMgr, { xhttp: allocatedPorts.xray, ssWs: allocatedPorts.ssWs });
    if (xrayInstance.start()) {
      config.xhttpPort = allocatedPorts.xray || null;
      config.ssWsPort = allocatedPorts.ssWs || null;
    } else {
      Logger.warn('Xray-core did not start; VLESS-XHTTP / Shadowsocks-WS links hidden.');
    }
  } else if (config.enable.vlessXhttp || config.enable.ssWs) {
    Logger.warn('VLESS-XHTTP / Shadowsocks-WS enabled but Xray-core is not available; their links are hidden.');
  }

  // 8. Generate share links & subscriptions
  const linkGen = new LinkGenerator(config, stateMgr.state, resolvedHost);
  const compatNodes = linkGen.getAllNodes({ compat: 'v2ray' });
  const allNodes = linkGen.getAllNodes({ compat: 'full', allowLocalHostLinks: true });
  const links = compatNodes.map((n) => n.uri);
  const clashYaml = linkGen.buildClashMetaYaml(allNodes);
  const singboxJson = linkGen.buildSingBoxClientJson(allNodes);
  stateMgr.setLinks(links, clashYaml, singboxJson);

  // 9. HTTP panel & TCP multiplexer
  const engineStatusGetter = () => ({
    singbox: !!(singboxInstance && singboxInstance.process && !singboxInstance.process.killed),
    xray: !!(xrayInstance && xrayInstance.process && !xrayInstance.process.killed),
    https: !!(tcpRouter && tcpRouter.internalHttpsPort)
  });
  let tcpRouter = null;

  const { server: expressServer, app: expressApp } = createHttpPanel(config, stateMgr, engineStatusGetter, () => resolvedHost, settingsMgr);
  tcpRouter = new TcpRouter(config, allocatedPorts, expressServer, expressApp);
  await tcpRouter.start();

  // 10. Summary
  const panelUrl = `http://${resolvedHost}:${config.publicPort}/${config.panelPath}`;
  Logger.item('Link host / SNI', `${linkGen.host} / ${linkGen.tlsOpt.sni} (port ${linkGen.port}, fp=${linkGen.tlsOpt.fp})`);
  Logger.section('Aral Pars Active');
  Logger.item('Web Panel', panelUrl);
  Logger.item('Nodes', `${compatNodes.length} share links / ${allNodes.length} full nodes`);

  // Graceful shutdown
  const shutdown = () => {
    Logger.info('Stopping Aral Pars...');
    if (singboxInstance) singboxInstance.stop();
    if (xrayInstance) xrayInstance.stop();
    if (tcpRouter) tcpRouter.stop();
    try { Traffic.save(); } catch {}
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  return {
    config,
    state: stateMgr.state,
    nodes: compatNodes,
    allNodes,
    panelUrl,
    allocatedPorts,
    tcpRouter,
    singboxInstance,
    xrayInstance,
    shutdown
  };
}

// --- Auto-start execution ---
if (require.main === module) {
  startPanel().catch((err) => {
    console.error('[FATAL] Failed to start Aral Pars:', err);
    process.exit(1);
  });
}

module.exports = { startPanel, DEFAULT_CONFIG, buildConfig };
