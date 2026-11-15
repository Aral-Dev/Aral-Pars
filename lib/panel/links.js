/**
 * Aral Pars — share link & subscription generator.
 * Produces, for every enabled protocol: the URI (v2ray clients), the Clash Meta
 * (mihomo) proxy entry and the sing-box outbound JSON.
 */
'use strict';

const crypto = require('crypto');
const { PATHS, BRAND, normalizeHost, isLocalAddress } = require('../constants');
const { certSha256 } = require('../cert');

function urlSafeEncode(str) { return encodeURIComponent(str); }
function yamlSafeQuote(str) { return `"${String(str).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`; }

/** Validate a node share URI (v2rayN / v2rayNG / Hiddify / sing-box compatibility filter). */
function isValidNode(node, options = {}) {
  if (!node || !node.uri || typeof node.uri !== 'string') return false;
  const { allowLocalHostLinks = false, compatMode = 'v2ray' } = options;
  const uri = node.uri.trim();

  try {
    const scheme = uri.split('://')[0].toLowerCase();

    // vmess:// (base64 JSON)
    if (scheme === 'vmess') {
      try {
        const rawJson = Buffer.from(uri.replace(/^vmess:\/\//i, ''), 'base64').toString('utf8');
        const vConf = JSON.parse(rawJson);
        if (!vConf.add || !vConf.port || !vConf.id) return false;
        if (!allowLocalHostLinks && isLocalAddress(vConf.add)) return false;
        return true;
      } catch { return false; }
    }

    const parsed = new URL(uri);
    if (!allowLocalHostLinks && isLocalAddress(parsed.hostname)) return false;

    if (compatMode === 'v2ray') {
      const allowedSchemes = ['vless', 'vmess', 'trojan', 'ss'];
      if (!allowedSchemes.includes(scheme)) return false;
    }

    if (scheme === 'vless') {
      const uuid = parsed.username;
      if (!uuid || uuid.length < 8) return false;
      const type = parsed.searchParams.get('type');
      if (type === 'ws') {
        const pathVal = parsed.searchParams.get('path');
        if (!pathVal) return false;
      }
      if (type === 'grpc') {
        const serviceName = parsed.searchParams.get('serviceName');
        if (!serviceName) return false;
      }
    }

    if (scheme === 'trojan') {
      if (!parsed.username) return false;
    }

    if (scheme === 'ss') {
      if (!parsed.username && !parsed.hostname) return false;
    }

    return true;
  } catch {
    return false;
  }
}

class LinkGenerator {
  constructor(config, state, resolvedHost) {
    this.config = config;
    this.state = state;
    this.host = config.forceHost || resolvedHost || config.domain || '127.0.0.1';
    this.port = parseInt(process.env.LINK_PORT || '', 10) || config.publicPort;
    // Self-signed certificate -> links carry allowInsecure=1 for old clients and pcs=<sha256> pin for Xray 26.2+.
    this.insecure = true;
    this.tlsOpt = LinkGenerator.tlsOptions((config.forceHost && config.domain) ? config.domain : this.host);
    this.wsPath = PATHS.vlessWs;
    this.vmessPath = PATHS.vmessWs;
    this.huPath = PATHS.vlessHu;
    this.vmHuPath = PATHS.vmessHu;
    this.trHuPath = PATHS.trojanHu;
    this.xhPath = PATHS.xhttp;
    this.trPath = PATHS.trojanWs;
    this.ssWsPath = PATHS.ssWs;
    this.grpcService = PATHS.grpcService;
    this.pcs = (config.paths && config.paths.certPath) ? certSha256(config.paths.certPath) : '';
    this.keepAllowInsecure = this.insecure && !/^(0|false|no|off)$/i.test(String(process.env.LINK_ALLOW_INSECURE || 'true'));
    this.name = (t) => `${BRAND.short} • ${t}`;
  }

  /** Readable host for Host headers: the TLS/WS host override if set, else the link host. */
  get plainHost() { return normalizeHost(process.env.LINK_HOST) || this.host; }

  /**
   * TLS client options for share links / subscriptions (env driven):
   *   LINK_FP   uTLS fingerprint (default chrome)  |  LINK_ALPN  comma list (default http/1.1)
   *   LINK_SNI  override SNI  |  LINK_HOST  override WS/HTTPUpgrade Host header
   */
  static tlsOptions(defaultSni) {
    const env = process.env;
    const FP = ['chrome', 'firefox', 'safari', 'edge', 'ios', 'android', 'random', 'randomized', '360', 'qq', 'wechat_os', 'wechat_android', 'wechat_mac'];
    let fp = env.LINK_FP === undefined ? 'chrome' : String(env.LINK_FP).trim().toLowerCase();
    if (fp === 'none' || fp === 'off' || fp === 'false') fp = '';
    if (fp && !FP.includes(fp)) fp = 'chrome';
    const alpnRaw = env.LINK_ALPN === undefined ? 'http/1.1' : String(env.LINK_ALPN).trim();
    const alpn = /^(none|off|false)?$/i.test(alpnRaw) ? [] : alpnRaw.split(',').map((x) => x.trim()).filter(Boolean);
    const sni = normalizeHost(env.LINK_SNI) || defaultSni;
    const wsHost = normalizeHost(env.LINK_HOST) || sni;
    return { fp, alpn, sni, wsHost };
  }

  /** "&sni=..&fp=..&alpn=.." for vless:// and trojan:// links. */
  _uriTls() {
    const o = this.tlsOpt;
    let q = '&sni=' + encodeURIComponent(o.sni);
    if (o.fp) q += '&fp=' + encodeURIComponent(o.fp);
    if (o.alpn.length) q += '&alpn=' + encodeURIComponent(o.alpn.join(','));
    q += this._uriInsecure();
    return q;
  }

  /** "&allowInsecure=1&pcs=<sha256>" for the self-signed certificate. */
  _uriInsecure() {
    let q = '';
    if (this.keepAllowInsecure) q += '&allowInsecure=1';
    if (this.pcs) q += '&pcs=' + this.pcs;
    return q;
  }

  _sbTls(alpnOverride) {
    const o = this.tlsOpt;
    const t = { enabled: true, server_name: o.sni, insecure: this.insecure };
    t.alpn = alpnOverride || (o.alpn.length ? o.alpn.slice() : ['http/1.1']);
    if (o.fp) t.utls = { enabled: true, fingerprint: o.fp };
    return t;
  }

  _clashTls(obj, sniKey = 'servername', alpnOverride) {
    const o = this.tlsOpt;
    obj.tls = true;
    obj[sniKey] = o.sni;
    obj['skip-cert-verify'] = this.insecure;
    if (this.pcs) obj.fingerprint = this.pcs; // mihomo: pin the self-signed certificate
    if (o.fp) obj['client-fingerprint'] = o.fp === 'randomized' ? 'random' : o.fp;
    obj.alpn = alpnOverride || (o.alpn.length ? o.alpn.slice() : ['http/1.1']);
    return obj;
  }

  // ===== VLESS-WS / VLESS-WS-TLS (one sing-box inbound; TLS is terminated by the gate) =====
  generateVlessWsTls() {
    if (!this.config.enable.vlessWsTls || !this.config.enable.vlessWs) return null;
    const name = this.name('VLESS-WS-TLS');
    const o = this.tlsOpt;
    const clashProxy = this._clashTls({
      name, type: 'vless', server: this.host, port: this.port, uuid: this.state.uuid, network: 'ws',
      'ws-opts': { path: this.wsPath, headers: { Host: o.wsHost } }
    });
    const sbOutbound = {
      type: 'vless', tag: name, server: this.host, server_port: this.port, uuid: this.state.uuid,
      tls: this._sbTls(),
      transport: { type: 'ws', path: this.wsPath, headers: { Host: o.wsHost } }
    };
    return {
      name, type: 'VLESS-WS-TLS', label: 'WebSocket + TLS', compat: true,
      uri: `vless://${this.state.uuid}@${this.host}:${this.port}?encryption=none&security=tls${this._uriTls()}&type=ws&host=${encodeURIComponent(o.wsHost)}&path=${urlSafeEncode(this.wsPath)}#${urlSafeEncode(name)}`,
      clash: clashProxy,
      singboxOutbound: [sbOutbound]
    };
  }

  generateVlessWs() {
    if (!this.config.enable.vlessWs) return null;
    const name = this.name('VLESS-WS');
    const clashProxy = {
      name, type: 'vless', server: this.host, port: this.port, uuid: this.state.uuid,
      network: 'ws', tls: false,
      'ws-opts': { path: this.wsPath, headers: { Host: this.host } }
    };
    const sbOutbound = {
      type: 'vless', tag: name, server: this.host, server_port: this.port, uuid: this.state.uuid,
      transport: { type: 'ws', path: this.wsPath, headers: { Host: this.host } }
    };
    return {
      name, type: 'VLESS-WS', label: 'WebSocket Direct', compat: true,
      uri: `vless://${this.state.uuid}@${this.host}:${this.port}?encryption=none&security=none&type=ws&host=${encodeURIComponent(this.host)}&path=${urlSafeEncode(this.wsPath)}#${urlSafeEncode(name)}`,
      clash: clashProxy,
      singboxOutbound: [sbOutbound]
    };
  }

  // ===== VMess-WS / VMess-WS-TLS =====
  generateVmessWsTls() {
    if (!this.config.enable.vmessWsTls || !this.config.enable.vmessWs) return null;
    const name = this.name('VMess-WS-TLS');
    const o = this.tlsOpt;
    const vmessConfig = {
      v: '2', ps: name, add: this.host, port: String(this.port), id: this.state.uuid, aid: '0', scy: 'auto',
      net: 'ws', type: 'none', host: o.wsHost, path: this.vmessPath, tls: 'tls', sni: o.sni
    };
    if (o.alpn.length) vmessConfig.alpn = o.alpn.join(',');
    if (o.fp) vmessConfig.fp = o.fp;
    if (this.keepAllowInsecure) vmessConfig.allowInsecure = true;
    if (this.pcs) vmessConfig.pcs = this.pcs;
    const uri = 'vmess://' + Buffer.from(JSON.stringify(vmessConfig)).toString('base64');
    const clashProxy = this._clashTls({
      name, type: 'vmess', server: this.host, port: this.port, uuid: this.state.uuid, alterId: 0, cipher: 'auto', network: 'ws',
      'ws-opts': { path: this.vmessPath, headers: { Host: o.wsHost } }
    });
    const sbOutbound = {
      type: 'vmess', tag: name, server: this.host, server_port: this.port, uuid: this.state.uuid, alter_id: 0, security: 'auto',
      tls: this._sbTls(),
      transport: { type: 'ws', path: this.vmessPath, headers: { Host: o.wsHost } }
    };
    return { name, type: 'VMess-WS-TLS', label: 'VMess WebSocket TLS', compat: true, uri, clash: clashProxy, singboxOutbound: [sbOutbound] };
  }

  generateVmessWs() {
    if (!this.config.enable.vmessWs) return null;
    const name = this.name('VMess-WS');
    const vmessConfig = {
      v: '2', ps: name, add: this.host, port: String(this.port), id: this.state.uuid, aid: '0', scy: 'auto',
      net: 'ws', type: 'none', host: this.host, path: this.vmessPath, tls: 'none'
    };
    const uri = 'vmess://' + Buffer.from(JSON.stringify(vmessConfig)).toString('base64');
    const clashProxy = {
      name, type: 'vmess', server: this.host, port: this.port, uuid: this.state.uuid, alterId: 0, cipher: 'auto',
      network: 'ws', tls: false,
      'ws-opts': { path: this.vmessPath, headers: { Host: this.host } }
    };
    const sbOutbound = {
      type: 'vmess', tag: name, server: this.host, server_port: this.port, uuid: this.state.uuid, alter_id: 0, security: 'auto',
      transport: { type: 'ws', path: this.vmessPath, headers: { Host: this.host } }
    };
    return { name, type: 'VMess-WS', label: 'VMess WebSocket Direct', compat: true, uri, clash: clashProxy, singboxOutbound: [sbOutbound] };
  }

  // ===== Trojan-WS / Trojan-WS-TLS =====
  generateTrojanWsTls() {
    if (!this.config.enable.trojanWsTls || !this.config.enable.trojanWs) return null;
    const name = this.name('Trojan-WS-TLS');
    const o = this.tlsOpt;
    const sbOutbound = {
      type: 'trojan', tag: name, server: this.host, server_port: this.port, password: this.state.uuid,
      tls: this._sbTls(),
      transport: { type: 'ws', path: this.trPath, headers: { Host: o.wsHost } }
    };
    return {
      name, type: 'Trojan-WS-TLS', label: 'Trojan WebSocket TLS', compat: true,
      uri: `trojan://${this.state.uuid}@${this.host}:${this.port}?security=tls${this._uriTls()}&type=ws&host=${encodeURIComponent(o.wsHost)}&path=${urlSafeEncode(this.trPath)}#${urlSafeEncode(name)}`,
      clash: this._clashTls({
        name, type: 'trojan', server: this.host, port: this.port, password: this.state.uuid, network: 'ws',
        'ws-opts': { path: this.trPath, headers: { Host: o.wsHost } }
      }, 'sni'),
      singboxOutbound: [sbOutbound]
    };
  }

  generateTrojanWs() {
    if (!this.config.enable.trojanWs) return null;
    const name = this.name('Trojan-WS');
    const clashProxy = {
      name, type: 'trojan', server: this.host, port: this.port, password: this.state.uuid,
      network: 'ws', tls: false,
      'ws-opts': { path: this.trPath, headers: { Host: this.host } }
    };
    const sbOutbound = {
      type: 'trojan', tag: name, server: this.host, server_port: this.port, password: this.state.uuid,
      transport: { type: 'ws', path: this.trPath, headers: { Host: this.host } }
    };
    return {
      name, type: 'Trojan-WS', label: 'Trojan WebSocket Direct', compat: true,
      uri: `trojan://${this.state.uuid}@${this.host}:${this.port}?security=none&type=ws&host=${encodeURIComponent(this.host)}&path=${urlSafeEncode(this.trPath)}#${urlSafeEncode(name)}`,
      clash: clashProxy, // mihomo tolerates plain Trojan-WS entries even though it prefers TLS
      singboxOutbound: [sbOutbound]
    };
  }

  // ===== HTTPUpgrade for VLESS / VMess / Trojan (one generic builder) =====
  _httpUpgradeNode(proto, enabled, pathVal, type) {
    if (!enabled) return null;
    const o = this.tlsOpt;
    const hostHdr = this.plainHost;
    const name = this.name(type);
    const u = this.state.uuid;
    const base = { server: this.host, port: this.port };
    let uri; let clash; let sb;
    const clashWs = { network: 'ws', 'ws-opts': { path: pathVal, headers: { Host: hostHdr }, 'v2ray-http-upgrade': true } };
    const sbTransport = { type: 'httpupgrade', path: pathVal, host: hostHdr };
    if (proto === 'vless') {
      uri = `vless://${u}@${this.host}:${this.port}?encryption=none&security=none&type=httpupgrade&host=${encodeURIComponent(hostHdr)}&path=${urlSafeEncode(pathVal)}#${urlSafeEncode(name)}`;
      clash = { name, type: 'vless', ...base, uuid: u, ...clashWs };
      sb = { type: 'vless', tag: name, server: this.host, server_port: this.port, uuid: u, transport: sbTransport };
    } else if (proto === 'vmess') {
      const v = { v: '2', ps: name, add: this.host, port: String(this.port), id: u, aid: '0', scy: 'auto', net: 'httpupgrade', type: 'none', host: hostHdr, path: pathVal, tls: '' };
      uri = 'vmess://' + Buffer.from(JSON.stringify(v)).toString('base64');
      clash = { name, type: 'vmess', ...base, uuid: u, alterId: 0, cipher: 'auto', ...clashWs };
      sb = { type: 'vmess', tag: name, server: this.host, server_port: this.port, uuid: u, alter_id: 0, security: 'auto', transport: sbTransport };
    } else {
      uri = `trojan://${u}@${this.host}:${this.port}?security=none&type=httpupgrade&host=${encodeURIComponent(hostHdr)}&path=${urlSafeEncode(pathVal)}#${urlSafeEncode(name)}`;
      clash = { name, type: 'trojan', ...base, password: u, ...clashWs };
      sb = { type: 'trojan', tag: name, server: this.host, server_port: this.port, password: u, transport: sbTransport };
    }
    clash.tls = false;
    if (proto === 'trojan' && !clash) clash = null;
    return { name, type, label: type.replace('-', ' '), compat: true, uri, clash, singboxOutbound: [sb] };
  }

  generateVlessHttpUpgrade() { return this._httpUpgradeNode('vless', this.config.enable.vlessHttpUpgrade, this.huPath, 'VLESS-HTTPUpgrade'); }
  generateVmessHttpUpgrade() { return this._httpUpgradeNode('vmess', this.config.enable.vmessHttpUpgrade, this.vmHuPath, 'VMess-HTTPUpgrade'); }
  generateTrojanHttpUpgrade() { return this._httpUpgradeNode('trojan', this.config.enable.trojanHttpUpgrade, this.trHuPath, 'Trojan-HTTPUpgrade'); }

  // ===== VLESS-gRPC (h2c) / VLESS-gRPC-TLS (ALPN h2 only) =====
  generateVlessGrpc() {
    if (!this.config.enable.vlessGrpc) return null;
    const name = this.name('VLESS-gRPC');
    const serviceName = this.grpcService;
    const clashProxy = {
      name, type: 'vless', server: this.host, port: this.port, uuid: this.state.uuid,
      network: 'grpc', tls: false,
      'grpc-opts': { 'grpc-service-name': serviceName }
    };
    const sbOutbound = {
      type: 'vless', tag: name, server: this.host, server_port: this.port, uuid: this.state.uuid,
      transport: { type: 'grpc', service_name: serviceName }
    };
    return {
      name, type: 'VLESS-gRPC', label: 'gRPC Direct (h2c)', compat: true,
      uri: `vless://${this.state.uuid}@${this.host}:${this.port}?encryption=none&security=none&type=grpc&serviceName=${urlSafeEncode(serviceName)}&mode=gun#${urlSafeEncode(name)}`,
      clash: clashProxy, singboxOutbound: [sbOutbound]
    };
  }

  generateVlessGrpcTls() {
    if (!this.config.enable.vlessGrpcTls) return null;
    const name = this.name('VLESS-gRPC-TLS');
    const o = this.tlsOpt;
    const svc = this.grpcService;
    const q = '&sni=' + encodeURIComponent(o.sni) + (o.fp ? '&fp=' + encodeURIComponent(o.fp) : '') + '&alpn=h2' + this._uriInsecure();
    const sbTls = { enabled: true, server_name: o.sni, insecure: this.insecure, alpn: ['h2'] };
    if (o.fp) sbTls.utls = { enabled: true, fingerprint: o.fp };
    const sbOutbound = { type: 'vless', tag: name, server: this.host, server_port: this.port, uuid: this.state.uuid, tls: sbTls, transport: { type: 'grpc', service_name: svc } };
    const clash = { name, type: 'vless', server: this.host, port: this.port, uuid: this.state.uuid, network: 'grpc', tls: true, servername: o.sni, 'skip-cert-verify': this.insecure, alpn: ['h2'], 'grpc-opts': { 'grpc-service-name': svc } };
    if (this.pcs) clash.fingerprint = this.pcs;
    if (o.fp) clash['client-fingerprint'] = o.fp === 'randomized' ? 'random' : o.fp;
    return {
      name, type: 'VLESS-gRPC-TLS', label: 'gRPC TLS', compat: true,
      uri: `vless://${this.state.uuid}@${this.host}:${this.port}?encryption=none&security=tls${q}&type=grpc&serviceName=${urlSafeEncode(svc)}&mode=gun#${urlSafeEncode(name)}`,
      clash, singboxOutbound: [sbOutbound]
    };
  }

  // ===== Shadowsocks over WebSocket (SIP002 + v2ray-plugin "websocket" mode, mux off) — served by Xray-core =====
  generateShadowsocksWs() {
    if (!this.config.enable.ssWs || !this.config.ssWsPort || !this.state.shadowsocksPassword) return null;
    const name = this.name('Shadowsocks-WS');
    const method = this.config.shadowsocks.method || 'aes-256-gcm';
    const pass = this.state.shadowsocksPassword;
    const hostHdr = this.plainHost;
    const userinfo = /^2022-/i.test(method)
      ? encodeURIComponent(method) + ':' + encodeURIComponent(pass)
      : Buffer.from(`${method}:${pass}`).toString('base64url');
    const pluginOpts = `mode=websocket;host=${hostHdr};path=${this.ssWsPath};mux=0`;
    const sbOutbound = { type: 'shadowsocks', tag: name, server: this.host, server_port: this.port, method, password: pass, transport: { type: 'ws', path: this.ssWsPath } };
    return {
      name, type: 'Shadowsocks-WS', label: 'Shadowsocks + v2ray-plugin', compat: true,
      uri: `ss://${userinfo}@${this.host}:${this.port}/?plugin=${encodeURIComponent('v2ray-plugin;' + pluginOpts)}#${urlSafeEncode(name)}`,
      clash: { name, type: 'ss', server: this.host, port: this.port, cipher: method, password: pass, plugin: 'v2ray-plugin', 'plugin-opts': { mode: 'websocket', path: this.ssWsPath, host: hostHdr, tls: false } },
      singboxOutbound: [sbOutbound],
      note: 'Shadowsocks + v2ray-plugin (websocket, mux=0): v2rayN / v2rayNG / Hiddify / sing-box / Clash Meta'
    };
  }

  // ===== VLESS-XHTTP (Xray-core clients only) =====
  static xhttpOptions() {
    const MODES = ['auto', 'packet-up', 'stream-up', 'stream-one'];
    let mode = String(process.env.XHTTP_MODE || 'packet-up').trim().toLowerCase();
    if (!MODES.includes(mode)) mode = 'packet-up';
    return { mode };
  }

  generateXhttp() {
    if (!this.config.enable.vlessXhttp) return null;
    if (this.config.xhttpPort === null || this.config.xhttpPort === undefined) return null; // Xray-core failed to start
    const name = this.name('VLESS-XHTTP');
    const { mode } = LinkGenerator.xhttpOptions();
    return {
      name, type: 'VLESS-XHTTP', label: 'VLESS XHTTP',
      note: 'VLESS-XHTTP (Xray-core clients: v2rayN, v2rayNG, Hiddify w/ xray core)',
      compat: true,
      uri: `vless://${this.state.uuid}@${this.host}:${this.port}?encryption=none&security=none&type=xhttp&host=${encodeURIComponent(this.plainHost)}&path=${urlSafeEncode(this.xhPath)}&mode=${mode}#${urlSafeEncode(name)}`,
      clash: null
    };
  }

  getAllNodes(options = {}) {
    let compat = 'v2ray';
    let allowLocal = this.config.allowLocalHostLinks || false;
    if (options && typeof options === 'object') {
      if (options.compat) compat = options.compat;
      if (options.allowLocalHostLinks !== undefined) allowLocal = options.allowLocalHostLinks;
    }

    const all = [
      this.generateVlessWsTls(),
      this.generateVmessWsTls(),
      this.generateVlessWs(),
      this.generateVmessWs(),
      this.generateTrojanWs(),
      this.generateTrojanWsTls(),
      this.generateVlessHttpUpgrade(),
      this.generateVmessHttpUpgrade(),
      this.generateTrojanHttpUpgrade(),
      this.generateVlessGrpc(),
      this.generateVlessGrpcTls(),
      this.generateXhttp(),
      this.generateShadowsocksWs()
    ].filter(Boolean);

    return all.filter((node) => isValidNode(node, { allowLocalHostLinks: allowLocal, compatMode: compat }));
  }

  /** Clash Meta (mihomo) subscription YAML. */
  buildClashMetaYaml(nodes) {
    const proxyLines = [];
    const proxyNames = [];

    for (const node of nodes) {
      if (!node.clash) continue;
      proxyNames.push(node.clash.name);
      proxyLines.push(`  - name: ${yamlSafeQuote(node.clash.name)}`);
      proxyLines.push(`    type: ${node.clash.type}`);
      proxyLines.push(`    server: ${yamlSafeQuote(node.clash.server)}`);
      proxyLines.push(`    port: ${node.clash.port}`);
      if (node.clash.fingerprint) proxyLines.push(`    fingerprint: ${yamlSafeQuote(node.clash.fingerprint)}`);
      if (node.clash.plugin) {
        proxyLines.push(`    plugin: ${node.clash.plugin}`);
        const po = node.clash['plugin-opts'] || {};
        proxyLines.push(`    plugin-opts:`);
        for (const [k, v] of Object.entries(po)) proxyLines.push(`      ${k}: ${typeof v === 'string' ? yamlSafeQuote(v) : v}`);
      }
      if (node.clash.password) proxyLines.push(`    password: ${yamlSafeQuote(node.clash.password)}`);
      if (node.clash.uuid) proxyLines.push(`    uuid: ${yamlSafeQuote(node.clash.uuid)}`);
      if (node.clash.alterId !== undefined) proxyLines.push(`    alterId: ${node.clash.alterId}`);
      if (node.clash.sni) proxyLines.push(`    sni: ${yamlSafeQuote(node.clash.sni)}`);
      if (node.clash.servername) proxyLines.push(`    servername: ${yamlSafeQuote(node.clash.servername)}`);
      if (node.clash['skip-cert-verify'] !== undefined) proxyLines.push(`    skip-cert-verify: ${node.clash['skip-cert-verify']}`);
      if (node.clash.alpn) proxyLines.push(`    alpn: [${node.clash.alpn.map(yamlSafeQuote).join(', ')}]`);
      if (node.clash.network) proxyLines.push(`    network: ${node.clash.network}`);
      if (node.clash.tls !== undefined) proxyLines.push(`    tls: ${node.clash.tls}`);
      if (node.clash['client-fingerprint']) proxyLines.push(`    client-fingerprint: ${node.clash['client-fingerprint']}`);

      if (node.clash['ws-opts']) {
        proxyLines.push(`    ws-opts:`);
        proxyLines.push(`      path: ${yamlSafeQuote(node.clash['ws-opts'].path)}`);
        if (node.clash['ws-opts'].headers) {
          proxyLines.push(`      headers:`);
          for (const [k, v] of Object.entries(node.clash['ws-opts'].headers)) {
            proxyLines.push(`        ${k}: ${yamlSafeQuote(v)}`);
          }
        }
        if (node.clash['ws-opts']['v2ray-http-upgrade']) proxyLines.push(`      v2ray-http-upgrade: true`);
      }

      if (node.clash['grpc-opts']) {
        proxyLines.push(`    grpc-opts:`);
        proxyLines.push(`      grpc-service-name: ${yamlSafeQuote(node.clash['grpc-opts']['grpc-service-name'])}`);
      }

      if (node.clash.cipher) proxyLines.push(`    cipher: ${node.clash.cipher}`);
    }

    const proxiesBlock = proxyLines.join('\n');
    const proxyListStr = proxyNames.map((n) => `      - ${yamlSafeQuote(n)}`).join('\n');

    return `# Aral Pars - Clash Meta (Mihomo) Subscription
port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info

proxies:
${proxiesBlock}

proxy-groups:
  - name: "${BRAND.name}"
    type: select
    proxies:
      - "Auto Select"
${proxyListStr}

  - name: "Auto Select"
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
${proxyListStr}

rules:
  - MATCH,"${BRAND.name}"
`;
  }

  /** sing-box client JSON. */
  buildSingBoxClientJson(nodes) {
    const outbounds = [];
    const proxyTags = [];

    for (const node of nodes) {
      if (node.singboxOutbound && Array.isArray(node.singboxOutbound)) {
        for (const ob of node.singboxOutbound) outbounds.push(ob);
        proxyTags.push(node.name);
      }
    }

    const allOutbounds = [];
    if (proxyTags.length > 0) {
      allOutbounds.push(
        { type: 'selector', tag: BRAND.name, outbounds: ['Auto Select', ...proxyTags] },
        { type: 'urltest', tag: 'Auto Select', outbounds: [...proxyTags], url: 'http://www.gstatic.com/generate_204', interval: '5m' }
      );
    }
    allOutbounds.push(...outbounds);
    allOutbounds.push({ type: 'direct', tag: 'direct' });

    return JSON.stringify({ log: { level: 'info' }, outbounds: allOutbounds }, null, 2);
  }
}

module.exports = { LinkGenerator, isValidNode };
