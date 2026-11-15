/**
 * Aral Pars — sing-box engine.
 * Hosts VLESS-WS, VMess-WS, Trojan-WS (+ their TLS forms are terminated by the
 * gate's internal HTTPS server), HTTPUpgrade and gRPC inbounds.
 * All inbounds listen on 127.0.0.1 only; the Node mux on the public PORT routes to them.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const net = require('net');
const { spawn, spawnSync } = require('child_process');
const Logger = require('../logger');
const { PATHS } = require('../constants');
const { ensureTlsCertificates } = require('../cert');

class SingBoxEngine {
  constructor(config, stateManager, allocatedPorts) {
    this.config = config;
    this.paths = config.paths;
    this.stateManager = stateManager;
    this.ports = allocatedPorts;
    this.process = null;
  }

  buildJsonConfig() {
    const state = this.stateManager.state;
    const enable = this.config.enable;
    const wsPath = PATHS.vlessWs;
    const vmessPath = PATHS.vmessWs;
    const huPath = PATHS.vlessHu;

    const inbounds = [];

    // 1. VMess + WebSocket (also the backend for VMess-WS-TLS after gate TLS termination)
    if ((enable.vmessWs || enable.vmessWsTls) && this.ports.vmessWs) {
      inbounds.push({
        type: 'vmess',
        tag: 'vmess-ws-in',
        listen: '127.0.0.1',
        listen_port: this.ports.vmessWs,
        users: [{ uuid: state.uuid, alterId: 0 }],
        transport: {
          type: 'ws',
          path: vmessPath,
          max_early_data: 2560,
          early_data_header_name: 'Sec-WebSocket-Protocol'
        }
      });
    }

    // 2. VLESS + WebSocket (also the backend for VLESS-WS-TLS)
    if (enable.vlessWs && this.ports.vlessWs) {
      inbounds.push({
        type: 'vless',
        tag: 'vless-ws-in',
        listen: '127.0.0.1',
        listen_port: this.ports.vlessWs,
        users: [{ uuid: state.uuid, flow: '' }],
        tls: { enabled: false },
        transport: {
          type: 'ws',
          path: wsPath,
          max_early_data: 2560,
          early_data_header_name: 'Sec-WebSocket-Protocol'
        }
      });
    }

    // 3. VLESS + HTTPUpgrade (TCP)
    if (enable.vlessHttpUpgrade && this.ports.vlessHu) {
      inbounds.push({
        type: 'vless',
        tag: 'vless-hu-in',
        listen: '127.0.0.1',
        listen_port: this.ports.vlessHu,
        users: [{ uuid: state.uuid, flow: '' }],
        tls: { enabled: false },
        transport: { type: 'httpupgrade', path: huPath }
      });
    }

    // 3b. VMess + HTTPUpgrade
    if (enable.vmessHttpUpgrade && this.ports.vmessHu) {
      inbounds.push({
        type: 'vmess',
        tag: 'vmess-hu-in',
        listen: '127.0.0.1',
        listen_port: this.ports.vmessHu,
        users: [{ uuid: state.uuid, alterId: 0 }],
        transport: { type: 'httpupgrade', path: PATHS.vmessHu }
      });
    }

    // 3c. Trojan + HTTPUpgrade
    if (enable.trojanHttpUpgrade && this.ports.trojanHu) {
      inbounds.push({
        type: 'trojan',
        tag: 'trojan-hu-in',
        listen: '127.0.0.1',
        listen_port: this.ports.trojanHu,
        users: [{ password: state.uuid }],
        transport: { type: 'httpupgrade', path: PATHS.trojanHu }
      });
    }

    // 4. Trojan + WebSocket (also the backend for Trojan-WS-TLS)
    if (enable.trojanWs && this.ports.trojanWs) {
      inbounds.push({
        type: 'trojan',
        tag: 'trojan-ws-in',
        listen: '127.0.0.1',
        listen_port: this.ports.trojanWs,
        users: [{ password: state.uuid }],
        transport: { type: 'ws', path: PATHS.trojanWs }
      });
    }

    // 5. VLESS + gRPC (h2c backend; also the backend for gRPC-TLS decrypted by the gate's h2 router)
    if ((enable.vlessGrpc || enable.vlessGrpcTls) && this.ports.vlessGrpc) {
      inbounds.push({
        type: 'vless',
        tag: 'vless-grpc-in',
        listen: '127.0.0.1',
        listen_port: this.ports.vlessGrpc,
        users: [{ uuid: state.uuid, flow: '' }],
        tls: { enabled: false },
        transport: { type: 'grpc', service_name: PATHS.grpcService }
      });
    }

    // 5b. VLESS + gRPC + TLS (the mux sends TLS ClientHellos offering only ALPN h2 here)
    if (enable.vlessGrpcTls && this.ports.vlessGrpcTls) {
      ensureTlsCertificates(this.paths.certPath, this.paths.keyPath, this.config.domain || 'www.google.com');
      inbounds.push({
        type: 'vless',
        tag: 'vless-grpc-tls-in',
        listen: '127.0.0.1',
        listen_port: this.ports.vlessGrpcTls,
        users: [{ uuid: state.uuid, flow: '' }],
        tls: {
          enabled: true,
          server_name: this.config.domain || 'www.google.com',
          alpn: ['h2'],
          certificate_path: this.paths.certPath,
          key_path: this.paths.keyPath
        },
        transport: { type: 'grpc', service_name: PATHS.grpcService }
      });
    }

    return {
      log: { level: 'info', timestamp: true },
      inbounds,
      outbounds: [
        { type: 'direct', tag: 'direct' },
        { type: 'block', tag: 'block' }
      ],
      route: { final: 'direct' }
    };
  }

  testConfigSync(cfgObj) {
    const tmpFile = path.join(this.paths.dataDir, `test-check-${Date.now()}.json`);
    try {
      fs.writeFileSync(tmpFile, JSON.stringify(cfgObj, null, 2), 'utf8');
      const res = spawnSync(this.paths.singboxBin, ['check', '-c', tmpFile], { encoding: 'utf8', timeout: 8000 });
      try { fs.unlinkSync(tmpFile); } catch {}
      return { ok: res.status === 0, error: (res.stderr || res.stdout || '').trim() };
    } catch (err) {
      try { fs.unlinkSync(tmpFile); } catch {}
      return { ok: false, error: err.message };
    }
  }

  /** Validate with resilience: strip optional inbounds until sing-box accepts the config. */
  validateAndSanitize(configData) {
    let check = this.testConfigSync(configData);
    if (check.ok) return configData;

    Logger.warn(`sing-box initial check reported: ${check.error}. Running resilience auto-fix...`);
    const optionalTags = ['vless-grpc-tls-in', 'vless-grpc-in', 'trojan-ws-in', 'trojan-hu-in', 'vmess-hu-in'];
    for (const tag of optionalTags) {
      const idx = configData.inbounds.findIndex((ib) => ib.tag === tag);
      if (idx !== -1) {
        configData.inbounds.splice(idx, 1);
        check = this.testConfigSync(configData);
        if (check.ok) {
          Logger.warn(`sing-box validated after stripping ${tag}. Continuing with stable inbounds.`);
          return configData;
        }
      }
    }

    const coreTags = ['vless-ws-in', 'vmess-ws-in', 'vless-hu-in'];
    configData.inbounds = configData.inbounds.filter((ib) => coreTags.includes(ib.tag));
    check = this.testConfigSync(configData);
    if (check.ok) {
      Logger.warn('sing-box validated with minimum core inbounds (VLESS-WS, VMess-WS, VLESS-HTTPUpgrade).');
      return configData;
    }
    return null;
  }

  start() {
    if (!fs.existsSync(this.paths.singboxBin)) {
      Logger.warn('sing-box executable missing. Core engine skipped.');
      return false;
    }

    let configData = this.buildJsonConfig();
    configData = this.validateAndSanitize(configData);
    if (!configData) {
      Logger.error('sing-box validation failed completely even after auto-fix attempts.');
      return false;
    }

    fs.writeFileSync(this.paths.singboxConfig, JSON.stringify(configData, null, 2), 'utf8');
    Logger.success('sing-box configuration validated.');
    this._spawn();
    this._probeInbounds(configData);
    return true;
  }

  _spawn() {
    try {
      if (fs.existsSync(this.paths.singboxLog) && fs.statSync(this.paths.singboxLog).size > 5 * 1024 * 1024) {
        fs.truncateSync(this.paths.singboxLog, 0);
      }
    } catch {}
    const logFd = fs.openSync(this.paths.singboxLog, 'a');
    this.process = spawn(this.paths.singboxBin, ['run', '-c', this.paths.singboxConfig], {
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: false
    });
    Logger.info(`sing-box started (pid ${this.process.pid})`);

    let windowStart = Date.now();
    let printed = 0;
    const onData = (buf) => {
      try { fs.writeSync(logFd, buf); } catch {}
      const text = buf.toString('utf8').replace(/\x1b\[[0-9;]*m/g, '');
      for (const line of text.split('\n')) {
        if (!/FATAL|ERROR|WARN|panic/i.test(line)) continue;
        if (Date.now() - windowStart > 60000) { windowStart = Date.now(); printed = 0; }
        if (++printed <= 15) console.log('[sing-box] ' + line.trim().slice(0, 300));
      }
    };
    this.process.stdout.on('data', onData);
    this.process.stderr.on('data', onData);
    this.process.on('error', (err) => Logger.error(`sing-box process error: ${err.message}`));
    this.process.on('exit', (code, sig) => {
      try { fs.closeSync(logFd); } catch {}
      if (this._stopping) return;
      Logger.warn(`sing-box exited with code ${code} (${sig || 'none'})`);
      this._restarts = (this._restarts || 0) + 1;
      if (this._restarts <= 20) {
        const delay = Math.min(30000, 1000 * this._restarts);
        Logger.warn(`Restarting sing-box in ${delay / 1000}s (attempt ${this._restarts})...`);
        setTimeout(() => { if (!this._stopping) this._spawn(); }, delay);
      } else {
        Logger.error('sing-box keeps crashing; giving up. Check sing-box.log in the data directory.');
      }
    });
  }

  _probeInbounds(configData) {
    const list = (configData.inbounds || []).filter((ib) => ib.listen_port && ib.listen === '127.0.0.1');
    setTimeout(() => {
      for (const ib of list) {
        const sock = net.connect(ib.listen_port, '127.0.0.1');
        sock.setTimeout(3000);
        sock.once('connect', () => { Logger.success(`sing-box inbound ${ib.tag} listening on 127.0.0.1:${ib.listen_port}`); sock.destroy(); });
        sock.once('error', (e) => Logger.error(`sing-box inbound ${ib.tag} NOT listening on :${ib.listen_port} (${e.message})`));
        sock.once('timeout', () => { Logger.error(`sing-box inbound ${ib.tag} probe timeout on :${ib.listen_port}`); sock.destroy(); });
      }
    }, 2500);
  }

  stop() {
    this._stopping = true;
    if (this.process && !this.process.killed) {
      try { this.process.kill('SIGTERM'); } catch {}
    }
  }
}

module.exports = SingBoxEngine;
