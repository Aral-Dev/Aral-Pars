/**
 * Aral Pars — Xray-core engine.
 * Hosts VLESS-XHTTP and Shadowsocks-over-WebSocket (sing-box has no server transport
 * for Shadowsocks). Both listen on 127.0.0.1 only; the Node mux on PORT routes to them by path.
 */
'use strict';

const fs = require('fs');
const net = require('net');
const { spawn, spawnSync } = require('child_process');
const Logger = require('../logger');
const { PATHS } = require('../constants');

class XrayEngine {
  constructor(config, stateManager, ports) {
    this.config = config;
    this.paths = config.paths;
    this.stateManager = stateManager;
    this.ports = (ports && typeof ports === 'object') ? ports : { xhttp: ports };
    this.port = this.ports.xhttp || null;
    this.process = null;
  }

  static xhttpPath() { return PATHS.xhttp; }

  buildConfig() {
    const state = this.stateManager.state;
    const inbounds = [];
    if (this.ports.xhttp) {
      inbounds.push({
        tag: 'vless-xhttp-in',
        listen: '127.0.0.1',
        port: this.ports.xhttp,
        protocol: 'vless',
        settings: { clients: [{ id: state.uuid, level: 0 }], decryption: 'none' },
        streamSettings: {
          network: 'xhttp',
          security: 'none', // TLS (if any) is terminated in front of Xray
          xhttpSettings: { path: XrayEngine.xhttpPath(), mode: 'auto' }
        }
      });
    }
    if (this.ports.ssWs) {
      inbounds.push({
        tag: 'ss-ws-in',
        listen: '127.0.0.1',
        port: this.ports.ssWs,
        protocol: 'shadowsocks',
        settings: { method: this.config.shadowsocks.method || 'aes-256-gcm', password: state.shadowsocksPassword },
        streamSettings: { network: 'ws', security: 'none', wsSettings: { path: PATHS.ssWs } }
      });
    }
    return {
      log: { loglevel: 'warning' },
      inbounds,
      outbounds: [
        { protocol: 'freedom', tag: 'direct' },
        { protocol: 'blackhole', tag: 'block' }
      ]
    };
  }

  start() {
    if (!fs.existsSync(this.paths.xrayBin)) return false;
    if (!this.ports.xhttp && !this.ports.ssWs) return false;
    fs.writeFileSync(this.paths.xrayConfig, JSON.stringify(this.buildConfig(), null, 2), 'utf8');
    try {
      const t = spawnSync(this.paths.xrayBin, ['run', '-test', '-c', this.paths.xrayConfig], { encoding: 'utf8', timeout: 15000 });
      if (t.status !== 0) {
        Logger.error('Xray config test failed: ' + String(t.stdout || t.stderr || '').replace(/\x1b\[[0-9;]*m/g, '').trim());
        return false;
      }
    } catch (err) {
      Logger.warn('Xray config test could not run: ' + err.message);
    }
    this._spawn();
    this._probe();
    return true;
  }

  _spawn() {
    try {
      if (fs.existsSync(this.paths.xrayLog) && fs.statSync(this.paths.xrayLog).size > 5 * 1024 * 1024) {
        fs.truncateSync(this.paths.xrayLog, 0);
      }
    } catch {}
    const logFd = fs.openSync(this.paths.xrayLog, 'a');
    this.process = spawn(this.paths.xrayBin, ['run', '-c', this.paths.xrayConfig], { stdio: ['ignore', 'pipe', 'pipe'] });
    Logger.info(`Xray-core started (pid ${this.process.pid})${this.ports.xhttp ? ', VLESS-XHTTP on 127.0.0.1:' + this.ports.xhttp : ''}${this.ports.ssWs ? ', Shadowsocks-WS on 127.0.0.1:' + this.ports.ssWs : ''}`);

    let windowStart = Date.now();
    let printed = 0;
    const onData = (buf) => {
      try { fs.writeSync(logFd, buf); } catch {}
      const text = buf.toString('utf8').replace(/\x1b\[[0-9;]*m/g, '');
      for (const line of text.split('\n')) {
        if (!/\[(Warning|Error)\]|panic|failed to/i.test(line)) continue;
        if (/is deprecated|Please migrate/i.test(line)) continue;
        if (Date.now() - windowStart > 60000) { windowStart = Date.now(); printed = 0; }
        if (++printed <= 15) console.log('[xray] ' + line.trim().slice(0, 300));
      }
    };
    this.process.stdout.on('data', onData);
    this.process.stderr.on('data', onData);
    this.process.on('error', (err) => Logger.error(`Xray process error: ${err.message}`));
    this.process.on('exit', (code, sig) => {
      try { fs.closeSync(logFd); } catch {}
      if (this._stopping) return;
      Logger.warn(`Xray-core exited with code ${code} (${sig || 'none'})`);
      this._restarts = (this._restarts || 0) + 1;
      if (this._restarts <= 20) {
        const delay = Math.min(30000, 1000 * this._restarts);
        Logger.warn(`Restarting Xray-core in ${delay / 1000}s (attempt ${this._restarts})...`);
        setTimeout(() => { if (!this._stopping) this._spawn(); }, delay);
      } else {
        Logger.error('Xray-core keeps crashing; giving up. See xray.log in the data directory.');
      }
    });
  }

  _probe() {
    setTimeout(() => {
      for (const [tag, port] of [['vless-xhttp-in', this.ports.xhttp], ['ss-ws-in', this.ports.ssWs]]) {
        if (!port) continue;
        const sock = net.connect(port, '127.0.0.1');
        sock.setTimeout(3000);
        sock.once('connect', () => { Logger.success(`xray inbound ${tag} listening on 127.0.0.1:${port}`); sock.destroy(); });
        sock.once('error', (e) => Logger.error(`xray inbound ${tag} NOT listening on :${port} (${e.message})`));
        sock.once('timeout', () => { Logger.error(`xray inbound ${tag} probe timeout on :${port}`); sock.destroy(); });
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

module.exports = XrayEngine;
