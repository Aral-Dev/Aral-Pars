/** Aral Pars — persistent state (uuid, credentials, links) in aral-data/state.json. */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Logger = require('./logger');
const { UUID_RE, ss2022KeyLen } = require('./constants');

class StateManager {
  constructor(paths, config) {
    this.paths = paths;
    this.config = config;
    this.state = {
      uuid: '',
      shadowsocksPassword: '',
      ssKey2022: '',
      publicIp: '',
      links: [],
      clashYaml: '',
      singboxJson: '',
      base64Sub: '',
      updatedAt: null
    };
  }

  loadOrCreate() {
    try {
      fs.mkdirSync(this.paths.dataDir, { recursive: true });
      if (fs.existsSync(this.paths.stateFile)) {
        const parsed = JSON.parse(fs.readFileSync(this.paths.stateFile, 'utf8'));
        this.state = { ...this.state, ...parsed };
      }
    } catch (err) {
      Logger.warn(`Failed to read existing state.json: ${err.message}. Generating fresh state.`);
    }

    // UUID: env UUID -> persisted state -> generate
    if (this.config.uuid) {
      const raw = String(this.config.uuid).trim();
      if (UUID_RE.test(raw)) {
        this.state.uuid = raw.toLowerCase();
      } else {
        // sing-box rejects non-UUID ids: derive a stable UUID from any string
        const h = crypto.createHash('sha256').update(raw).digest();
        h[6] = (h[6] & 0x0f) | 0x40;
        h[8] = (h[8] & 0x3f) | 0x80;
        const x = h.subarray(0, 16).toString('hex');
        this.state.uuid = `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20, 32)}`;
        Logger.warn('UUID env value is not a valid UUID; using a derived one.');
      }
    } else if (!this.state.uuid || !UUID_RE.test(this.state.uuid)) {
      this.state.uuid = crypto.randomUUID();
    }

    // Shadowsocks password (env -> persisted -> generate)
    if (this.config.shadowsocks.password) {
      this.state.shadowsocksPassword = this.config.shadowsocks.password;
    } else if (!this.state.shadowsocksPassword) {
      this.state.shadowsocksPassword = crypto.randomBytes(16).toString('base64url');
    }
    // 2022 ciphers need a base64 key of exactly 16/32 bytes
    const ssKeyLen = ss2022KeyLen(this.config.shadowsocks.method || '');
    if (ssKeyLen) {
      let ok = false;
      try { ok = /^[A-Za-z0-9+/]+={0,2}$/.test(this.state.shadowsocksPassword) && Buffer.from(this.state.shadowsocksPassword, 'base64').length === ssKeyLen; } catch {}
      if (!ok) {
        if (this.config.shadowsocks.password) Logger.warn(`SS_PASSWORD is not a base64 ${ssKeyLen}-byte key for ${this.config.shadowsocks.method}; generating a valid one.`);
        this.state.ssKey2022 = (this.state.ssKey2022 && Buffer.from(this.state.ssKey2022, 'base64').length === ssKeyLen)
          ? this.state.ssKey2022
          : crypto.randomBytes(ssKeyLen).toString('base64');
        this.state.shadowsocksPassword = this.state.ssKey2022;
      }
    }

    this.save();
    return this.state;
  }

  setLinks(links, clashYaml = '', singboxJson = '') {
    this.state.links = links;
    this.state.clashYaml = clashYaml;
    this.state.singboxJson = singboxJson;
    this.state.base64Sub = Buffer.from(links.join('\n')).toString('base64');
    this.save();
  }

  setPublicIp(ip) {
    if (this.state.publicIp !== ip) {
      this.state.publicIp = ip;
      this.save();
    }
  }

  save() {
    try {
      this.state.updatedAt = new Date().toISOString();
      fs.mkdirSync(this.paths.dataDir, { recursive: true });
      fs.writeFileSync(this.paths.stateFile, JSON.stringify(this.state, null, 2), 'utf8');
    } catch (err) {
      Logger.warn(`Could not save state.json: ${err.message}`);
    }
  }
}

module.exports = StateManager;
