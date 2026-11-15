/**
 * Aral Pars — runtime settings persisted to aral-data/settings.json.
 * Only the minimal, necessary options: link domain, protocol switches,
 * Shadowsocks method/password. Applied on restart.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const Logger = require('./logger');

const PROTO_KEYS = [
  'vlessWs', 'vlessWsTls',
  'vmessWs', 'vmessWsTls',
  'trojanWs', 'trojanWsTls',
  'vlessHttpUpgrade', 'vmessHttpUpgrade', 'trojanHttpUpgrade',
  'vlessGrpc', 'vlessGrpcTls',
  'ssWs', 'vlessXhttp'
];

const SS_METHODS = [
  'aes-256-gcm', 'aes-128-gcm', 'chacha20-ietf-poly1305',
  '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm'
];

class SettingsManager {
  constructor(dataDir) {
    this.file = path.join(dataDir, 'settings.json');
    this.settings = { domain: '', enable: {}, ssMethod: '', ssPassword: '' };
    this.load();
  }

  load() {
    try {
      if (fs.existsSync(this.file)) {
        const parsed = JSON.parse(fs.readFileSync(this.file, 'utf8'));
        this.settings = { ...this.settings, ...parsed };
      }
    } catch (err) {
      Logger.warn(`Could not read settings.json: ${err.message}`);
    }
  }

  save() {
    try {
      fs.writeFileSync(this.file, JSON.stringify(this.settings, null, 2), 'utf8');
    } catch (err) {
      Logger.warn(`Could not save settings.json: ${err.message}`);
    }
  }

  /** Domain override for links (saved, applied on restart unless env DOMAIN wins). */
  setDomain(domain) {
    this.settings.domain = String(domain || '').trim();
    this.save();
    return this.settings.domain;
  }

  /** Toggle protocol switches (saved, applied on restart unless env flags win). */
  setProtocols(enableObj) {
    for (const k of PROTO_KEYS) {
      if (k in enableObj) this.settings.enable[k] = !!enableObj[k];
    }
    this.save();
    return this.settings.enable;
  }

  /** Shadowsocks method / password (saved, applied on restart unless env wins). */
  setAdvanced({ ssPassword, ssMethod }) {
    if (ssMethod !== undefined) {
      const m = String(ssMethod || '').trim();
      this.settings.ssMethod = SS_METHODS.includes(m) ? m : '';
    }
    if (ssPassword !== undefined && ssPassword !== null && String(ssPassword) !== '') {
      this.settings.ssPassword = String(ssPassword);
    }
    this.save();
    return { ssMethod: this.settings.ssMethod, ssPassword: this.settings.ssPassword };
  }

  /** Merge persisted settings into a built config (env vars always win). */
  applyTo(config) {
    const env = process.env;
    if (this.settings.domain && !env.DOMAIN && !config.domain) {
      config.domain = this.settings.domain;
      config.forceHost = config.forceHost || this.settings.domain;
    }
    for (const k of PROTO_KEYS) {
      if (k in this.settings.enable) config.enable[k] = !!this.settings.enable[k];
    }
    if (this.settings.ssMethod && !env.SS_METHOD) config.shadowsocks.method = this.settings.ssMethod;
    if (this.settings.ssPassword && !env.SS_PASSWORD) config.shadowsocks.password = this.settings.ssPassword;
    return config;
  }
}

module.exports = { SettingsManager, PROTO_KEYS, SS_METHODS };
