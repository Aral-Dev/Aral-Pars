/**
 * Aral Pars — shared constants and helpers.
 * Paths, credentials helpers and host normalization used across the panel.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

/** Single brand used everywhere (panel title, node names, subscriptions, footer). */
const BRAND = {
  name: 'Aral Pars',
  short: 'Aral',
  tagline: 'یک پورت، همهٔ مسیرها',
  taglineEn: 'One port. Many paths.'
};

/**
 * Every transport path / gRPC service routed on the single public port.
 * Exact-path routing (longest path first) keeps `.../vmess-hu` distinct from `.../vmess`.
 */
const P = '/@AralPars--';
const PATHS = {
  vlessWs: P + 'ws',
  vmessWs: P + 'vmess',
  trojanWs: P + 'trojan',
  vlessHu: P + 'httpupgrade',
  vmessHu: P + 'vmess-hu',
  trojanHu: P + 'trojan-hu',
  xhttp: P + 'xhttp',
  ssWs: P + 'ss',
  grpcService: P.slice(1) + 'grpc'
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Normalize a host: strips scheme, path, port; keeps IPv6 brackets. */
function normalizeHost(v) {
  let h = String(v || '').trim();
  if (!h) return '';
  h = h.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').split('/')[0].split('?')[0].split('#')[0];
  if (h.startsWith('[')) return h.slice(0, h.indexOf(']') + 1);
  if ((h.match(/:/g) || []).length === 1) h = h.split(':')[0];
  return h.toLowerCase();
}

function isIpLiteral(h) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':') || h.startsWith('[');
}

function isLocalAddress(host) {
  if (!host) return true;
  const clean = String(host).toLowerCase().trim();
  return clean === '127.0.0.1' || clean === 'localhost' || clean === '::1' ||
    clean === '0.0.0.0' || clean.startsWith('127.');
}

/** Short, non-secret form of a credential for logs. */
function mask(v) {
  v = String(v || '');
  return v ? v.slice(0, 4) + '…' + '(' + v.length + ' chars)' : '(empty)';
}

/** Shadowsocks 2022 ciphers need a base64 key of an exact length. */
function ss2022KeyLen(method) {
  if (/^2022-blake3-aes-128-gcm$/i.test(method)) return 16;
  if (/^2022-blake3-/i.test(method)) return 32;
  return 0;
}

/** Derive the x25519 public key from a base64 private key (REALITY keypair). */
function deriveX25519PublicKey(privBase64) {
  try {
    if (!privBase64 || typeof privBase64 !== 'string') return null;
    const privBuf = Buffer.from(privBase64.trim(), 'base64');
    if (privBuf.length !== 32) return null;
    const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), privBuf]);
    const keyObj = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
    return crypto.createPublicKey(keyObj).export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
  } catch {
    return null;
  }
}

/**
 * Determine a writable data directory.
 * Order: ARAL_DATA_DIR → ./aral-data (cwd) → app-dir/aral-data → tmpdir fallback.
 */
function resolveDataDir() {
  const tryDir = (dir) => {
    try {
      fs.mkdirSync(dir, { recursive: true });
      fs.accessSync(dir, fs.constants.W_OK);
      const probe = path.join(dir, '.aral-write-test');
      fs.writeFileSync(probe, 'ok');
      fs.unlinkSync(probe);
      return true;
    } catch {
      return false;
    }
  };
  const candidates = [
    [process.env.ARAL_DATA_DIR || process.env.FILE_PATH, 'ARAL_DATA_DIR'],
    [path.join(process.cwd(), 'aral-data'), './aral-data'],
    [path.join(__dirname, '..', 'aral-data'), 'app-dir aral-data']
  ];
  for (const [dir, source] of candidates) {
    if (dir && tryDir(dir)) {
      resolveDataDir.info = { dir, source };
      return dir;
    }
  }
  const dir = path.join(os.tmpdir(), 'aral-data');
  resolveDataDir.info = { dir, source: 'temp-dir fallback' };
  return dir;
}

module.exports = {
  BRAND,
  PATHS,
  UUID_RE,
  normalizeHost,
  isIpLiteral,
  isLocalAddress,
  mask,
  ss2022KeyLen,
  deriveX25519PublicKey,
  resolveDataDir
};
