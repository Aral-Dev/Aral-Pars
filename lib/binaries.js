/** Aral Pars — binary manager: downloads sing-box and Xray-core into aral-data/bin. */
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const https = require('https');
const zlib = require('zlib');
const { spawnSync } = require('child_process');
const Logger = require('./logger');

function getNormalizedArch() {
  const arch = os.arch();
  if (arch === 'arm64' || arch === 'aarch64') return { sb: 'arm64', xray: 'arm64-v8a' };
  return { sb: 'amd64', xray: '64' };
}

function checkDiskSpaceMb(dir) {
  if (os.platform() !== 'linux') return 1024;
  try {
    const res = spawnSync('df', ['-m', dir], { encoding: 'utf8', timeout: 3000 });
    if (res.status === 0 && res.stdout) {
      const lines = res.stdout.trim().split('\n');
      if (lines.length >= 2) {
        const avail = parseInt(lines[1].trim().split(/\s+/)[3], 10);
        if (!isNaN(avail)) return avail;
      }
    }
  } catch {}
  return null;
}

/** Streaming download with timeout (no external HTTP deps). */
function downloadToFile(url, destPath) {
  return new Promise((resolve, reject) => {
    const tempPath = `${destPath}.tmp_${Date.now()}`;
    const file = fs.createWriteStream(tempPath);
    const req = https.get(url, {
      headers: { 'User-Agent': 'AralPars/1.0' },
      timeout: 60000,
      followRedirects: true
    }, (res) => {
      // Node https.get does not follow redirects by itself
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        file.close(() => fs.unlink(tempPath, () => {}));
        return downloadToFile(new URL(res.headers.location, url).toString(), destPath).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        file.close(() => fs.unlink(tempPath, () => {}));
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      res.pipe(file);
      file.on('finish', () => {
        file.close(() => {
          try {
            fs.renameSync(tempPath, destPath);
            if (os.platform() !== 'win32') fs.chmodSync(destPath, 0o755);
            resolve(true);
          } catch (err) { reject(err); }
        });
      });
      file.on('error', (err) => { try { fs.unlinkSync(tempPath); } catch {} reject(err); });
    });
    req.on('timeout', () => { req.destroy(new Error('download timeout')); });
    req.on('error', (err) => { try { file.close(); fs.unlinkSync(tempPath); } catch {} reject(err); });
  });
}

/** Extract a single file (by base name) from a .zip without external tools. */
function extractFromZip(zipPath, wantNames) {
  const buf = fs.readFileSync(zipPath);
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('zip: end of central directory not found');
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  for (let k = 0; k < count; k++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) throw new Error('zip: bad central directory');
    const method = buf.readUInt16LE(off + 10);
    const crc = buf.readUInt32LE(off + 16) >>> 0;
    const csize = buf.readUInt32LE(off + 20);
    const usize = buf.readUInt32LE(off + 24);
    const nlen = buf.readUInt16LE(off + 28);
    const elen = buf.readUInt16LE(off + 30);
    const clen = buf.readUInt16LE(off + 32);
    const lho = buf.readUInt32LE(off + 42);
    const name = buf.toString('utf8', off + 46, off + 46 + nlen);
    off += 46 + nlen + elen + clen;
    const base = name.split('/').pop();
    if (!wantNames.includes(base)) continue;
    if (buf.readUInt32LE(lho) !== 0x04034b50) throw new Error('zip: bad local header');
    const start = lho + 30 + buf.readUInt16LE(lho + 26) + buf.readUInt16LE(lho + 28);
    const raw = buf.subarray(start, start + csize);
    let data;
    if (method === 0) data = Buffer.from(raw);
    else if (method === 8) data = zlib.inflateRawSync(raw);
    else throw new Error('zip: unsupported compression method ' + method);
    if (data.length !== usize) throw new Error('zip: size mismatch for ' + base);
    if (typeof zlib.crc32 === 'function' && (zlib.crc32(data) >>> 0) !== crc) throw new Error('zip: CRC mismatch for ' + base);
    return { name: base, data };
  }
  return null;
}

function fetchText(url) {
  return new Promise((resolve) => {
    const req = https.get(url, { headers: { 'User-Agent': 'AralPars/1.0' }, timeout: 20000 }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return fetchText(new URL(res.headers.location, url).toString()).then(resolve, resolve);
      }
      if (res.statusCode !== 200) { res.resume(); return resolve(null); }
      let s = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { s += c; });
      res.on('end', () => resolve(s));
    });
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
  });
}

/** Fetch "<url>.dgst" (Xray release format) and return the SHA-256 hex, or null. */
async function fetchSha256Digest(url) {
  const txt = await fetchText(url + '.dgst');
  if (!txt) return null;
  const m = /SHA2?-?256[^=]*=\s*([0-9a-f]{64})/i.exec(String(txt));
  return m ? m[1].toLowerCase() : null;
}

class BinaryManager {
  constructor(config) {
    this.config = config;
    this.paths = config.paths;
    this.arch = getNormalizedArch();
  }

  ensureDirectories() {
    for (const d of [this.paths.dataDir, this.paths.binDir, this.paths.certDir]) {
      fs.mkdirSync(d, { recursive: true });
    }
  }

  async ensureSingBox() {
    this.ensureDirectories();
    const bin = this.paths.singboxBin;

    if (fs.existsSync(bin)) {
      try {
        if (fs.statSync(bin).size > 1024 * 1024) {
          if (os.platform() !== 'win32') fs.chmodSync(bin, 0o755);
          return true;
        }
      } catch {}
    }

    const freeMb = checkDiskSpaceMb(this.paths.binDir);
    if (freeMb !== null && freeMb < 40) Logger.warn(`Low disk space (~${freeMb}MB free). sing-box download might fail with ENOSPC.`);

    const ver = this.config.singBoxVersion || '1.11.15';
    const osType = os.platform() === 'win32' ? 'windows' : 'linux';
    const ext = osType === 'windows' ? 'zip' : 'tar.gz';
    const tarName = `sing-box-${ver}-${osType}-${this.arch.sb}.${ext}`;
    const url = process.env.SB_URL || `https://github.com/SagerNet/sing-box/releases/download/v${ver}/${tarName}`;
    const archivePath = path.join(this.paths.binDir, tarName);

    Logger.step(`Downloading sing-box v${ver} (${osType}-${this.arch.sb})...`);
    try {
      await downloadToFile(url, archivePath);

      if (osType === 'linux') {
        const extDir = path.join(this.paths.binDir, `sb_extract_${Date.now()}`);
        fs.mkdirSync(extDir, { recursive: true });
        const tarRes = spawnSync('tar', ['-xzf', archivePath, '-C', extDir]);
        if (tarRes.status !== 0) throw new Error(`tar extraction failed: ${tarRes.stderr}`);

        let foundBin = null;
        for (const f of fs.readdirSync(extDir)) {
          const sub = path.join(extDir, f);
          if (fs.statSync(sub).isDirectory() && fs.existsSync(path.join(sub, 'sing-box'))) {
            foundBin = path.join(sub, 'sing-box');
            break;
          }
        }
        if (!foundBin && fs.existsSync(path.join(extDir, 'sing-box'))) foundBin = path.join(extDir, 'sing-box');
        if (!foundBin) throw new Error('sing-box binary not found in archive');

        fs.copyFileSync(foundBin, bin);
        fs.chmodSync(bin, 0o755);
        try { fs.unlinkSync(archivePath); fs.rmSync(extDir, { recursive: true, force: true }); } catch {}
      } else {
        const entry = extractFromZip(archivePath, ['sing-box.exe']);
        if (!entry) throw new Error('sing-box.exe not found in archive');
        fs.writeFileSync(bin, entry.data);
        fs.chmodSync(bin, 0o755);
        try { fs.unlinkSync(archivePath); } catch {}
      }

      Logger.success('sing-box engine installed successfully.');
      return true;
    } catch (err) {
      Logger.error(`sing-box installation error: ${err.message}`);
      return false;
    }
  }

  async ensureXray() {
    this.ensureDirectories();
    const bin = this.paths.xrayBin;
    const want = String(process.env.XRAY_VERSION || this.config.xrayVersion || '').trim().replace(/^v/i, '');
    const probe = () => {
      try {
        const r = spawnSync(bin, ['version'], { encoding: 'utf8', timeout: 15000 });
        const m = /Xray\s+v?(\d+\.\d+\.\d+)/.exec(r.stdout || '');
        return r.status === 0 && m ? m[1] : null;
      } catch { return null; }
    };

    if (fs.existsSync(bin)) {
      if (os.platform() !== 'win32') { try { fs.chmodSync(bin, 0o755); } catch {} }
      const have = probe();
      if (have && (!want || want === have)) {
        Logger.success(`Xray-core ${have} ready (cached in ${this.paths.binDir}).`);
        return true;
      }
      if (have) Logger.info(`Xray-core ${have} cached but XRAY_VERSION=${want} requested - downloading.`);
      else Logger.warn('Cached Xray-core binary is not runnable - re-downloading.');
    }

    const freeMb = checkDiskSpaceMb(this.paths.binDir);
    if (freeMb !== null && freeMb < 60) Logger.warn(`Low disk space (~${freeMb}MB free). Xray-core download might fail.`);

    const osType = os.platform() === 'win32' ? 'windows' : 'linux';
    const zipName = `Xray-${osType}-${this.arch.xray}.zip`;
    const url = process.env.XRAY_URL || (want
      ? `https://github.com/XTLS/Xray-core/releases/download/v${want}/${zipName}`
      : `https://github.com/XTLS/Xray-core/releases/latest/download/${zipName}`);
    const exeName = osType === 'windows' ? 'xray.exe' : 'xray';
    Logger.step(`Downloading Xray-core ${want ? 'v' + want : '(latest stable)'} (${osType}-${this.arch.xray})...`);

    for (let attempt = 1; attempt <= 3; attempt++) {
      const archivePath = path.join(this.paths.binDir, `${zipName}.${Date.now()}`);
      const tmpBin = bin + '.new';
      try {
        await downloadToFile(url, archivePath);
        if (!process.env.XRAY_URL) {
          const expected = await fetchSha256Digest(url);
          const actual = crypto.createHash('sha256').update(fs.readFileSync(archivePath)).digest('hex');
          if (expected && expected !== actual) throw new Error('SHA-256 mismatch (download corrupted)');
          if (expected) Logger.info('Xray-core archive SHA-256 verified.');
          else Logger.warn('Xray-core .dgst not available; skipped SHA-256 check.');
        }
        const entry = extractFromZip(archivePath, [exeName]);
        if (!entry) throw new Error(exeName + ' not found in archive');
        fs.writeFileSync(tmpBin, entry.data);
        if (os.platform() !== 'win32') fs.chmodSync(tmpBin, 0o755);
        fs.renameSync(tmpBin, bin);
        const ver = probe();
        if (!ver) throw new Error('downloaded binary does not run');
        Logger.success(`Xray-core ${ver} installed (${osType}-${this.arch.xray}).`);
        return true;
      } catch (err) {
        Logger.warn(`Xray-core download attempt ${attempt}/3 failed: ${err.message}`);
        await new Promise((r) => setTimeout(r, 2000 * attempt));
      } finally {
        try { fs.unlinkSync(archivePath); } catch {}
        try { if (fs.existsSync(tmpBin)) fs.unlinkSync(tmpBin); } catch {}
      }
    }
    Logger.error('Xray-core unavailable - VLESS-XHTTP / Shadowsocks-WS disabled for this run.');
    return false;
  }
}

module.exports = { BinaryManager, downloadToFile, extractFromZip, getNormalizedArch };
