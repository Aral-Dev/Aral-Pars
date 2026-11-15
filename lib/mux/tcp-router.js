/**
 * Aral Pars — single-port TCP multiplexer.
 *
 * One public PORT carries everything. The first bytes of each TCP connection decide the route:
 *   - TLS ClientHello (0x16 0x03) → ALPN routing: gRPC-only clients (ALPN "h2" alone) go to
 *     sing-box's gRPC-TLS inbound; everything else is decrypted by the internal HTTPS server
 *     (panel, subscriptions, WS/HTTPUpgrade/XHTTP over TLS).
 *   - HTTP/2 cleartext preface ("PRI * HTTP/2.0") → sing-box VLESS-gRPC (h2c).
 *   - Plain HTTP → Express panel & WS upgrades, routed per path.
 */
'use strict';

const net = require('net');
const http = require('http');
const https = require('https');
const http2 = require('http2');
const tls = require('tls');
const Logger = require('../logger');
const { PATHS } = require('../constants');
const { parseClientHello } = require('../tls-sni');
const { ensureTlsCertificates } = require('../cert');
const Traffic = require('../traffic');

class TcpRouter {
  constructor(config, targetPorts, expressServer, expressApp) {
    this.config = config;
    this.ports = targetPorts;
    this.httpServer = expressServer;
    this.expressApp = expressApp || (expressServer && expressServer.listeners('request')[0]);
    this.server = null;
    this.httpsServer = null;
    this.internalHttpsPort = null;
  }

  pipeToBackend(clientSocket, firstChunk, targetPort, label) {
    clientSocket.setTimeout(0);
    clientSocket.setKeepAlive(true, 10000);
    clientSocket.setNoDelay(true);

    const backend = net.connect(targetPort, '127.0.0.1', () => {
      backend.setTimeout(0);
      backend.setKeepAlive(true, 10000);
      backend.setNoDelay(true);
      backend.write(firstChunk);
      if (label !== 'Internal-HTTPS') { // decrypted WS / HTTPUpgrade / XHTTP traffic is metered inside the HTTPS path
        Traffic.add(label, firstChunk ? firstChunk.length : 0, 0);
        Traffic.meter(label, clientSocket, backend);
      }
      clientSocket.pipe(backend);
      backend.pipe(clientSocket);
      clientSocket.resume();
    });

    backend.on('error', (err) => {
      const now = Date.now();
      if (!this._lastWarns) this._lastWarns = {};
      if (!this._lastWarns[label] || now - this._lastWarns[label] > 15000) {
        Logger.warn(`TCP Router: ${label} backend on :${targetPort} unreachable (${err.message})`);
        this._lastWarns[label] = now;
      }
      try { clientSocket.destroy(); } catch {}
    });

    clientSocket.on('error', () => {
      try { backend.destroy(); } catch {}
    });
  }

  /** Route WebSocket / HTTPUpgrade handshakes per path (exact path, longest first). */
  attachUpgradeHandlers(server) {
    server.on('upgrade', (req, socket, head) => {
      socket.setTimeout(0);
      socket.setKeepAlive(true, 10000);
      socket.setNoDelay(true);

      let url = req.url || '';
      try { url = decodeURIComponent(url.split('?')[0]); } catch { url = url.split('?')[0]; }
      const pp = this.config.panelPath;
      const routes = [
        [PATHS.vlessWs, `/${pp}-ws`, this.ports.vlessWs, 'VLESS-WS'],
        [PATHS.vmessWs, `/${pp}-vmess`, this.ports.vmessWs, 'VMess-WS'],
        [PATHS.trojanWs, `/${pp}-trojan`, this.ports.trojanWs, 'Trojan-WS'],
        [PATHS.vlessHu, `/${pp}-hu`, this.ports.vlessHu, 'VLESS-HTTPUpgrade'],
        [PATHS.vmessHu, `/${pp}-vmess-hu`, this.ports.vmessHu, 'VMess-HTTPUpgrade'],
        [PATHS.trojanHu, `/${pp}-trojan-hu`, this.ports.trojanHu, 'Trojan-HTTPUpgrade'],
        [PATHS.xhttp, `/${pp}-xh`, this.config.xhttpPort, 'VLESS-XHTTP'],
        [PATHS.ssWs, `/${pp}-ss`, this.config.ssWsPort, 'Shadowsocks-WS']
      ];
      const hit = (p) => url === p || url.startsWith(p + '/');

      let destPort = null;
      let label = 'Unknown Upgrade';
      for (const [branded, legacy, port, lbl] of routes) {
        if (hit(branded) || hit(legacy)) { if (port) { destPort = port; label = lbl; } break; }
      }

      this._upgradeCount = (this._upgradeCount || 0) + 1;
      if (this._upgradeCount <= 20 || !destPort) {
        Logger.info(`WS upgrade #${this._upgradeCount} ${label} path=${url.slice(0, 80)} host=${req.headers.host || '-'}`);
      }

      if (!destPort) {
        socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
        socket.destroy();
        return;
      }

      const backend = net.connect(destPort, '127.0.0.1', () => {
        backend.setTimeout(0);
        backend.setKeepAlive(true, 10000);
        backend.setNoDelay(true);

        let headersStr = `${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`;
        for (let i = 0; i < req.rawHeaders.length; i += 2) {
          headersStr += `${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}\r\n`;
        }
        headersStr += '\r\n';

        backend.write(headersStr);
        if (head && head.length > 0) backend.write(head);

        Traffic.add(label, head && head.length ? head.length : 0, 0);
        Traffic.meter(label, socket, backend);
        socket.pipe(backend);
        backend.pipe(socket);
      });

      let connected = false;
      backend.once('connect', () => { connected = true; });
      backend.on('error', (err) => {
        if (!connected) {
          const now = Date.now();
          if (!this._lastUpErr || now - this._lastUpErr > 15000) {
            this._lastUpErr = now;
            Logger.error(`${label} backend :${destPort} unreachable (${err.message}) - is sing-box running? Serving 502.`);
          }
          try { socket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); } catch {}
        }
        try { socket.destroy(); } catch {}
      });

      socket.on('error', () => { try { backend.destroy(); } catch {} });
      socket.on('close', () => { try { backend.destroy(); } catch {} });
      backend.on('close', () => { try { socket.destroy(); } catch {} });
    });
  }

  /**
   * One internal TLS terminator for everything TLS on the shared port:
   *   ALPN http/1.1 → Express panel / subscription + WS / HTTPUpgrade / XHTTP upgrades
   *   ALPN h2       → per-stream router: gRPC service path → sing-box VLESS-gRPC (h2c), else panel
   * (Xray clients with a uTLS fingerprint offer "h2,http/1.1" for gRPC exactly like a browser,
   *  so the choice has to be made per HTTP/2 stream, not from the ClientHello.)
   */
  async setupInternalHttps() {
    try {
      const certs = ensureTlsCertificates(this.config.paths.certPath, this.config.paths.keyPath, this.config.domain || 'localhost');
      if (!certs || !certs.cert || !certs.key) return;

      const handler = this.expressApp || (this.httpServer && this.httpServer.listeners('request')[0]);
      this.h1Server = http.createServer(handler);
      this.h1Server.keepAliveTimeout = 120000;
      this.h1Server.headersTimeout = 125000;
      this.h1Server.requestTimeout = 0;
      this.h1Server.timeout = 0;
      this.attachUpgradeHandlers(this.h1Server);

      const grpcBackend = this.config.enable.vlessGrpcTls && this.ports.vlessGrpc;
      if (grpcBackend) this._setupH2Router();

      this.httpsServer = tls.createServer({
        cert: certs.cert,
        key: certs.key,
        ALPNProtocols: grpcBackend ? ['h2', 'http/1.1'] : ['http/1.1']
      }, (sock) => {
        sock.on('error', () => {});
        if (sock.alpnProtocol === 'h2' && this.h2Server) this.h2Server.emit('connection', sock);
        else this.h1Server.emit('connection', sock);
      });
      this.httpsServer.on('tlsClientError', () => {});

      await new Promise((resolve) => {
        this.httpsServer.listen(0, '127.0.0.1', () => {
          this.internalHttpsPort = this.httpsServer.address().port;
          Logger.item('Internal HTTPS Port', this.internalHttpsPort);
          resolve();
        });
        this.httpsServer.on('error', (err) => {
          Logger.warn(`Internal HTTPS server failed to start: ${err.message}`);
          resolve();
        });
      });
    } catch (err) {
      Logger.warn(`Internal HTTPS setup error: ${err.message}`);
    }
  }

  /** HTTP/2 stream router inside the TLS terminator: gRPC paths → sing-box VLESS-gRPC, else panel over h1. */
  _setupH2Router() {
    const HOP = new Set(['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'host', 'te', 'trailer', 'proxy-authorization', 'proxy-authenticate']);
    const grpcPrefix = '/' + PATHS.grpcService + '/';
    const big = { initialWindowSize: 4 * 1024 * 1024, maxFrameSize: 64 * 1024 };
    this.h2Server = http2.createServer({ settings: big });
    this.h2Server.on('session', (session) => {
      session.on('error', () => {});
      try { session.setLocalWindowSize(16 * 1024 * 1024); } catch {}
      session.on('close', () => {
        if (session._aralBackend) { try { session._aralBackend.close(); } catch {} }
      });
    });
    const backendFor = (session) => {
      let be = session._aralBackend;
      if (be && !be.closed && !be.destroyed) return be;
      be = http2.connect(`http://127.0.0.1:${this.ports.vlessGrpc}`, { settings: big });
      be.on('error', () => {});
      be.on('connect', () => { try { be.setLocalWindowSize(16 * 1024 * 1024); } catch {} });
      session._aralBackend = be;
      return be;
    };
    this.h2Server.on('stream', (stream, headers) => {
      stream.on('error', () => {});
      const p = String(headers[':path'] || '/');
      const fwd = {};
      for (const k of Object.keys(headers)) if (!k.startsWith(':') && !HOP.has(k)) fwd[k] = headers[k];

      if (p.startsWith(grpcPrefix)) {
        let up;
        try {
          up = backendFor(stream.session).request({ ...fwd, ':method': headers[':method'] || 'POST', ':path': p });
        } catch { try { stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR); } catch {} return; }
        let trailers = null;
        up.on('error', () => { try { stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR); } catch {} });
        up.on('response', (rh) => {
          const out = { ':status': rh[':status'] || 200 };
          for (const k of Object.keys(rh)) if (!k.startsWith(':') && !HOP.has(k)) out[k] = rh[k];
          try { stream.respond(out, { waitForTrailers: true }); } catch { return; }
          Traffic.meter('VLESS-gRPC', stream, up);
          up.pipe(stream);
        });
        up.on('trailers', (t) => { trailers = t; });
        stream.on('wantTrailers', () => {
          const t = {};
          if (trailers) for (const k of Object.keys(trailers)) if (!k.startsWith(':')) t[k] = trailers[k];
          if (!Object.keys(t).length) t['grpc-status'] = '0';
          try { stream.sendTrailers(t); } catch {}
        });
        stream.pipe(up);
        stream.on('close', () => { if (!up.closed) { try { up.close(); } catch {} } });
        up.on('close', () => { if (!stream.closed && !stream.headersSent) { try { stream.close(); } catch {} } });
        return;
      }

      // Not a gRPC client: relay the request to the panel over HTTP/1.1.
      fwd.host = headers[':authority'] || 'localhost';
      fwd['x-forwarded-proto'] = 'https';
      const rq = http.request({ host: '127.0.0.1', port: this.config.publicPort, method: headers[':method'] || 'GET', path: p, headers: fwd, agent: false });
      rq.on('response', (r) => {
        const out = { ':status': r.statusCode };
        for (const [k, v] of Object.entries(r.headers)) if (!HOP.has(k)) out[k] = v;
        try { stream.respond(out); } catch { r.destroy(); return; }
        r.pipe(stream);
      });
      rq.on('error', () => { try { if (!stream.headersSent) stream.respond({ ':status': 502 }); stream.end(); } catch {} });
      stream.pipe(rq);
    });
  }

  async start() {
    this.httpServer.keepAliveTimeout = 120000;
    this.httpServer.headersTimeout = 125000;
    this.attachUpgradeHandlers(this.httpServer);

    await this.setupInternalHttps();

    this.server = net.createServer((socket) => {
      socket.setTimeout(0);
      socket.setKeepAlive(true, 10000);
      socket.setNoDelay(true);

      // A TLS ClientHello (esp. with post-quantum key shares, ~1.8 KB) often arrives split
      // over several TCP segments; wait for the whole first record so SNI / ALPN routing sees every extension.
      let pending = null;
      let waitTimer = null;
      const onFirstData = (data) => {
        pending = pending ? Buffer.concat([pending, data]) : data;
        const needMore = (pending[0] === 0x16 && pending[1] === 0x03 && pending.length >= 5 && pending.length < pending.readUInt16BE(3) + 5)
          || (pending.length < 16 && 'PRI * HTTP/2.0\r\n'.startsWith(pending.toString('latin1')));
        if (needMore) {
          if (!waitTimer) waitTimer = setTimeout(() => { socket.removeListener('data', onFirstData); socket.pause(); route(pending); }, 400);
          return;
        }
        if (waitTimer) clearTimeout(waitTimer);
        socket.removeListener('data', onFirstData);
        socket.pause();
        route(pending);
      };
      socket.on('data', onFirstData);
      const route = (chunk) => {
        // 1. TLS ClientHello check (0x16 0x03)
        if (chunk.length >= 3 && chunk[0] === 0x16 && chunk[1] === 0x03) {
          const { sni, alpn } = parseClientHello(chunk);
          let target = null;

          // Priority 1: gRPC over TLS. gRPC clients offer ONLY "h2"; browsers / WS / HTTPUpgrade
          // clients offer "http/1.1" (often together with h2), so they still reach the internal HTTPS server below.
          if (alpn && alpn.includes('h2') && !alpn.includes('http/1.1') && this.config.enable.vlessGrpcTls && this.ports.vlessGrpcTls) {
            target = { port: this.ports.vlessGrpcTls, label: 'VLESS-gRPC' };
          }
          // Priority 2: Internal HTTPS server (VLESS-WS-TLS, VMess-WS-TLS, Trojan-WS-TLS, HTTPS Sub, HTTPS Panel)
          else if (this.internalHttpsPort) {
            target = { port: this.internalHttpsPort, label: 'Internal-HTTPS' };
          }
          // Priority 3: fallback to sing-box's own TLS inbound
          else if (this.config.enable.vlessGrpcTls && this.ports.vlessGrpcTls) {
            target = { port: this.ports.vlessGrpcTls, label: 'VLESS-gRPC' };
          }

          if (target) {
            this.pipeToBackend(socket, chunk, target.port, target.label);
            return;
          }
        }

        // 2. gRPC check (HTTP/2 cleartext connection preface)
        if (this.config.enable.vlessGrpc && this.ports.vlessGrpc && chunk.length >= 16) {
          if (chunk.toString('latin1', 0, 16) === 'PRI * HTTP/2.0\r\n') {
            this.pipeToBackend(socket, chunk, this.ports.vlessGrpc, 'VLESS-gRPC');
            return;
          }
        }

        // 3. Fallback: hand off to the internal HTTP server (Express panel & WS upgrades)
        socket.unshift(chunk);
        this.httpServer.emit('connection', socket);
        socket.resume();
      };

      socket.on('error', () => {});
    });

    return new Promise((resolve, reject) => {
      this.server.listen(this.config.publicPort, '0.0.0.0', () => {
        Logger.success(`Public TCP multiplexer listening on 0.0.0.0:${this.config.publicPort}`);
        resolve(this.server);
      });
      this.server.on('error', reject);
    });
  }

  stop() {
    if (this.server) { try { this.server.close(); } catch {} }
    if (this.httpsServer) { try { this.httpsServer.close(); } catch {} }
  }
}

module.exports = TcpRouter;
