/** Aral Pars — local port allocation helpers. */
'use strict';

const net = require('net');

/** Find one available TCP port on 127.0.0.1. */
function findFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const address = srv.address();
      const port = typeof address === 'object' && address ? address.port : null;
      srv.close((err) => {
        if (err) return reject(err);
        if (!port) return reject(new Error('Failed to resolve ephemeral port'));
        resolve(port);
      });
    });
  });
}

/** Allocate multiple distinct free local ports. */
async function allocatePorts(count = 1) {
  const ports = [];
  for (let i = 0; i < count; i++) ports.push(await findFreePort());
  return count === 1 ? ports[0] : ports;
}

module.exports = { findFreePort, allocatePorts };
