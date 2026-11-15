/** Aral Pars — minimal ANSI logger. */
'use strict';

const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  gold: '\x1b[38;5;178m',
  wine: '\x1b[38;5;52m',
  cream: '\x1b[38;5;230m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  cyan: '\x1b[36m'
};

class Logger {
  static quiet = false;

  static banner() {
    if (this.quiet) return;
    const art = `
${C.gold}${C.bold}    ▄▀█ █▀▄▀█ █▄▄ █▀█ ▀▄▀   █░░ █ █▄░█ █▀▀░ ▄▀█ █▀
${C.gold}    █▀█ █░▀░█ █▄█ █▄█ █░█   █▄▄ █ █░▀█ █▄▄▀ █▀█ ▄█
${C.wine}    ── Aral Pars ── ${C.cream}یک پورت، همهٔ مسیرها${C.wine} ── Aral Pars ──${C.reset}`;
    console.log(art);
    console.log(`${C.cyan}================================================================${C.reset}`);
    console.log(`${C.bold}${C.gold}  ARAL PARS ${C.cream}• ${'lightweight multi-protocol proxy panel'}${C.reset}`);
    console.log(`${C.dim}  Brand: Aral Pars${C.reset}`);
    console.log(`${C.cyan}================================================================${C.reset}\n`);
  }

  static info(msg) { if (!this.quiet) console.log(`${C.cyan}[i] ${msg}${C.reset}`); }
  static success(msg) { if (!this.quiet) console.log(`${C.green}[OK] ${msg}${C.reset}`); }
  static warn(msg) { if (!this.quiet) console.log(`${C.yellow}[!] ${msg}${C.reset}`); }
  static error(msg) { console.error(`${C.red}[X] ${msg}${C.reset}`); }
  static step(msg) { if (!this.quiet) console.log(`${C.gold}==> ${msg}${C.reset}`); }
  static item(label, val) {
    if (!this.quiet) console.log(`  ${C.gold}${String(label).padEnd(18)}:${C.reset} ${C.cream}${val}${C.reset}`);
  }
  static section(title) {
    if (!this.quiet) console.log(`\n${C.bold}${C.gold}--- ${title} ---${C.reset}`);
  }
}

module.exports = Logger;
