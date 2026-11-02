'use strict';
const fs = require('fs');
const path = require('path');

const DEFAULTS = {
    server: { host: '0.0.0.0', port: 3000 },
    discovery: {
        enabled: true,
        intervalMs: 60000,
        timeoutMs: 3000,
        port: 3629,
        // Extra UDP targets (broadcast or unicast) in addition to every local interface's broadcast address.
        broadcastAddresses: [],
        // Projectors that never answer UDP HELLO but should still be monitored.
        staticHosts: [],
    },
    protocol: { port: 3629, versions: ['v2', 'v1'] },
    // Passwords tried in order on the first connection to a projector ("" = no password).
    credentials: ['', 'admin', '12345678'],
    polling: {
        fastIntervalMs: 10000,
        slowIntervalMs: 300000,
        connectTimeoutMs: 2000,
        commandTimeoutMs: 3000,
        maxBackoffMs: 120000,
        // Minimum wait before re-trying the credential list on a projector that rejected all of them.
        authRetryMs: 600000,
    },
    history: { maxEntries: 500 },
    // Learned per-host settings: { "10.1.2.3": { version: "v2", password: "admin", savedAt: "..." } }
    projectors: {},
};

function merge(base, over) {
    if (Array.isArray(base) || typeof base !== 'object' || base === null) return over === undefined ? base : over;
    const out = { ...base };
    for (const [k, v] of Object.entries(over ?? {})) {
        out[k] = k in base && base[k] && typeof base[k] === 'object' && !Array.isArray(base[k]) ? merge(base[k], v) : v;
    }
    return out;
}

class Config {
    constructor(file) {
        this.file = file;
        this.data = merge(DEFAULTS, {});
    }

    load() {
        if (fs.existsSync(this.file)) {
            let parsed;
            try {
                parsed = JSON.parse(fs.readFileSync(this.file, 'utf8').replace(/^\uFEFF/, ''));
            } catch (err) {
                throw new Error(`Cannot parse config ${this.file}: ${err.message}`);
            }
            this.data = merge(DEFAULTS, parsed);
        } else {
            this.save();
        }
        return this;
    }

    save() {
        fs.mkdirSync(path.dirname(this.file), { recursive: true });
        const tmp = `${this.file}.tmp`;
        fs.writeFileSync(tmp, JSON.stringify(this.data, null, 2) + '\n', { mode: 0o600 });
        fs.renameSync(tmp, this.file);
    }

    getProjectorSettings(host) {
        return this.data.projectors[host] ?? null;
    }

    setProjectorSettings(host, settings) {
        this.data.projectors[host] = { ...settings, savedAt: new Date().toISOString() };
        this.save();
    }

    clearProjectorSettings(host) {
        if (host in this.data.projectors) {
            delete this.data.projectors[host];
            this.save();
        }
    }
}

module.exports = { Config, DEFAULTS };
