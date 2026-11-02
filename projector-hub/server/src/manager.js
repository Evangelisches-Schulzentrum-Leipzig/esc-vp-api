'use strict';
const { Projector } = require('./projector');
const { discover } = require('./discovery');

class Manager {
    constructor(config, log) {
        this.config = config;
        this.log = log;
        this.projectors = new Map();
        this._discoveryTimer = null;
        this._discovering = null;
        this._stopped = false;
    }

    start() {
        const { discovery } = this.config.data;
        for (const host of Object.keys(this.config.data.projectors)) this.ensure(host, 'saved');
        for (const host of discovery.staticHosts) this.ensure(host, 'static');
        if (discovery.enabled) this._scheduleDiscovery(0);
    }

    stop() {
        this._stopped = true;
        clearTimeout(this._discoveryTimer);
        for (const p of this.projectors.values()) p.stop();
    }

    ensure(host, via, info) {
        let p = this.projectors.get(host);
        if (!p) {
            p = new Projector(host, { config: this.config, log: this.log });
            this.projectors.set(host, p);
            this.log.info(`Monitoring projector ${host} (${via})`);
            p.start();
        }
        if (info) p.updateDiscovery(info, via);
        return p;
    }

    discoverNow() {
        if (!this._discovering) {
            const d = this.config.data.discovery;
            this._discovering = discover({
                port: d.port, timeoutMs: d.timeoutMs, broadcastAddresses: d.broadcastAddresses, staticHosts: d.staticHosts, log: this.log,
            })
                .then(found => {
                    for (const [ip, info] of found) this.ensure(ip, 'udp-hello', info);
                    this.log.info(`Discovery finished: ${found.size} responded, ${this.projectors.size} monitored`);
                    return found.size;
                })
                .catch(err => this.log.error(`Discovery failed: ${err.message}`))
                .finally(() => {
                    this._discovering = null;
                });
        }
        return this._discovering;
    }

    _scheduleDiscovery(delay) {
        this._discoveryTimer = setTimeout(async () => {
            await this.discoverNow();
            if (!this._stopped) this._scheduleDiscovery(this.config.data.discovery.intervalMs);
        }, delay);
    }

    list() {
        return [...this.projectors.values()];
    }

    get(id) {
        return this.projectors.get(id) ?? null;
    }
}

module.exports = { Manager };
