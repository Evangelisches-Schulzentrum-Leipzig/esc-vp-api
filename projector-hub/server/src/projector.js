'use strict';
// One monitored projector: negotiates credentials/protocol version once, then polls all get commands on an interval.
const { openSession, EscvpError } = require('./protocol');
const { COMMANDS, interpretReply, sourceMapFrom } = require('./commands');

const iso = () => new Date().toISOString();

// Identity values retained even when the projector later answers ERR (e.g. in standby).
const IDENTITY = { NWPNAME: 'name', IMNWPNAME: 'altName', SNO: 'serialNumber', NWMAC: 'macAddress', VER: 'firmware' };

class Projector {
    constructor(host, { config, log }) {
        this.host = host;
        this.config = config;
        this.log = log;
        this.discovery = null;
        this.connection = {
            status: 'pending', protocolVersion: null, error: null,
            lastAttemptAt: null, lastConnectedAt: null, consecutiveFailures: 0,
        };
        this.commands = {};
        this.identity = {};
        this.history = [];
        this.lastPollAt = null;
        this.lastPollDurationMs = null;

        this._session = null;
        this._running = false;
        this._timer = null;
        this._wake = null;
        this._pendingRefresh = false;
        this._slowDueAt = 0;
    }

    start() {
        if (this._running) return;
        this._running = true;
        this._loop();
    }

    stop() {
        this._running = false;
        this._session?.close();
        if (this._wake) this._wake();
    }

    refreshNow() {
        this._pendingRefresh = true;
        this._slowDueAt = 0;
        if (this._wake) this._wake();
    }

    updateDiscovery(info, via) {
        this.discovery = { ...(this.discovery ?? {}), ...info, via, lastSeenAt: iso() };
    }

    // ---- polling loop ----

    async _loop() {
        while (this._running) {
            let delay;
            try {
                delay = await this._cycle();
            } catch (err) {
                this.log.error(`[${this.host}] unexpected poll error: ${err.stack || err}`);
                delay = this.config.data.polling.fastIntervalMs;
            }
            if (this._running) await this._sleep(delay);
        }
    }

    _sleep(ms) {
        if (this._pendingRefresh) {
            this._pendingRefresh = false;
            return Promise.resolve();
        }
        return new Promise(resolve => {
            this._timer = setTimeout(() => this._finishSleep(resolve), ms);
            this._wake = () => this._finishSleep(resolve);
        });
    }

    _finishSleep(resolve) {
        clearTimeout(this._timer);
        this._wake = null;
        this._pendingRefresh = false;
        resolve();
    }

    async _cycle() {
        const p = this.config.data.polling;
        const started = Date.now();
        this.connection.lastAttemptAt = iso();
        try {
            this._session = await this._connect();
            this._setConnection('online');
            const slowDue = started >= this._slowDueAt;
            // Scheduled before polling so a power change during the poll can still force an early slow refresh.
            if (slowDue) this._slowDueAt = Date.now() + p.slowIntervalMs;
            await this._pollCommands(slowDue);
            this.lastPollAt = iso();
            this.lastPollDurationMs = Date.now() - started;
            return Math.max(0, p.fastIntervalMs - this.lastPollDurationMs);
        } catch (err) {
            return this._handleFailure(err);
        } finally {
            this._session?.close();
            this._session = null;
        }
    }

    _handleFailure(err) {
        const p = this.config.data.polling;
        const kind = err instanceof EscvpError ? err.kind : 'network';
        this.connection.consecutiveFailures += 1;
        this.connection.error = err.message;
        this.log.warn(`[${this.host}] ${kind}: ${err.message}`);
        switch (kind) {
            case 'auth':
                this._setConnection('auth-failed');
                return p.authRetryMs;
            case 'version':
                this._setConnection('unsupported');
                return p.authRetryMs;
            case 'busy':
                this._setConnection('busy');
                return p.fastIntervalMs;
            default:
                this._setConnection('unreachable');
                return Math.min(p.maxBackoffMs, p.fastIntervalMs * 2 ** Math.min(this.connection.consecutiveFailures, 10));
        }
    }

    _setConnection(status) {
        const c = this.connection;
        if (status === 'online') {
            c.lastConnectedAt = iso();
            c.consecutiveFailures = 0;
            c.error = null;
        }
        if (c.status !== status) {
            this._pushHistory({ type: 'connection', from: c.status, to: status, error: c.error });
            c.status = status;
        }
    }

    // ---- connection / credential negotiation ----

    _open(version, password) {
        const p = this.config.data.polling;
        return openSession({
            host: this.host,
            port: this.config.data.protocol.port,
            version,
            password,
            connectTimeoutMs: p.connectTimeoutMs,
            ioTimeoutMs: p.commandTimeoutMs,
        }).then(session => {
            this.connection.protocolVersion = version;
            return session;
        });
    }

    async _connect() {
        const saved = this.config.getProjectorSettings(this.host);
        if (saved) {
            try {
                return await this._open(saved.version, saved.password);
            } catch (err) {
                if (!(err instanceof EscvpError) || (err.kind !== 'auth' && err.kind !== 'version')) throw err;
                this.log.warn(`[${this.host}] saved settings rejected (${err.message}); renegotiating`);
                this.config.clearProjectorSettings(this.host);
            }
        }
        return this._negotiate();
    }

    async _negotiate() {
        let last = null;
        for (const version of this.config.data.protocol.versions) {
            for (const password of this.config.data.credentials) {
                try {
                    const session = await this._open(version, password);
                    this.config.setProjectorSettings(this.host, { version, password });
                    this.log.info(`[${this.host}] connected with protocol ${version}; settings saved`);
                    return session;
                } catch (err) {
                    if (!(err instanceof EscvpError) || (err.kind !== 'auth' && err.kind !== 'version')) throw err;
                    last = err;
                    if (err.kind === 'version') break; // wrong version: other passwords will fail the same way
                }
            }
        }
        throw last ?? new EscvpError('auth', 'No credentials configured');
    }

    // ---- command polling ----

    _ctx() {
        return { sources: sourceMapFrom(this.commands.SOURCELIST?.value) };
    }

    async _pollCommands(slowDue) {
        let reconnects = 0;
        for (const def of COMMANDS) {
            if (def.poll === 'slow' && !slowDue) continue;
            try {
                const reply = await this._session.query(def.query);
                this._record(def, interpretReply(def, reply, this._ctx()));
            } catch (err) {
                if (!(err instanceof EscvpError)) throw err;
                this._record(def, { status: 'error', error: err.message });
                if (err.kind !== 'timeout' && err.kind !== 'network') throw err;
                // The session is unusable after a missed reply; reconnect and carry on with the next command.
                this._session.close();
                if (++reconnects > 3) throw err;
                this._session = await this._connect();
            }
        }
    }

    _record(def, outcome) {
        const now = iso();
        const prev = this.commands[def.cmd];
        const entry = {
            command: def.cmd,
            query: def.query,
            category: def.category,
            description: def.description,
            documented: def.documented,
            status: outcome.status,
            raw: outcome.raw ?? null,
            value: outcome.value ?? null,
            display: outcome.display ?? null,
            error: outcome.error ?? null,
            updatedAt: now,
            lastOkAt: outcome.status === 'ok' ? now : prev?.lastOkAt ?? null,
            changedAt: prev?.changedAt ?? now,
        };
        const changed = !prev || prev.status !== entry.status || prev.raw !== entry.raw;
        if (changed) {
            entry.changedAt = now;
            if (prev) {
                this._pushHistory({
                    type: 'command', command: def.cmd,
                    from: { status: prev.status, raw: prev.raw, display: prev.display },
                    to: { status: entry.status, raw: entry.raw, display: entry.display },
                });
                if (def.cmd === 'PWR') this._slowDueAt = 0; // identity/network data becomes readable after power changes
            }
        }
        this.commands[def.cmd] = entry;
        if (entry.status === 'ok' && IDENTITY[def.cmd]) {
            this.identity[IDENTITY[def.cmd]] = typeof entry.value === 'object' && entry.value?.active ? entry.value.active : entry.value;
        }
    }

    _pushHistory(item) {
        this.history.push({ at: iso(), ...item });
        const max = this.config.data.history.maxEntries;
        if (this.history.length > max) this.history.splice(0, this.history.length - max);
    }

    // ---- API views ----

    summary() {
        const ok = name => {
            const c = this.commands[name];
            return c && c.status === 'ok' ? { value: c.value, display: c.display } : null;
        };
        return {
            id: this.host,
            host: this.host,
            name: this.identity.name ?? this.identity.altName ?? this.discovery?.name ?? null,
            model: this.discovery?.imType ?? null,
            serialNumber: this.identity.serialNumber ?? null,
            macAddress: this.identity.macAddress ?? null,
            firmware: this.identity.firmware ?? null,
            online: this.connection.status === 'online',
            connection: { ...this.connection },
            power: ok('PWR'),
            source: ok('SOURCE'),
            signal: ok('SIGNAL'),
            errorCode: ok('ERR'),
            lampHours: ok('LAMP'),
            lastPollAt: this.lastPollAt,
        };
    }

    detail() {
        return {
            ...this.summary(),
            discovery: this.discovery,
            lastPollDurationMs: this.lastPollDurationMs,
            commands: this.commands,
        };
    }
}

module.exports = { Projector };
