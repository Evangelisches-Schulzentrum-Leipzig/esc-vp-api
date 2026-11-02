'use strict';
// ESC/VP.net transport (v1 plain password, v2 SHA-256 digest) and a read-only ESC/VP21 query session.
const net = require('net');
const crypto = require('crypto');

const SIGNATURE = Buffer.from('ESC/VP.net', 'ascii');
const COMMON_LEN = 16;
const HEADER_LEN = 18;
const VERSION = { v1: 0x10, v2: 0x20 };
const TYPE = { HELLO: 0x01, PASSWORD: 0x02, CONNECT: 0x03 };

const STATUS_TEXT = {
    0x20: 'OK',
    0x40: 'Bad request',
    0x41: 'Unauthorized (password required)',
    0x43: 'Forbidden (incorrect password)',
    0x45: 'Request not allowed',
    0x53: 'Service unavailable (busy)',
    0x55: 'Version not supported',
};

// Only get-style queries may ever be written to a projector.
const READ_ONLY_QUERY = /^[A-Z][A-Z0-9]{0,30}\?( [0-9A-Za-z]{1,16})?$/;

/** kind: network | timeout | protocol | auth | version | busy | command */
class EscvpError extends Error {
    constructor(kind, message, status = null) {
        super(message);
        this.name = 'EscvpError';
        this.kind = kind;
        this.status = status;
    }
}

function buildPacket(version, type, headers = []) {
    const packet = Buffer.alloc(COMMON_LEN + headers.length * HEADER_LEN);
    SIGNATURE.copy(packet);
    packet[10] = version;
    packet[11] = type;
    packet[15] = headers.length;
    headers.forEach((h, i) => {
        const off = COMMON_LEN + i * HEADER_LEN;
        packet[off] = h.id;
        packet[off + 1] = h.attribute;
        h.data.copy(packet, off + 2, 0, 16);
    });
    return packet;
}

function parsePacket(buf) {
    if (buf.length < COMMON_LEN) throw new EscvpError('protocol', 'Packet shorter than 16-byte header');
    if (!buf.subarray(0, 10).equals(SIGNATURE)) throw new EscvpError('protocol', 'Invalid ESC/VP.net signature');
    const count = buf[15];
    if (buf.length < COMMON_LEN + count * HEADER_LEN) {
        throw new EscvpError('protocol', 'Packet shorter than its declared headers');
    }
    const headers = [];
    for (let i = 0; i < count; i++) {
        const off = COMMON_LEN + i * HEADER_LEN;
        headers.push({ id: buf[off], attribute: buf[off + 1], data: buf.subarray(off + 2, off + HEADER_LEN) });
    }
    return { version: buf[10], type: buf[11], status: buf[14], headers };
}

function digestFor(password, nonce) {
    const passwordHash = crypto.createHash('sha256').update(`ESC/VP.net:${password}`, 'utf8').digest('hex');
    return crypto.createHash('sha256').update(`${passwordHash}:${nonce.toString('hex')}`, 'utf8').digest();
}

class SocketReader {
    constructor(socket) {
        this.buffer = Buffer.alloc(0);
        this.error = null;
        this.closed = false;
        this.wake = null;
        socket.on('data', chunk => {
            this.buffer = Buffer.concat([this.buffer, chunk]);
            this._notify();
        });
        socket.on('error', err => {
            this.error = err;
            this._notify();
        });
        socket.on('close', () => {
            this.closed = true;
            this._notify();
        });
    }

    _notify() {
        const wake = this.wake;
        this.wake = null;
        if (wake) wake();
    }

    async _fill(deadline) {
        if (this.error) throw new EscvpError('network', this.error.message);
        if (this.closed) throw new EscvpError('network', 'Connection closed by projector');
        const ms = deadline - Date.now();
        if (ms <= 0) throw new EscvpError('timeout', 'Timed out waiting for projector');
        await new Promise(resolve => {
            const timer = setTimeout(() => {
                this.wake = null;
                resolve();
            }, ms);
            this.wake = () => {
                clearTimeout(timer);
                resolve();
            };
        });
    }

    async readExactly(length, timeoutMs) {
        const deadline = Date.now() + timeoutMs;
        while (this.buffer.length < length) await this._fill(deadline);
        const out = this.buffer.subarray(0, length);
        this.buffer = this.buffer.subarray(length);
        return out;
    }

    async readUntil(marker, timeoutMs, maxLength = 8192) {
        const needle = Buffer.from(marker, 'ascii');
        const deadline = Date.now() + timeoutMs;
        for (;;) {
            const idx = this.buffer.indexOf(needle);
            if (idx !== -1) {
                const out = this.buffer.subarray(0, idx);
                this.buffer = this.buffer.subarray(idx + needle.length);
                return out;
            }
            if (this.buffer.length > maxLength) throw new EscvpError('protocol', 'Response exceeded maximum length');
            await this._fill(deadline);
        }
    }
}

function tcpConnect(host, port, timeoutMs) {
    return new Promise((resolve, reject) => {
        const socket = net.createConnection({ host, port });
        socket.setNoDelay(true);
        const timer = setTimeout(() => {
            socket.destroy();
            reject(new EscvpError('timeout', `Connect to ${host}:${port} timed out`));
        }, timeoutMs);
        const onError = err => {
            clearTimeout(timer);
            socket.destroy();
            reject(new EscvpError('network', `${host}:${port}: ${err.message}`));
        };
        socket.once('error', onError);
        socket.once('connect', () => {
            clearTimeout(timer);
            const reader = new SocketReader(socket);
            socket.off('error', onError);
            resolve({ socket, reader });
        });
    });
}

async function readPacket(reader, timeoutMs) {
    const head = await reader.readExactly(COMMON_LEN, timeoutMs);
    if (!head.subarray(0, 10).equals(SIGNATURE)) throw new EscvpError('protocol', 'Invalid ESC/VP.net response signature');
    const extra = head[15] * HEADER_LEN;
    const rest = extra ? await reader.readExactly(extra, timeoutMs) : Buffer.alloc(0);
    return parsePacket(Buffer.concat([head, rest]));
}

function statusError(status, context) {
    const message = `${context}: 0x${status.toString(16)} ${STATUS_TEXT[status] || 'Unknown status'}`;
    let kind = 'protocol';
    if (status === 0x41 || status === 0x43) kind = 'auth';
    else if (status === 0x55) kind = 'version';
    else if (status === 0x53) kind = 'busy';
    return new EscvpError(kind, message, status);
}

async function handshakeV1({ socket, reader }, password, ioTimeoutMs) {
    const pw = Buffer.from(password, 'latin1');
    if (pw.length > 16) throw new EscvpError('auth', 'Password too long for ESC/VP.net v1 (max 16 bytes)');
    const headers = pw.length ? [{ id: 0x01, attribute: 0x01, data: pw }] : [];
    socket.write(buildPacket(VERSION.v1, TYPE.CONNECT, headers));
    const res = await readPacket(reader, ioTimeoutMs);
    if (res.type !== TYPE.CONNECT) throw new EscvpError('protocol', `Unexpected response type ${res.type}`);
    if (res.status !== 0x20) throw statusError(res.status, 'V1 connect');
}

async function handshakeV2({ socket, reader }, password, ioTimeoutMs) {
    socket.write(buildPacket(VERSION.v2, TYPE.CONNECT, [{ id: 0x01, attribute: 0x03, data: Buffer.alloc(16) }]));
    const challenge = await readPacket(reader, ioTimeoutMs);
    if (challenge.type !== TYPE.CONNECT) throw new EscvpError('protocol', `Unexpected response type ${challenge.type}`);
    if (challenge.status !== 0x41 && challenge.status !== 0x20) throw statusError(challenge.status, 'V2 challenge');

    // Status 0x20 means no password is set; the proof is then computed from an empty password and zero nonce.
    let nonce = Buffer.alloc(16);
    let pw = '';
    if (challenge.status === 0x41) {
        if (!challenge.headers.length) throw new EscvpError('protocol', 'V2 challenge carried no nonce');
        nonce = challenge.headers[0].data;
        pw = password;
    }
    const digest = digestFor(pw, nonce);
    socket.write(buildPacket(VERSION.v2, TYPE.CONNECT, [
        { id: 0x01, attribute: 0x04, data: digest.subarray(0, 16) },
        { id: 0x01, attribute: 0x05, data: digest.subarray(16, 32) },
    ]));
    const res = await readPacket(reader, ioTimeoutMs);
    if (res.status !== 0x20) throw statusError(res.status, 'V2 authentication');
}

class Session {
    constructor(socket, reader, ioTimeoutMs) {
        this.socket = socket;
        this.reader = reader;
        this.ioTimeoutMs = ioTimeoutMs;
    }

    /** Sends one get-style query (e.g. "PWR?") and returns the raw reply text without the "\r:" terminator. */
    async query(command) {
        if (!READ_ONLY_QUERY.test(command)) {
            throw new EscvpError('command', `Refusing to send non-query command: ${command}`);
        }
        this.socket.write(`${command}\r`, 'ascii');
        const reply = await this.reader.readUntil('\r:', this.ioTimeoutMs);
        return reply.toString('ascii');
    }

    close() {
        this.socket.destroy();
    }
}

/** Opens an authenticated ESC/VP21 session. version: 'v1' | 'v2'. Throws EscvpError. */
async function openSession({ host, port = 3629, version, password = '', connectTimeoutMs = 2000, ioTimeoutMs = 3000 }) {
    if (!VERSION[version]) throw new EscvpError('protocol', `Unknown protocol version: ${version}`);
    const conn = await tcpConnect(host, port, connectTimeoutMs);
    try {
        if (version === 'v1') await handshakeV1(conn, password, ioTimeoutMs);
        else await handshakeV2(conn, password, ioTimeoutMs);
        return new Session(conn.socket, conn.reader, ioTimeoutMs);
    } catch (err) {
        conn.socket.destroy();
        throw err;
    }
}

module.exports = {
    SIGNATURE, VERSION, TYPE, STATUS_TEXT, EscvpError,
    buildPacket, parsePacket, digestFor, openSession,
};
