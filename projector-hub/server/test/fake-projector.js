'use strict';
// Minimal ESC/VP.net + ESC/VP21 projector emulator for tests.
const net = require('net');
const crypto = require('crypto');
const { parsePacket, buildPacket, digestFor } = require('../src/protocol');

function createFakeProjector({ versions = ['v1', 'v2'], password = '', replies = {}, dropUnsupported = false } = {}) {
    const nonce = crypto.randomBytes(16);
    const queries = [];

    const server = net.createServer(sock => {
        let buf = Buffer.alloc(0);
        let phase = 'hello';
        const reply = (version, status, headers = []) => {
            const p = buildPacket(version, 0x03, headers);
            p[14] = status;
            sock.write(p);
        };
        const fail = (version, status) => {
            if (dropUnsupported && status === 0x55) return sock.destroy();
            reply(version, status);
            sock.end();
        };

        const onPacket = pkt => {
            if (pkt.version === 0x20) {
                if (!versions.includes('v2')) return fail(0x20, 0x55);
                if (phase === 'hello') {
                    phase = 'proof';
                    return reply(0x20, 0x41, [{ id: 1, attribute: 3, data: nonce }]);
                }
                const d = Buffer.concat([pkt.headers[0].data, pkt.headers[1].data]);
                if (!d.equals(digestFor(password, nonce))) return fail(0x20, 0x43);
                phase = 'command';
                return reply(0x20, 0x20);
            }
            if (!versions.includes('v1')) return fail(0x10, 0x55);
            const sent = pkt.headers.length ? pkt.headers[0].data.toString('latin1').replace(/\0+$/, '') : '';
            if (sent !== password) return fail(0x10, sent ? 0x43 : 0x41);
            phase = 'command';
            reply(0x10, 0x20);
        };

        const pump = () => {
            for (;;) {
                if (phase === 'command') {
                    const i = buf.indexOf(13);
                    if (i < 0) return;
                    const line = buf.subarray(0, i).toString('ascii');
                    buf = buf.subarray(i + 1);
                    queries.push(line);
                    const cmd = line.replace(/\?.*$/, '');
                    sock.write(cmd in replies ? `${cmd}=${replies[cmd]}\r:` : 'ERR\r:');
                    continue;
                }
                if (buf.length < 16 || buf.length < 16 + 18 * buf[15]) return;
                const need = 16 + 18 * buf[15];
                const pkt = parsePacket(buf.subarray(0, need));
                buf = buf.subarray(need);
                onPacket(pkt);
            }
        };
        sock.on('data', d => {
            buf = Buffer.concat([buf, d]);
            pump();
        });
        sock.on('error', () => {});
    });

    return new Promise(resolve => {
        server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, queries }));
    });
}

module.exports = { createFakeProjector };
