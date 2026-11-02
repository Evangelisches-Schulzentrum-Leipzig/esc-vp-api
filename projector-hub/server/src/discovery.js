'use strict';
// UDP HELLO discovery (ESC/VP.net v1, type 0x01) across all local IPv4 interfaces.
const dgram = require('dgram');
const os = require('os');
const { VERSION, TYPE, buildPacket, parsePacket } = require('./protocol');

const IM_TYPES = {
    0x0c: 'Type D', 0x20: 'EMP/PL-735', 0x21: 'Type C/E', 0x22: 'Type F', 0x23: 'Type G', 0x30: 'Type B',
    0x40: 'Type H', 0x41: 'Type I', 0x42: 'Type J', 0x50: 'Type K',
};
const COMMAND_TYPES = { 0x16: 'ESC/VP Level 6', 0x21: 'ESC/VP21 v1.0' };

function localInterfaces() {
    const out = [];
    for (const addrs of Object.values(os.networkInterfaces())) {
        for (const a of addrs ?? []) {
            if (a.family !== 'IPv4' || a.internal) continue;
            const ip = a.address.split('.').map(Number);
            const mask = a.netmask.split('.').map(Number);
            out.push({ address: a.address, broadcast: ip.map((b, i) => (b | (~mask[i] & 0xff))).join('.') });
        }
    }
    return out;
}

function headerText(packet, id) {
    const h = packet.headers.find(x => x.id === id);
    return h ? h.data.toString('ascii').replace(/[\0 ]+$/, '') : null;
}

function parseHello(data) {
    const p = parsePacket(data);
    if (p.type !== TYPE.HELLO) return null;
    const im = p.headers.find(h => h.id === 0x04);
    const cmd = p.headers.find(h => h.id === 0x05);
    return {
        name: headerText(p, 0x03),
        imType: im ? (IM_TYPES[im.attribute] ?? `0x${im.attribute.toString(16)}`) : null,
        commandType: cmd ? (COMMAND_TYPES[cmd.attribute] ?? `0x${cmd.attribute.toString(16)}`) : null,
        status: p.status,
    };
}

function bindSocket(address, port) {
    return new Promise((resolve, reject) => {
        const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
        socket.once('error', reject);
        socket.bind({ address, port }, () => {
            socket.off('error', reject);
            socket.setBroadcast(true);
            resolve(socket);
        });
    });
}

/** Resolves to a map ip -> { name, imType, commandType, status }. */
async function discover({ port = 3629, timeoutMs = 3000, broadcastAddresses = [], staticHosts = [], log }) {
    const ifaces = localInterfaces();
    const localAddrs = new Set(ifaces.map(i => i.address));
    const found = new Map();
    const hello = buildPacket(VERSION.v1, TYPE.HELLO);

    const bindTargets = ifaces.length ? ifaces : [{ address: '0.0.0.0', broadcast: null }];
    const bound = [];
    for (const iface of bindTargets) {
        try {
            // Prefer the well-known port (some firmware replies to 3629), fall back to an ephemeral one.
            bound.push({ iface, socket: await bindSocket(iface.address, port).catch(() => bindSocket(iface.address, 0)) });
        } catch (err) {
            log?.warn(`Discovery: cannot bind ${iface.address}: ${err.message}`);
        }
    }
    const sockets = bound.map(b => b.socket);

    sockets.forEach(socket => {
        socket.on('error', err => log?.warn(`Discovery socket error: ${err.message}`));
        socket.on('message', (msg, rinfo) => {
            if (localAddrs.has(rinfo.address) || found.has(rinfo.address)) return;
            try {
                const info = parseHello(msg);
                if (info) found.set(rinfo.address, info);
            } catch {
                // Not an ESC/VP.net packet; ignore.
            }
        });
    });

    bound.forEach(({ iface, socket }) => {
        const targets = new Set([...(iface.broadcast ? [iface.broadcast] : []), '255.255.255.255', ...broadcastAddresses, ...staticHosts]);
        for (const target of targets) socket.send(hello, port, target, err => err && log?.warn(`Discovery send to ${target} failed: ${err.message}`));
    });

    await new Promise(resolve => setTimeout(resolve, timeoutMs));
    sockets.forEach(s => s.close());
    return found;
}

module.exports = { discover, localInterfaces };
