'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.ESCVP_LOG = 'silent';
const { openSession, EscvpError } = require('../src/protocol');
const { COMMANDS, BY_NAME, interpretReply } = require('../src/commands');
const { Config } = require('../src/config');
const { Projector } = require('../src/projector');
const { log } = require('../src/log');
const { createFakeProjector } = require('./fake-projector');

const REPLIES = {
    PWR: '01', SOURCE: '30', SOURCELIST: '30 HDMI1 A0 HDMI2', SNO: 'ABC123', NWPNAME: 'Room 1',
    NWMAC: 'F82551D588C7', NWCNF: 'ON 0.0.0.0 0.0.0.0 0.0.0.0', MUTE: 'OFF', LAMP: '123',
    NWWLCNF: 'OFF 10.0.0.2 255.255.255.0 10.0.0.1 6 Net 0102030405060708090a0b0c0d',
};

test('command parsing', () => {
    const r = interpretReply(BY_NAME.get('NWMAC'), 'NWMAC=F82551D588C7\r');
    assert.strictEqual(r.value, 'F8:25:51:D5:88:C7');
    assert.strictEqual(interpretReply(BY_NAME.get('PWR'), ':ERR').status, 'unsupported');
    assert.strictEqual(interpretReply(BY_NAME.get('MUTE'), 'MUTE=ON').value, true);
    const src = interpretReply(BY_NAME.get('SOURCELIST'), 'SOURCELIST=30 HDMI1 56 Screen^Mirroring1');
    assert.deepStrictEqual(src.value[1], { code: '56', name: 'Screen Mirroring1' });
    const wl = interpretReply(BY_NAME.get('NWWLCNF'), `NWWLCNF=${REPLIES.NWWLCNF}`);
    assert.strictEqual(wl.value.essid, 'Net');
    assert.ok(!JSON.stringify(wl).includes('0102030405'));
    assert.strictEqual(interpretReply(BY_NAME.get('VER'), 'VER=3X01VER=----VER=----').value.active, '3X01');
    assert.ok(COMMANDS.every(c => /^[A-Z]+\?( \d+)?$/.test(c.query)));
});

test('session refuses non-query commands', async () => {
    const fake = await createFakeProjector({});
    const s = await openSession({ host: '127.0.0.1', port: fake.port, version: 'v2' });
    await assert.rejects(s.query('PWR ON'), e => e.kind === 'command');
    s.close();
    fake.server.close();
});

test('v2 and v1 authentication', async () => {
    const fake = await createFakeProjector({ password: 'secret', replies: REPLIES });
    for (const version of ['v2', 'v1']) {
        const s = await openSession({ host: '127.0.0.1', port: fake.port, version, password: 'secret' });
        assert.strictEqual(await s.query('PWR?'), 'PWR=01');
        s.close();
        await assert.rejects(
            openSession({ host: '127.0.0.1', port: fake.port, version, password: 'wrong' }),
            e => e instanceof EscvpError && e.kind === 'auth',
        );
    }
    fake.server.close();
});

test('projector negotiates credentials/version, saves them and records state', async () => {
    const fake = await createFakeProjector({ versions: ['v1'], password: 'admin', replies: REPLIES });
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'escvp-')), 'config.json');
    const config = new Config(file).load();
    config.data.protocol.port = fake.port;
    config.data.credentials = ['', 'nope', 'admin'];
    config.data.polling.fastIntervalMs = 60000;

    const p = new Projector('127.0.0.1', { config, log });
    await p._cycle();

    assert.strictEqual(p.connection.status, 'online');
    assert.strictEqual(p.connection.protocolVersion, 'v1');
    const saved = JSON.parse(fs.readFileSync(file, 'utf8')).projectors['127.0.0.1'];
    assert.deepStrictEqual([saved.version, saved.password], ['v1', 'admin']);
    assert.strictEqual(p.commands.PWR.display, 'Power on');
    assert.strictEqual(p.commands.SOURCE.display, 'HDMI1');
    assert.strictEqual(p.commands.ZOOM.status, 'unsupported');
    assert.strictEqual(p.summary().name, 'Room 1');
    assert.ok(fake.queries.every(q => q.endsWith('?') || q.includes('? ')));

    // Second cycle reuses the saved settings with a single handshake (no negotiation).
    fake.queries.length = 0;
    await p._cycle();
    assert.strictEqual(p.connection.status, 'online');
    fake.server.close();
});

test('falls back to v1 when the projector drops the connection on v2', async () => {
    const fake = await createFakeProjector({ versions: ['v1'], dropUnsupported: true, replies: REPLIES });
    const config = new Config(path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'escvp-')), 'c.json')).load();
    config.data.protocol.port = fake.port;
    const p = new Projector('127.0.0.1', { config, log });
    await p._cycle();
    assert.strictEqual(p.connection.status, 'online');
    assert.strictEqual(p.connection.protocolVersion, 'v1');
    fake.server.close();
});

test('all credentials rejected -> auth-failed', async () => {
    const fake = await createFakeProjector({ password: 'hidden' });
    const config = new Config(path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'escvp-')), 'c.json')).load();
    config.data.protocol.port = fake.port;
    const p = new Projector('127.0.0.1', { config, log });
    await p._cycle();
    assert.strictEqual(p.connection.status, 'auth-failed');
    assert.strictEqual(config.getProjectorSettings('127.0.0.1'), null);
    fake.server.close();
});
