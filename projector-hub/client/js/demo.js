'use strict';
// Synthetic fleet for UI development: open the client with ?demo=50.

let demoFleet = null;
const demoLog = [];

function demoRng(seed) {
    return () => {
        seed |= 0; seed = (seed + 0x6D2B79F5) | 0;
        let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

function demoCmd(command, category, description, raw, display, value = raw) {
    const now = new Date().toISOString();
    return { command, query: `${command}?`, category, description, documented: true, status: 'ok', raw: String(raw), value, display, error: null, updatedAt: now, lastOkAt: now, changedAt: now };
}

function demoBuild(f) {
    const now = new Date().toISOString();
    const c = {};
    const add = (...a) => { c[a[0]] = demoCmd(...a); };
    const unsupported = (command, category, description) => {
        c[command] = { ...demoCmd(command, category, description, '', ''), status: 'unsupported', raw: null, value: null, display: null, lastOkAt: null };
    };
    const PWR = { on: ['01', 'Power on'], warm: ['02', 'Warm up'], cool: ['03', 'Cooling down'], standby: ['04', 'Standby (network on)'] }[f.pwr];
    const live = f.pwr === 'on';
    if (f.online) {
        add('PWR', 'Power & Status', 'Power state', PWR[0], PWR[1]);
        add('LAMP', 'Maintenance', 'Lamp hours', f.lamp, `${f.lamp} h`, f.lamp);
        add('ONTIME', 'Maintenance', 'Operation time', f.ontime, `${f.ontime} h`, f.ontime);
        add('SNO', 'Device Info', 'Serial number', f.serial, f.serial);
        add('NWPNAME', 'Device Info', 'Projector name', f.name, f.name);
        add('NWMAC', 'Network', 'Wired MAC address', f.mac, f.mac);
        add('VER', 'Maintenance', 'Firmware version', f.fw, f.fw, { active: f.fw, otherBanks: [] });
        add('NWCNF', 'Network', 'Wired network configuration', '', `DHCP: on, IP: ${f.host}`, { dhcp: true, ip: f.host, subnet: '255.255.0.0', gateway: '10.1.255.254' });
        add('SOURCELIST', 'Input', 'Available input sources', '', 'HDMI1 (30), HDMI2 (A0), Computer1 (10)', [{ code: '30', name: 'HDMI1' }, { code: 'A0', name: 'HDMI2' }, { code: '10', name: 'Computer1' }]);
        if (live) {
            add('SOURCE', 'Input', 'Input source', f.src[0], f.src[1]);
            add('SIGNAL', 'Power & Status', 'Signal state', f.signal ? '01' : '00', f.signal ? 'Signal detected' : 'No signal');
            add('ERR', 'Power & Status', 'Error code', f.err ? '06' : '00', f.err ? 'Lamp error' : 'No error');
            add('MUTE', 'Controls', 'A/V mute', f.mute ? 'ON' : 'OFF', f.mute ? 'Muted' : 'Not muted', f.mute);
            add('FREEZE', 'Controls', 'Freeze', 'OFF', 'Not frozen', false);
            add('ASPECT', 'Image', 'Aspect ratio', '30', 'Auto');
            add('CMODE', 'Image', 'Color mode', '04', 'Presentation');
            add('VOL', 'Audio', 'Volume', 12, '12', 12);
        } else {
            ['SOURCE', 'SIGNAL', 'ERR', 'MUTE', 'FREEZE', 'ASPECT', 'CMODE', 'VOL'].forEach(n => unsupported(n, 'Other', n));
        }
    }
    const status = f.online ? 'online' : f.conn;
    return {
        id: f.host, host: f.host, name: f.name, model: null, serialNumber: f.online ? f.serial : null, macAddress: f.online ? f.mac : null, firmware: f.online ? f.fw : null,
        online: f.online,
        connection: { status, protocolVersion: f.online ? 'v2' : null, error: f.online ? null : f.conn === 'refused' ? 'V1 connect: 0x45 Request not allowed' : 'Connect timed out', lastAttemptAt: now, lastConnectedAt: f.online ? now : null, consecutiveFailures: f.online ? 0 : 3 },
        power: null, lastPollAt: now, lastPollDurationMs: 180 + Math.round(f.n * 3),
        discovery: { name: f.name, imType: f.model, commandType: 'ESC/VP21 v1.0', via: 'udp-hello', lastSeenAt: now },
        commands: c,
    };
}

function demoProjectors(n) {
    if (!demoFleet) {
        const rnd = demoRng(42);
        const pick = a => a[Math.floor(rnd() * a.length)];
        demoFleet = Array.from({ length: n }, (_, i) => {
            const r = rnd();
            const online = r < 0.86;
            return {
                n: i, host: `10.1.${193 + (i % 8)}.${30 + i * 3 % 200}`, name: `Room ${'ABCD'[i % 4]}${100 + i}`, model: pick(['Type 0x36', 'Type 0x38', 'Type 0x38', 'Type 0x41']),
                online, conn: r < 0.92 ? 'unreachable' : r < 0.97 ? 'refused' : 'auth-failed',
                pwr: !online ? 'standby' : r < 0.28 ? 'on' : r < 0.3 ? 'warm' : r < 0.31 ? 'cool' : 'standby',
                lamp: Math.round(rnd() * 5000), ontime: Math.round(rnd() * 9000), serial: `XCB${String(94800000 + i * 37)}`,
                mac: [...Array(6)].map((_, k) => (k === 0 ? 'F8' : Math.floor(rnd() * 256).toString(16).padStart(2, '0')).toUpperCase()).join(':'),
                fw: pick(['54011864JFWWV162', '54011864JFWWV162', '54011864JFWWV150', '3X011864JFWWV116']),
                src: pick([['30', 'HDMI1'], ['A0', 'HDMI2'], ['10', 'Computer1']]), signal: rnd() > 0.2, mute: rnd() > 0.85, err: rnd() > 0.95,
            };
        });
    } else if (Math.random() < 0.5) {
        const f = demoFleet[Math.floor(Math.random() * demoFleet.length)];
        if (f.online) {
            const from = f.pwr;
            f.pwr = from === 'on' ? 'standby' : 'on';
            demoLog.unshift({ host: f.host, name: f.name, type: 'command', command: 'PWR', at: new Date().toISOString(), from: { status: 'ok', display: from }, to: { status: 'ok', display: f.pwr } });
        }
    }
    return demoFleet.map(demoBuild);
}

const demoActivity = () => demoLog.slice(0, 50);
