'use strict';
// Catalog of every ESC/VP21 get command from the spec (plus observed/undocumented ones) and reply interpretation.

const ONOFF = (on, off) => ({ ON: on, OFF: off });

const SOURCE_VALUES = {
    '10': 'Input 1 (D-Sub)', '11': 'Input 1 (RGB)', '14': 'Input 1 (Component)',
    '20': 'Input 2', '21': 'Input 2 (RGB)', '24': 'Input 2 (Component)',
    '30': 'Input 3 (DVI-D/HDMI)', '31': 'Input 3 (RGB)', '33': 'Input 3 (RGB-Video)',
    '34': 'Input 3 (YCbCr)', '35': 'Input 3 (YPbPr)',
    '40': 'Video', '41': 'Video (RCA)', '42': 'Video (S)', '45': 'Video1 (BNC)', '50': 'EasyMP',
    'B0': 'Input 4 (BNC)', 'B1': 'Input 4 (RGB)', 'B2': 'Input 4 (YCbCr)', 'B3': 'Input 4 (YPbPr)',
    'B4': 'Input 4 (Component)',
};

const ipOk = s => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
const onOff = s => (s === 'ON' ? true : s === 'OFF' ? false : null);
const mac = raw => (/^[0-9A-Fa-f]{12}$/.test(raw) ? raw.match(/.{2}/g).join(':').toUpperCase() : raw);

function netConfig(parts) {
    const [dhcp, ip, subnet, gateway] = parts;
    return { dhcp: onOff(dhcp), ip, subnet, gateway };
}

function netDisplay(c) {
    return `DHCP: ${c.dhcp === null ? '?' : c.dhcp ? 'on' : 'off'}, IP: ${c.ip}, Subnet: ${c.subnet}, Gateway: ${c.gateway}`;
}

const raw = value => ({ value, display: value });

// Custom parsers return { value, display, raw? } or null when the reply is malformed (-> raw fallback).
const PARSERS = {
    mac: r => ({ value: mac(r), display: mac(r) }),

    netcnf: r => {
        const p = r.split(/\s+/);
        if (p.length < 4 || !ipOk(p[1])) return null;
        const value = netConfig(p);
        return { value, display: netDisplay(value) };
    },

    dns: r => {
        const [primary, secondary] = r.split(/\s+/);
        if (!primary) return null;
        return { value: { primary, secondary: secondary || null }, display: `Primary: ${primary}, Secondary: ${secondary || '-'}` };
    },

    sourcelist: r => {
        const t = r.split(/\s+/).filter(Boolean);
        const value = [];
        for (let i = 0; i + 1 < t.length; i += 2) value.push({ code: t[i].toUpperCase(), name: t[i + 1].replace(/\^/g, ' ') });
        return { value, display: value.map(s => `${s.name} (${s.code})`).join(', ') };
    },

    lumconst: r => {
        const [mode, level] = r.split(/\s+/);
        if (level === undefined) return null;
        const value = { enabled: mode === '01', level: Number(level) };
        return { value, display: `${value.enabled ? 'On' : 'Off'}, Level: ${value.level}` };
    },

    wlcnf: r => {
        const p = r.split(/\s+/);
        if (p.length < 5 || !ipOk(p[1])) return null;
        const flags = parseInt(p[4], 16);
        const value = { ...netConfig(p), adHoc: !!(flags & 1), wepKeyValid: !!(flags & 2), essid: null };
        let idx = 5;
        if (flags & 4) value.essid = p[idx++] ?? null;
        // The WEP key (p[idx]) is deliberately dropped: the API is unauthenticated.
        const redacted = [...p.slice(0, idx)].join(' ');
        const display = `${netDisplay(value)}${value.essid ? `, ESSID: ${value.essid}` : ''}${value.adHoc ? ', Ad-Hoc' : ''}`;
        return { value, display, raw: flags & 2 ? `${redacted} <redacted>` : r };
    },

    wlcnfs: r => {
        const p = r.split(/\s+/);
        if (p.length < 5 || !ipOk(p[1])) return null;
        const opts = parseInt(p[4], 16);
        const value = { ...netConfig(p), adHoc: !!(opts & 1), essid: opts & 2 ? p.slice(5).join(' ') || null : null };
        return { value, display: `${netDisplay(value)}${value.essid ? `, ESSID: ${value.essid}` : ''}${value.adHoc ? ', Ad-Hoc' : ''}` };
    },

    wlsec: r => {
        if (!/^[0-9A-Fa-f]{6}$/.test(r)) return null;
        const enc = { 0: 'None', 1: 'WEP', 2: 'TKIP', 3: 'CKIP', 4: 'AES' };
        const key = { 0: 'None', 1: '64-bit', 2: '128-bit', 3: '152-bit' };
        const eap = { '00': 'None', '01': 'Shared key', '02': 'TTLS', '03': 'TLS', '04': 'LEAP', '05': 'MD5', '06': 'PEAP' };
        const auth = { '00': 'None', '01': '802.1x (RADIUS)', '02': 'WPA', '03': 'WPA2' };
        const u = r.toUpperCase();
        const value = {
            encryption: enc[u[0]] ?? `Reserved (${u[0]})`,
            keyLength: key[u[1]] ?? `Reserved (${u[1]})`,
            eap: eap[u.slice(2, 4)] ?? `Reserved (${u.slice(2, 4)})`,
            authentication: auth[u.slice(4, 6)] ?? `Reserved (${u.slice(4, 6)})`,
        };
        return { value, display: `Encryption: ${value.encryption}, Key: ${value.keyLength}, EAP: ${value.eap}, Auth: ${value.authentication}` };
    },

    pwstatus: r => {
        const fields = r.split(/\s+/).filter(Boolean);
        return { value: fields, display: fields.join(' ') };
    },

    ver: r => {
        const [active, ...rest] = r.split('VER=');
        const banks = rest.filter(b => b && !/^-+$/.test(b));
        return { value: { active: active || null, otherBanks: banks }, display: [active, ...banks].filter(Boolean).join(', ') };
    },

    lamps: r => {
        const n = r.split(/\s+/).map(Number);
        if (n.length < 2 || n.some(Number.isNaN)) return null;
        const value = [];
        for (let i = 0; i + 1 < n.length; i += 2) value.push({ normalHours: n[i], ecoHours: n[i + 1] });
        return { value, display: value.map((l, i) => `Source ${i + 1}: ${l.normalHours}h normal / ${l.ecoHours}h eco`).join(', ') };
    },
};

const get = (cmd, o) => ({ cmd, query: `${cmd}?`, poll: 'fast', documented: true, ...o });
const enumCmd = (cmd, category, description, values, o) => get(cmd, { category, description, type: 'enum', values, ...o });
const boolCmd = (cmd, category, description, on, off, o) => get(cmd, { category, description, type: 'bool', labels: ONOFF(on, off), ...o });
const numCmd = (cmd, category, description, unit, o) => get(cmd, { category, description, type: 'number', unit, ...o });
const strCmd = (cmd, category, description, o) => get(cmd, { category, description, type: 'string', ...o });
const customCmd = (cmd, category, description, parser, o) => get(cmd, { category, description, type: 'custom', parser, ...o });

const INFERRED = { documented: false, note: 'Get form inferred from the documented step-parameter set command.' };

// Array order is polling order; SOURCELIST precedes SOURCE so model-specific source names are available.
const COMMANDS = [
    // Power & status
    enumCmd('PWR', 'Power & Status', 'Power state', {
        '00': 'Standby (network off)', '01': 'Power on', '02': 'Warm up', '03': 'Cooling down',
        '04': 'Standby (network on)', '05': 'Abnormal standby',
    }),
    customCmd('PWSTATUS', 'Power & Status', 'Power status (extended)', 'pwstatus', { documented: false, note: 'Observed in captures; field meanings unknown.' }),
    enumCmd('SIGNAL', 'Power & Status', 'Signal state', { '00': 'No signal', '01': 'Signal detected', 'FF': 'Unsupported signal' }),
    enumCmd('ERR', 'Power & Status', 'Error code', {
        '00': 'No error', '01': 'Fan error', '03': 'Lamp failure at power on', '04': 'High internal temperature error',
        '06': 'Lamp error', '07': 'Lamp cover open', '08': 'Cinema filter error',
        '09': 'Electric dual-layered capacitor disconnected', '0A': 'Auto iris error', '0B': 'Subsystem error',
        '0C': 'Low air flow error', '0D': 'Air filter air flow sensor error', '0E': 'Power supply unit error (ballast)',
    }),

    // Input
    customCmd('SOURCELIST', 'Input', 'Available input sources', 'sourcelist', { poll: 'slow' }),
    enumCmd('SOURCE', 'Input', 'Input source', SOURCE_VALUES),
    enumCmd('AUDIO', 'Input', 'Audio input source', { '01': 'Audio1', '02': 'Audio2', '03': 'USB' }),

    // Image
    enumCmd('ASPECT', 'Image', 'Aspect ratio', {
        '00': 'Normal', '10': '4:3', '12': '4:3 (zoom)', '20': '16:9', '21': '16:9 (up)', '22': '16:9 (down)',
        '30': 'Auto', '40': 'Full', '50': 'Zoom', '60': 'Through',
    }),
    enumCmd('CMODE', 'Image', 'Color mode', {
        '01': 'sRGB', '02': 'Normal', '03': 'Meeting/Text', '04': 'Presentation', '05': 'Theater',
        '06': 'Amusement/Living room/Game', '08': 'Dynamic/Sports', '10': 'Customized', '11': 'Black board', '14': 'Photo',
    }),
    enumCmd('LUMINANCE', 'Image', 'Brightness level', { '00': 'High', '01': 'Low' }),
    customCmd('LUMCONST', 'Image', 'Constant brightness mode', 'lumconst'),
    numCmd('BRIGHT', 'Image', 'Brightness', '', INFERRED),
    numCmd('CONTRAST', 'Image', 'Contrast', '', INFERRED),
    numCmd('TINT', 'Image', 'Tint', '', INFERRED),

    // Audio
    numCmd('VOL', 'Audio', 'Volume', '', INFERRED),
    numCmd('TONEH', 'Audio', 'Treble', '', INFERRED),
    numCmd('TONEL', 'Audio', 'Bass', '', INFERRED),

    // Controls
    boolCmd('MUTE', 'Controls', 'A/V mute', 'Muted', 'Not muted'),
    enumCmd('MSEL', 'Controls', 'A/V mute screen', { '00': 'Black screen', '01': 'Blue screen', '02': 'User logo' }),
    boolCmd('FREEZE', 'Controls', 'Freeze', 'Frozen', 'Not frozen'),
    enumCmd('CCAP', 'Controls', 'Closed caption mode', {
        '00': 'Off', '11': 'CC1', '12': 'CC2', '13': 'CC3', '14': 'CC4', '21': 'TEXT1', '22': 'TEXT2', '23': 'TEXT3', '24': 'TEXT4',
    }),
    strCmd('MENUINFO', 'Controls', 'Info menu (all data)', {
        query: 'MENUINFO? 00', poll: 'slow', documented: false, note: 'Parameter form "00" (all data) inferred from the spec table.',
    }),

    // Projection
    boolCmd('AUTOKEYSTONE', 'Projection', 'Auto keystone', 'On', 'Off'),
    boolCmd('HREVERSE', 'Projection', 'Rear projection', 'Rear on', 'Rear off'),
    boolCmd('VREVERSE', 'Projection', 'Ceiling projection', 'Ceiling on', 'Ceiling off'),
    numCmd('ZOOM', 'Projection', 'E-Zoom', ''),
    numCmd('VKEYSTONE', 'Projection', 'Vertical keystone', '', INFERRED),
    numCmd('HKEYSTONE', 'Projection', 'Horizontal keystone', '', INFERRED),

    // Maintenance
    numCmd('LAMP', 'Maintenance', 'Lamp hours', 'h', { poll: 'slow' }),
    numCmd('ONTIME', 'Maintenance', 'Operation time', 'h', { poll: 'slow' }),
    numCmd('FILTER', 'Maintenance', 'Filter time', 'h', { poll: 'slow' }),
    boolCmd('FLWARNING', 'Maintenance', 'Filter warning', 'Warning active', 'No warning'),
    customCmd('LAMPS', 'Maintenance', 'Light source usage hours', 'lamps', { poll: 'slow', documented: false, note: 'Observed in captures; field count may vary by model.' }),
    customCmd('VER', 'Maintenance', 'Firmware version', 'ver', { poll: 'slow', documented: false, note: 'Observed in captures.' }),

    // Device info
    strCmd('SNO', 'Device Info', 'Serial number', { poll: 'slow' }),
    strCmd('IMNWPNAME', 'Device Info', 'Projector name (IM)', { poll: 'slow' }),
    strCmd('NWPNAME', 'Device Info', 'Projector name', { poll: 'slow' }),

    // Wired network
    customCmd('NWMAC', 'Network', 'Wired MAC address', 'mac', { poll: 'slow' }),
    customCmd('NWCNF', 'Network', 'Wired network configuration', 'netcnf', { poll: 'slow' }),
    boolCmd('NWIPDISP', 'Network', 'Wired IP display on projector', 'Displayed', 'Hidden', { poll: 'slow' }),
    customCmd('NWDNS', 'Network', 'Wired DNS servers', 'dns', { poll: 'slow' }),
    enumCmd('NWIF', 'Network', 'Active network interface', { '00': 'Wired LAN', '01': '802.11b', '02': '802.11a', '03': '802.11g' }, { poll: 'slow' }),
    enumCmd('NWPRIMIF', 'Network', 'Priority network interface', { '0': 'Wired LAN', '1': 'Wireless LAN' }, { poll: 'slow' }),

    // Wireless network
    customCmd('NWWLMAC', 'Wireless', 'Wireless MAC address', 'mac', { poll: 'slow' }),
    boolCmd('NWWLIPDISP', 'Wireless', 'Wireless IP display on projector', 'Displayed', 'Hidden', { poll: 'slow' }),
    customCmd('NWWLCNF', 'Wireless', 'Wireless network configuration', 'wlcnf', { poll: 'slow' }),
    customCmd('NWWLCNFS', 'Wireless', 'Wireless network configuration (802.1x)', 'wlcnfs', { poll: 'slow' }),
    customCmd('NWWLSEC', 'Wireless', 'Wireless security', 'wlsec', { poll: 'slow' }),
    customCmd('NWWLDNS', 'Wireless', 'Wireless DNS servers', 'dns', { poll: 'slow' }),
    numCmd('NWESSDISP', 'Wireless', 'ESSID display', '', { poll: 'slow', documented: false, note: 'Observed in captures; value range unclear.' }),
];

const BY_NAME = new Map(COMMANDS.map(c => [c.cmd, c]));

/**
 * Classifies a raw reply ("CMD=value" or "ERR") for a command.
 * Returns { status: 'ok'|'unsupported'|'error', raw, value, display, error }.
 */
function interpretReply(def, reply, ctx = {}) {
    const text = reply.replace(/^[\s:]+/, '').trim();
    if (text === 'ERR') return { status: 'unsupported' };
    if (!text) return { status: 'error', error: 'Empty reply' };
    const prefix = `${def.cmd}=`;
    if (!text.startsWith(prefix)) return { status: 'error', error: `Unexpected reply: ${text.slice(0, 80)}` };
    const value = text.slice(prefix.length).trim();
    return { status: 'ok', raw: value, ...interpretValue(def, value, ctx) };
}

function interpretValue(def, value, ctx) {
    switch (def.type) {
        case 'enum': {
            const code = value.toUpperCase();
            let values = def.values;
            if (def.cmd === 'SOURCE' && ctx.sources) values = { ...values, ...ctx.sources };
            return { value: code, display: values[code] ?? `Unknown (${value})` };
        }
        case 'bool': {
            const v = value.toUpperCase();
            return { value: onOff(v), display: def.labels[v] ?? `Unknown (${value})` };
        }
        case 'number': {
            const n = Number(value);
            if (value === '' || Number.isNaN(n)) return raw(value);
            return { value: n, display: def.unit ? `${n} ${def.unit}` : String(n) };
        }
        case 'custom': {
            const parsed = PARSERS[def.parser](value);
            return parsed ?? raw(value);
        }
        default:
            return raw(value);
    }
}

function sourceMapFrom(sourceListValue) {
    if (!Array.isArray(sourceListValue)) return undefined;
    return Object.fromEntries(sourceListValue.map(s => [s.code, s.name]));
}

function catalog() {
    return COMMANDS.map(({ cmd, query, category, description, type, poll, documented, note }) => ({
        command: cmd, query, category, description, type, poll, documented, note: note ?? null,
    }));
}

module.exports = { COMMANDS, BY_NAME, interpretReply, sourceMapFrom, catalog };
