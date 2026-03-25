const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Load .env file without external packages
const envPath = path.resolve(__dirname, '.env');
if (fs.existsSync(envPath)) {
    fs.readFileSync(envPath, 'utf-8')
        .split('\n')
        .filter(line => line.trim() && !line.startsWith('#'))
        .forEach(line => {
            const idx = line.indexOf('=');
            if (idx !== -1) {
                const key = line.slice(0, idx).trim();
                const value = line.slice(idx + 1).trim().replace(/^["']|["']$/g, '');
                if (!process.env[key]) process.env[key] = value;
            }
        });
}

// ==================== Configuration ====================
const PROJECTOR_HOST = process.env.PROJECTOR_HOST || '10.101.10.38';
const PROJECTOR_PORT = parseInt(process.env.PROJECTOR_PORT || '80', 10);
const USERNAME = process.env.PROJECTOR_USER || 'EPSONWEB';
const PASSWORD = process.env.PROJECTOR_PASSWORD || 'admin';
const DASHBOARD_PORT = parseInt(process.env.DASHBOARD_PORT || '3000', 10);
const POLL_INTERVAL = parseInt(process.env.POLL_INTERVAL || '10000', 10);

// ==================== ESC/VP21 GET Command Definitions ====================
const GET_COMMANDS = {
    // Power & Status
    'PWR': {
        description: 'Power state',
        category: 'Power & Status',
        values: {
            '00': 'Standby (Network off)',
            '01': 'Power on',
            '02': 'Warm up',
            '03': 'Cooling down',
            '04': 'Standby (Network on)',
            '05': 'Abnormal Standby'
        }
    },
    'SIGNAL': {
        description: 'Signal state',
        category: 'Power & Status',
        values: {
            '00': 'No signal',
            '01': 'Signal detected',
            'FF': 'Unsupported signal'
        }
    },
    'ERR': {
        description: 'Error code',
        category: 'Power & Status',
        values: {
            '00': 'No error',
            '01': 'Fan error',
            '03': 'Lamp failure at power on',
            '04': 'High internal temperature error',
            '06': 'Lamp error',
            '07': 'Open Lamp cover door error',
            '08': 'Cinema filter error',
            '09': 'Electric dual-layered capacitor disconnected',
            '0A': 'Auto iris error',
            '0B': 'Subsystem Error',
            '0C': 'Low air flow error',
            '0D': 'Air filter air flow sensor error',
            '0E': 'Power supply unit error (Ballast)'
        }
    },

    // Input & Source
    'SOURCE': {
        description: 'Input source',
        category: 'Input',
        values: {
            '10': 'Input 1 (D-Sub)',
            '11': 'Input 1 (RGB)',
            '14': 'Input 1 (Component)',
            '20': 'Input 2',
            '21': 'Input 2 (RGB)',
            '24': 'Input 2 (Component)',
            '30': 'Input 3 (DVI-D/HDMI)',
            '31': 'Input 3 (RGB)',
            '33': 'Input 3 (RGB-Video)',
            '34': 'Input 3 (YCbCr)',
            '35': 'Input 3 (YPbPr)',
            '40': 'Video',
            '41': 'Video (RCA)',
            '42': 'Video (S)',
            '45': 'Video1 (BNC)',
            '50': 'EasyMP',
            'B0': 'Input 4 (BNC)',
            'B1': 'Input 4 (RGB)',
            'B2': 'Input 4 (YCbCr)',
            'B3': 'Input 4 (YPbPr)',
            'B4': 'Input 4 (Component)'
        }
    },
    'SOURCELIST': {
        description: 'Available input sources',
        category: 'Input',
        parse: 'sourcelist'
    },
    'AUDIO': {
        description: 'Audio input source',
        category: 'Input',
        values: {
            '01': 'Audio1',
            '02': 'Audio2',
            '03': 'USB'
        }
    },

    // Image Settings
    'ASPECT': {
        description: 'Aspect ratio',
        category: 'Image',
        values: {
            '00': 'Normal',
            '10': '4:3',
            '12': '4:3 (Zoom)',
            '20': '16:9',
            '21': '16:9 (Up)',
            '22': '16:9 (Down)',
            '30': 'Auto',
            '40': 'Full',
            '50': 'Zoom',
            '60': 'Through'
        }
    },
    'CMODE': {
        description: 'Color mode',
        category: 'Image',
        values: {
            '01': 'sRGB',
            '02': 'Normal',
            '03': 'Meeting/Text',
            '04': 'Presentation',
            '05': 'Theater',
            '06': 'Amusement/Living Room/Game',
            '08': 'Dynamic/Sports',
            '10': 'Customized',
            '11': 'Black Board',
            '14': 'Photo'
        }
    },
    'LUMINANCE': {
        description: 'Brightness level',
        category: 'Image',
        values: {
            '00': 'High',
            '01': 'Low'
        }
    },
    'LUMCONST': {
        description: 'Constant brightness mode',
        category: 'Image',
        parse: 'lumconst'
    },

    // Mute & Freeze
    'MUTE': {
        description: 'A/V Mute state',
        category: 'Controls',
        values: { 'ON': 'Muted', 'OFF': 'Not muted' }
    },
    'MSEL': {
        description: 'A/V Mute screen setting',
        category: 'Controls',
        values: {
            '00': 'Black Screen',
            '01': 'Blue Screen',
            '02': 'User Logo'
        }
    },
    'FREEZE': {
        description: 'Freeze state',
        category: 'Controls',
        values: { 'ON': 'Frozen', 'OFF': 'Not frozen' }
    },

    // Projection & Keystone
    'AUTOKEYSTONE': {
        description: 'Auto Keystone state',
        category: 'Projection',
        values: { 'ON': 'On', 'OFF': 'Off' }
    },
    'HREVERSE': {
        description: 'Rear projection state',
        category: 'Projection',
        values: { 'ON': 'Rear on', 'OFF': 'Rear off' }
    },
    'VREVERSE': {
        description: 'Ceiling projection state',
        category: 'Projection',
        values: { 'ON': 'Ceiling on', 'OFF': 'Ceiling off' }
    },
    'ZOOM': {
        description: 'E-Zoom setting',
        category: 'Projection',
        parse: 'numeric',
        unit: ''
    },

    // Lamp & Filter
    'LAMP': {
        description: 'Lamp hours',
        category: 'Maintenance',
        parse: 'numeric',
        unit: 'h'
    },
    'ONTIME': {
        description: 'Operation time',
        category: 'Maintenance',
        parse: 'numeric',
        unit: 'h'
    },
    'FILTER': {
        description: 'Filter time',
        category: 'Maintenance',
        parse: 'numeric',
        unit: 'h'
    },
    'FLWARNING': {
        description: 'Filter warning state',
        category: 'Maintenance',
        values: { 'ON': 'Warning active', 'OFF': 'No warning' }
    },

    // Closed Captions
    'CCAP': {
        description: 'Closed caption mode',
        category: 'Misc',
        values: {
            '00': 'Off',
            '11': 'CC1',
            '12': 'CC2',
            '13': 'CC3',
            '14': 'CC4',
            '21': 'TEXT1',
            '22': 'TEXT2',
            '23': 'TEXT3',
            '24': 'TEXT4'
        }
    },

    // Device Info
    'SNO': {
        description: 'Serial number',
        category: 'Device Info',
        parse: 'string'
    },
    'IMNWPNAME': {
        description: 'Projector name (IM)',
        category: 'Device Info',
        parse: 'string'
    },
    'NWPNAME': {
        description: 'Projector name',
        category: 'Device Info',
        parse: 'string'
    },

    // Network - Wired
    'NWMAC': {
        description: 'Wired MAC address',
        category: 'Network',
        parse: 'mac'
    },
    'NWCNF': {
        description: 'Wired network configuration',
        category: 'Network',
        parse: 'netcnf'
    },
    'NWIPDISP': {
        description: 'Wired IP display on projector',
        category: 'Network',
        values: { 'ON': 'Displayed', 'OFF': 'Hidden' }
    },
    'NWDNS': {
        description: 'Wired DNS servers',
        category: 'Network',
        parse: 'dns'
    },
    'NWIF': {
        description: 'Active network interface',
        category: 'Network',
        values: {
            '00': 'Wired LAN',
            '01': '802.11b',
            '02': '802.11a',
            '03': '802.11g'
        }
    },
    'NWPRIMIF': {
        description: 'Priority network interface',
        category: 'Network',
        values: {
            '0': 'Wired LAN',
            '1': 'Wireless LAN'
        }
    },

    // Network - Wireless
    'NWWLMAC': {
        description: 'Wireless MAC address',
        category: 'Wireless',
        parse: 'mac'
    },
    'NWWLIPDISP': {
        description: 'Wireless IP display on projector',
        category: 'Wireless',
        values: { 'ON': 'Displayed', 'OFF': 'Hidden' }
    },
    'NWWLCNF': {
        description: 'Wireless network configuration',
        category: 'Wireless',
        parse: 'wlcnf'
    },
    'NWWLCNFS': {
        description: 'Wireless config (802.1x)',
        category: 'Wireless',
        parse: 'wlcnfs'
    },
    'NWWLSEC': {
        description: 'Wireless security',
        category: 'Wireless',
        parse: 'wlsec'
    },
    'NWWLDNS': {
        description: 'Wireless DNS servers',
        category: 'Wireless',
        parse: 'dns'
    },

    // Undocumented (observed)
    'PWSTATUS': {
        description: 'Power status (extended)',
        category: 'Extended',
        parse: 'string'
    },
    'NWESSDISP': {
        description: 'ESSID display',
        category: 'Extended',
        parse: 'string'
    },
    'VER': {
        description: 'Firmware version',
        category: 'Extended',
        parse: 'string'
    },
    'LAMPS': {
        description: 'Light source usage hours',
        category: 'Extended',
        parse: 'lamps'
    }
};

// ==================== Response Parsers ====================
function parseResponse(cmd, raw) {
    const def = GET_COMMANDS[cmd];
    if (!def) return { raw, display: raw };

    const trimmed = raw.trim();

    // Lookup table values
    if (def.values) {
        const display = def.values[trimmed] || `Unknown (${trimmed})`;
        return { raw: trimmed, display };
    }

    // Custom parsers
    switch (def.parse) {
        case 'numeric': {
            const num = parseInt(trimmed, 10);
            const display = isNaN(num) ? trimmed : `${num}${def.unit ? ' ' + def.unit : ''}`;
            return { raw: trimmed, display };
        }
        case 'string':
            return { raw: trimmed, display: trimmed };

        case 'mac': {
            // 12-char hex → colon-separated
            const display = trimmed.length === 12
                ? trimmed.match(/.{2}/g).join(':').toUpperCase()
                : trimmed;
            return { raw: trimmed, display };
        }
        case 'netcnf': {
            // "<DHCP> <IP> <Subnet> <Gateway>"
            const parts = trimmed.split(/\s+/);
            if (parts.length >= 4) {
                return {
                    raw: trimmed,
                    display: `DHCP: ${parts[0]}, IP: ${parts[1]}, Subnet: ${parts[2]}, Gateway: ${parts[3]}`
                };
            }
            return { raw: trimmed, display: trimmed };
        }
        case 'dns': {
            const parts = trimmed.split(/\s+/);
            if (parts.length >= 2) {
                return { raw: trimmed, display: `Primary: ${parts[0]}, Secondary: ${parts[1]}` };
            }
            return { raw: trimmed, display: trimmed };
        }
        case 'sourcelist': {
            // Space-separated pairs: "30 HDMI1 A0 HDMI2 ..."
            const tokens = trimmed.split(/\s+/);
            const sources = [];
            for (let i = 0; i + 1 < tokens.length; i += 2) {
                sources.push(`${tokens[i + 1].replace(/\^/g, ' ')} (${tokens[i]})`);
            }
            return { raw: trimmed, display: sources.join(', ') || trimmed };
        }
        case 'lumconst': {
            // "x1 x2" → mode + brightness level
            const parts = trimmed.split(/\s+/);
            if (parts.length >= 2) {
                const mode = parts[0] === '01' ? 'On' : 'Off';
                return { raw: trimmed, display: `${mode}, Level: ${parseInt(parts[1], 10)}` };
            }
            return { raw: trimmed, display: trimmed };
        }
        case 'wlcnf': {
            // "<DHCP> <IP> <Subnet> <Gateway> <flags> [<ESSID>] [<WEPkey>]"
            const parts = trimmed.split(/\s+/);
            if (parts.length >= 5) {
                let display = `DHCP: ${parts[0]}, IP: ${parts[1]}, Subnet: ${parts[2]}, Gateway: ${parts[3]}`;
                const flags = parseInt(parts[4], 16);
                if (flags & 0x4 && parts.length >= 6) display += `, ESSID: ${parts[5]}`;
                if (flags & 0x1) display += ', Ad-Hoc: On';
                return { raw: trimmed, display };
            }
            return { raw: trimmed, display: trimmed };
        }
        case 'wlcnfs': {
            // "<DHCP> <IP> <Subnet> <Gateway> <Options> <ESSID>"
            const parts = trimmed.split(/\s+/);
            if (parts.length >= 5) {
                let display = `DHCP: ${parts[0]}, IP: ${parts[1]}, Subnet: ${parts[2]}, Gateway: ${parts[3]}`;
                const opts = parseInt(parts[4], 16);
                if (opts & 0x2 && parts.length >= 6) display += `, ESSID: ${parts[5]}`;
                if (opts & 0x1) display += ', Ad-Hoc: On';
                return { raw: trimmed, display };
            }
            return { raw: trimmed, display: trimmed };
        }
        case 'wlsec': {
            // 6-char hex "wxyyzz"
            if (trimmed.length === 6) {
                const encMap = { '0': 'None', '1': 'WEP', '2': 'TKIP', '3': 'CKIP', '4': 'AES' };
                const keyMap = { '0': 'None', '1': '64-bit', '2': '128-bit', '3': '152-bit' };
                const eapMap = { '00': 'None', '01': 'Shared key', '02': 'TTLS', '03': 'TLS', '04': 'LEAP', '05': 'MD5', '06': 'PEAP' };
                const authMap = { '00': 'None', '01': '802.1x (RADIUS)', '02': 'WPA', '03': 'WPA2' };
                const enc = encMap[trimmed[0]] || `Reserved (${trimmed[0]})`;
                const keyLen = keyMap[trimmed[1]] || `Reserved (${trimmed[1]})`;
                const eap = eapMap[trimmed.slice(2, 4)] || `Reserved (${trimmed.slice(2, 4)})`;
                const auth = authMap[trimmed.slice(4, 6)] || `Reserved (${trimmed.slice(4, 6)})`;
                return { raw: trimmed, display: `Encryption: ${enc}, Key: ${keyLen}, EAP: ${eap}, Auth: ${auth}` };
            }
            return { raw: trimmed, display: trimmed };
        }
        case 'lamps': {
            // Space-separated hours per light source
            const parts = trimmed.split(/\s+/).map(Number);
            if (parts.length >= 4) {
                return {
                    raw: trimmed,
                    display: `Source 1: ${parts[0]}h normal / ${parts[1]}h eco, Source 2: ${parts[2]}h normal / ${parts[3]}h eco`
                };
            }
            return { raw: trimmed, display: trimmed };
        }
        default:
            return { raw: trimmed, display: trimmed };
    }
}

// ==================== HTTP Digest Authentication ====================
function parseDigestChallenge(header) {
    const params = {};
    const regex = /(\w+)=(?:"([^"]+)"|([^\s,]+))/g;
    let match;
    while ((match = regex.exec(header)) !== null) {
        params[match[1]] = match[2] || match[3];
    }
    return params;
}

function buildDigestHeader(method, uri, challenge, username, password) {
    const nc = '00000001';
    const cnonce = crypto.randomBytes(16).toString('base64');
    const ha1 = crypto.createHash('md5')
        .update(`${username}:${challenge.realm}:${password}`).digest('hex');
    const ha2 = crypto.createHash('md5')
        .update(`${method}:${uri}`).digest('hex');
    const response = crypto.createHash('md5')
        .update(`${ha1}:${challenge.nonce}:${nc}:${cnonce}:${challenge.qop}:${ha2}`).digest('hex');
    return `Digest username="${username}", realm="${challenge.realm}", ` +
        `nonce="${challenge.nonce}", uri="${uri}", cnonce="${cnonce}", ` +
        `nc=${nc}, qop=${challenge.qop}, response="${response}"`;
}

function httpGet(urlPath) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: PROJECTOR_HOST,
            port: PROJECTOR_PORT,
            path: urlPath,
            method: 'GET',
            headers: { 'User-Agent': 'esc-vp-api/1.0' }
        };

        // First request to get the digest challenge
        const req1 = http.request(options, (res1) => {
            let body1 = '';
            res1.on('data', chunk => body1 += chunk);
            res1.on('end', () => {
                if (res1.statusCode !== 401) {
                    // No auth needed (unlikely but handle it)
                    resolve(body1);
                    return;
                }
                const wwwAuth = res1.headers['www-authenticate'];
                if (!wwwAuth || !wwwAuth.startsWith('Digest')) {
                    reject(new Error('Expected Digest authentication challenge'));
                    return;
                }
                const challenge = parseDigestChallenge(wwwAuth);

                // Second request with digest credentials
                const authHeader = buildDigestHeader('GET', urlPath, challenge, USERNAME, PASSWORD);
                const options2 = { ...options, headers: { ...options.headers, 'Authorization': authHeader } };
                const req2 = http.request(options2, (res2) => {
                    let body2 = '';
                    res2.on('data', chunk => body2 += chunk);
                    res2.on('end', () => {
                        if (res2.statusCode === 200) {
                            resolve(body2);
                        } else {
                            reject(new Error(`HTTP ${res2.statusCode}: ${body2}`));
                        }
                    });
                });
                req2.on('error', reject);
                req2.setTimeout(5000, () => { req2.destroy(new Error('Request timeout')); });
                req2.end();
            });
        });
        req1.on('error', reject);
        req1.setTimeout(5000, () => { req1.destroy(new Error('Request timeout')); });
        req1.end();
    });
}

// ==================== Command Execution ====================
async function queryCommand(cmd) {
    const urlPath = `/api/v01/control/escvp21?cmd=${encodeURIComponent(cmd + '?')}`;
    try {
        const raw = await httpGet(urlPath);
        const parsed = parseResponse(cmd, raw);
        return { cmd, status: 'ok', ...parsed };
    } catch (err) {
        return { cmd, status: 'error', raw: '', display: err.message };
    }
}

async function queryAllCommands() {
    const results = {};
    const cmds = Object.keys(GET_COMMANDS);

    // Query sequentially to avoid overwhelming the projector
    for (const cmd of cmds) {
        results[cmd] = await queryCommand(cmd);
    }

    return results;
}

// ==================== Console Output ====================
function printResults(results) {
    console.log('\n' + '='.repeat(72));
    console.log(`  Epson Projector Status — ${PROJECTOR_HOST} — ${new Date().toLocaleString()}`);
    console.log('='.repeat(72));

    const categories = {};
    for (const [cmd, result] of Object.entries(results)) {
        const cat = GET_COMMANDS[cmd]?.category || 'Other';
        if (!categories[cat]) categories[cat] = [];
        categories[cat].push({ cmd, ...result });
    }

    for (const [cat, items] of Object.entries(categories)) {
        console.log(`\n  [${cat}]`);
        for (const item of items) {
            const desc = GET_COMMANDS[item.cmd]?.description || item.cmd;
            const icon = item.status === 'ok' ? '✓' : '✗';
            console.log(`    ${icon} ${desc.padEnd(30)} ${item.display}`);
        }
    }
    console.log('\n' + '='.repeat(72));
}

// ==================== HTML Dashboard ====================
let latestResults = {};

function escapeHtml(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function buildStatusBadge(cmd, result) {
    if (result.status === 'error') {
        return '<span class="badge error">ERROR</span>';
    }
    if (cmd === 'PWR') {
        const on = result.raw === '01' || result.raw === '02';
        return `<span class="badge ${on ? 'on' : 'off'}">${on ? 'ON' : 'OFF'}</span>`;
    }
    if (cmd === 'ERR' && result.raw !== '00') {
        return '<span class="badge error">ALERT</span>';
    }
    if (['MUTE', 'FREEZE'].includes(cmd) && result.raw === 'ON') {
        return '<span class="badge warn">ACTIVE</span>';
    }
    if (cmd === 'FLWARNING' && result.raw === 'ON') {
        return '<span class="badge warn">WARNING</span>';
    }
    if (cmd === 'SIGNAL' && result.raw === '00') {
        return '<span class="badge warn">NO SIGNAL</span>';
    }
    return '';
}

function generateHtml(results) {
    const categories = {};
    for (const [cmd, result] of Object.entries(results)) {
        const cat = GET_COMMANDS[cmd]?.category || 'Other';
        if (!categories[cat]) categories[cat] = [];
        categories[cat].push({ cmd, ...result });
    }

    let tableRows = '';
    for (const [cat, items] of Object.entries(categories)) {
        tableRows += `<tr class="cat-header"><td colspan="4">${escapeHtml(cat)}</td></tr>\n`;
        for (const item of items) {
            const desc = GET_COMMANDS[item.cmd]?.description || item.cmd;
            const badge = buildStatusBadge(item.cmd, item);
            const statusClass = item.status === 'error' ? 'row-error' : '';
            tableRows += `<tr class="${statusClass}">
                <td class="cmd-name"><code>${escapeHtml(item.cmd)}?</code></td>
                <td>${escapeHtml(desc)}</td>
                <td class="value">${escapeHtml(item.display)} ${badge}</td>
                <td class="raw"><code>${escapeHtml(item.raw)}</code></td>
            </tr>\n`;
        }
    }

    const pwrResult = results['PWR'];
    const powerClass = pwrResult?.raw === '01' ? 'power-on'
        : pwrResult?.raw === '02' ? 'power-warmup'
        : pwrResult?.raw === '03' ? 'power-cooling'
        : 'power-off';
    const powerText = pwrResult?.display || 'Unknown';
    const projName = results['NWPNAME']?.display || results['IMNWPNAME']?.display || 'Epson Projector';
    const serial = results['SNO']?.display || '—';
    const errResult = results['ERR'];
    const hasError = errResult && errResult.status === 'ok' && errResult.raw !== '00';

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Projector Status — ${escapeHtml(projName)}</title>
<meta http-equiv="refresh" content="${Math.round(POLL_INTERVAL / 1000)}">
<style>
  :root {
    --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3a;
    --text: #e1e4ed; --text-dim: #8b8fa3; --accent: #6c8cff;
    --green: #4ade80; --red: #f87171; --yellow: #fbbf24; --blue: #60a5fa;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.5;
    padding: 1.5rem; max-width: 1100px; margin: 0 auto;
  }
  header {
    display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;
    padding-bottom: 1.5rem; border-bottom: 1px solid var(--border); margin-bottom: 1.5rem;
  }
  .power-indicator {
    width: 14px; height: 14px; border-radius: 50%; flex-shrink: 0;
    box-shadow: 0 0 8px currentColor;
  }
  .power-on .power-indicator { background: var(--green); color: var(--green); }
  .power-warmup .power-indicator { background: var(--yellow); color: var(--yellow); }
  .power-cooling .power-indicator { background: var(--blue); color: var(--blue); }
  .power-off .power-indicator { background: var(--text-dim); color: var(--text-dim); box-shadow: none; }
  h1 { font-size: 1.4rem; font-weight: 600; }
  .meta { color: var(--text-dim); font-size: 0.85rem; margin-left: auto; text-align: right; }
  .alert {
    background: #2d1215; border: 1px solid #7f1d1d; border-radius: 8px;
    padding: 0.75rem 1rem; margin-bottom: 1rem; color: var(--red); font-weight: 500;
  }
  .summary {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 0.75rem; margin-bottom: 1.5rem;
  }
  .card {
    background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
    padding: 0.85rem 1rem;
  }
  .card-label { font-size: 0.75rem; text-transform: uppercase; color: var(--text-dim); letter-spacing: 0.04em; }
  .card-value { font-size: 1.15rem; font-weight: 600; margin-top: 0.2rem; }
  table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; }
  th {
    text-align: left; padding: 0.6rem 0.85rem; font-size: 0.75rem;
    text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-dim);
    background: var(--surface); border-bottom: 1px solid var(--border);
  }
  td { padding: 0.5rem 0.85rem; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
  tr:last-child td { border-bottom: none; }
  .cat-header td {
    font-weight: 600; font-size: 0.82rem; text-transform: uppercase;
    letter-spacing: 0.05em; color: var(--accent); background: rgba(108,140,255,0.06);
    padding: 0.55rem 0.85rem;
  }
  .row-error td { color: var(--text-dim); }
  .cmd-name { white-space: nowrap; }
  code { font-family: 'SF Mono', Consolas, 'Liberation Mono', monospace; font-size: 0.85em; }
  .raw code { color: var(--text-dim); }
  .value { max-width: 360px; word-break: break-word; }
  .badge {
    display: inline-block; font-size: 0.7rem; font-weight: 700; padding: 0.15em 0.5em;
    border-radius: 4px; vertical-align: middle; margin-left: 0.4em; letter-spacing: 0.02em;
  }
  .badge.on { background: rgba(74,222,128,0.15); color: var(--green); }
  .badge.off { background: rgba(139,143,163,0.15); color: var(--text-dim); }
  .badge.error { background: rgba(248,113,113,0.15); color: var(--red); }
  .badge.warn { background: rgba(251,191,36,0.15); color: var(--yellow); }
  footer { margin-top: 1.5rem; color: var(--text-dim); font-size: 0.8rem; text-align: center; }
</style>
</head>
<body>
  <header class="${powerClass}">
    <div class="power-indicator"></div>
    <h1>${escapeHtml(projName)}</h1>
    <div class="meta">
      ${escapeHtml(PROJECTOR_HOST)}<br>
      S/N: ${escapeHtml(serial)}<br>
      Updated: ${new Date().toLocaleString()}
    </div>
  </header>
  ${hasError ? `<div class="alert">Error: ${escapeHtml(errResult.display)}</div>` : ''}
  <div class="summary">
    <div class="card">
      <div class="card-label">Power</div>
      <div class="card-value">${escapeHtml(powerText)}</div>
    </div>
    <div class="card">
      <div class="card-label">Source</div>
      <div class="card-value">${escapeHtml(results['SOURCE']?.display || '—')}</div>
    </div>
    <div class="card">
      <div class="card-label">Signal</div>
      <div class="card-value">${escapeHtml(results['SIGNAL']?.display || '—')}</div>
    </div>
    <div class="card">
      <div class="card-label">Lamp Hours</div>
      <div class="card-value">${escapeHtml(results['LAMP']?.display || '—')}</div>
    </div>
    <div class="card">
      <div class="card-label">A/V Mute</div>
      <div class="card-value">${escapeHtml(results['MUTE']?.display || '—')}</div>
    </div>
    <div class="card">
      <div class="card-label">Error</div>
      <div class="card-value">${escapeHtml(results['ERR']?.display || '—')}</div>
    </div>
  </div>
  <table>
    <thead><tr><th>Command</th><th>Description</th><th>Value</th><th>Raw</th></tr></thead>
    <tbody>
      ${tableRows}
    </tbody>
  </table>
  <footer>Auto-refresh: ${Math.round(POLL_INTERVAL / 1000)}s &middot; ESC/VP21 over HTTP Digest &middot; esc-vp-api</footer>
</body>
</html>`;
}

// ==================== Dashboard Server ====================
const server = http.createServer((req, res) => {
    if (req.url === '/' || req.url === '/index.html') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(generateHtml(latestResults));
    } else if (req.url === '/api/status') {
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify(latestResults, null, 2));
    } else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
    }
});

// ==================== Main ====================
async function poll() {
    try {
        latestResults = await queryAllCommands();
        printResults(latestResults);
    } catch (err) {
        console.error('Poll error:', err.message);
    }
}

server.listen(DASHBOARD_PORT, () => {
    console.log(`Projector: ${PROJECTOR_HOST}:${PROJECTOR_PORT} (user: ${USERNAME})`);
    console.log(`Dashboard: http://localhost:${DASHBOARD_PORT}/`);
    console.log(`JSON API:  http://localhost:${DASHBOARD_PORT}/api/status`);
    console.log(`Polling every ${POLL_INTERVAL / 1000}s\n`);
    poll();
    setInterval(poll, POLL_INTERVAL);
});
