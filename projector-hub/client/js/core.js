'use strict';
// Shared helpers, settings, data store and derived projector state. Classic scripts share this global scope.

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const ICONS = {
    table: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 10h18M9 4v16"/>',
    cards: '<rect x="3" y="3" width="8" height="8" rx="1.5"/><rect x="13" y="3" width="8" height="8" rx="1.5"/><rect x="3" y="13" width="8" height="8" rx="1.5"/><rect x="13" y="13" width="8" height="8" rx="1.5"/>',
    tiles: '<rect x="3" y="3" width="5" height="5" rx="1"/><rect x="9.5" y="3" width="5" height="5" rx="1"/><rect x="16" y="3" width="5" height="5" rx="1"/><rect x="3" y="9.5" width="5" height="5" rx="1"/><rect x="9.5" y="9.5" width="5" height="5" rx="1"/><rect x="16" y="9.5" width="5" height="5" rx="1"/><rect x="3" y="16" width="5" height="5" rx="1"/><rect x="9.5" y="16" width="5" height="5" rx="1"/><rect x="16" y="16" width="5" height="5" rx="1"/>',
    chart: '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
    refresh: '<path d="M21 12a9 9 0 1 1-3-6.7L21 8M21 3v5h-5"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
    gear: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1 7 17M17 7l2.1-2.1"/>',
    radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="m12 12 6-6"/>',
    external: '<path d="M14 3h7v7M21 3l-9 9M19 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h5"/>',
    copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
    left: '<path d="m15 18-6-6 6-6"/>',
    right: '<path d="m9 18 6-6-6-6"/>',
    down: '<path d="m6 9 6 6 6-6"/>',
    download: '<path d="M12 3v12m0 0-4-4m4 4 4-4M4 21h16"/>',
    columns: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M9 4v16M15 4v16"/>',
    power: '<path d="M12 3v8"/><path d="M6.4 7a8 8 0 1 0 11.2 0"/>',
    alert: '<path d="M12 3 2 21h20L12 3zM12 10v5M12 18v.01"/>',
    x: '<path d="M18 6 6 18M6 6l12 12"/>',
};
const icon = (n, cls = '') => `<svg class="ic ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n]}</svg>`;

// ---- settings (persisted) ----

const DEFAULT_COLUMNS = ['status', 'name', 'host', 'source', 'signal', 'flags', 'alerts', 'lamp', 'ontime', 'firmware', 'updated'];
const settings = {
    theme: 'auto', refreshSec: 10, lampWarn: 4000, density: 'comfortable',
    columns: DEFAULT_COLUMNS, view: 'table', group: 'none', sort: { key: 'name', dir: 1 },
    ...JSON.parse(localStorage.getItem('ph.settings') || '{}'),
};
const saveSettings = () => localStorage.setItem('ph.settings', JSON.stringify(settings));

function applyTheme() {
    const root = document.documentElement;
    if (settings.theme === 'auto') root.removeAttribute('data-theme'); else root.dataset.theme = settings.theme;
    root.dataset.density = settings.density;
}

// ---- store ----

const params = new URLSearchParams(location.search);
const DEMO = params.get('demo');
const API = (params.get('api') || (location.protocol === 'file:' ? 'http://localhost:3000' : '')).replace(/\/$/, '');

const state = {
    projectors: [],
    byId: new Map(),
    activity: [],
    lastFetch: null,
    fetchError: null,
    filter: 'all',
    search: '',
    route: { page: 'list', id: null, tab: 'overview' },
    collapsed: new Set(),
    flash: new Set(),
    prev: new Map(),
    cmdQuery: '',
    cmdStatus: 'ok',
    histFilter: 'all',
    history: null,
};

async function api(path, opts) {
    const res = await fetch(API + path, opts);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
}

// ---- formatting ----

function ago(iso) {
    if (!iso) return 'never';
    const s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
    if (s < 5) return 'just now';
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
}
const fmtTime = iso => (iso ? new Date(iso).toLocaleString() : 'never');
const ipKey = h => h.split('.').map(n => n.padStart(3, '0')).join('.');
const num = n => (n === null || n === undefined ? '-' : Number(n).toLocaleString());

// ---- derived state ----

const STATE_META = {
    on: { label: 'On', order: 0 },
    warm: { label: 'Warming up', order: 1 },
    cool: { label: 'Cooling down', order: 2 },
    standby: { label: 'Standby', order: 3 },
    abnormal: { label: 'Abnormal', order: 4 },
    pending: { label: 'Connecting', order: 5 },
    offline: { label: 'Unreachable', order: 6 },
    refused: { label: 'Refused', order: 7 },
    authfail: { label: 'Auth failed', order: 8 },
};
const PWR_STATE = { '01': 'on', '02': 'warm', '03': 'cool', '00': 'standby', '04': 'standby', '05': 'abnormal' };
const CONN_STATE = { pending: 'pending', unreachable: 'offline', busy: 'offline', 'auth-failed': 'authfail', refused: 'refused', unsupported: 'refused' };

function derive(p) {
    const ok = n => {
        const c = p.commands?.[n];
        return c && c.status === 'ok' ? c : null;
    };
    const pwr = ok('PWR');
    const st = p.online ? (pwr ? PWR_STATE[pwr.value] || 'standby' : 'pending') : CONN_STATE[p.connection.status] || 'offline';
    const lamp = ok('LAMP')?.value ?? null;
    const wired = ok('NWCNF')?.value;
    const wl = (ok('NWWLCNFS') || ok('NWWLCNF'))?.value;
    const err = ok('ERR');

    const alerts = [];
    if (st === 'abnormal') alerts.push({ level: 'crit', text: 'Abnormal standby' });
    if (err && err.value !== '00') alerts.push({ level: 'crit', text: err.display });
    if (st === 'authfail') alerts.push({ level: 'warn', text: 'Authentication failed' });
    if (st === 'refused') alerts.push({ level: 'warn', text: 'Access refused' });
    if (st === 'offline') alerts.push({ level: 'warn', text: 'Unreachable' });
    if (ok('FLWARNING')?.value === true) alerts.push({ level: 'warn', text: 'Filter warning' });
    const lampHigh = lamp !== null && lamp >= settings.lampWarn;
    if (lampHigh) alerts.push({ level: 'warn', text: `Lamp ${num(lamp)} h` });

    return {
        st,
        meta: STATE_META[st],
        online: p.online,
        projecting: st === 'on' || st === 'warm',
        pwrDisplay: pwr?.display ?? null,
        alerts,
        crit: alerts.some(a => a.level === 'crit'),
        name: p.name || p.host,
        subnet: p.host.split('.').slice(0, 3).join('.') + '.x',
        source: ok('SOURCE')?.display ?? '',
        signal: ok('SIGNAL'),
        mute: ok('MUTE')?.value === true,
        freeze: ok('FREEZE')?.value === true,
        lamp, lampHigh,
        lampPct: lamp === null ? null : Math.min(100, (lamp / settings.lampWarn) * 100),
        ontime: ok('ONTIME')?.value ?? null,
        filterH: ok('FILTER')?.value ?? null,
        firmware: p.firmware || '',
        essid: wl?.essid ?? '',
        wiredIp: wired?.ip && wired.ip !== '0.0.0.0' ? wired.ip : '',
        model: p.discovery?.imType || '',
        stateSince: p.commands?.PWR?.changedAt ?? null,
    };
}

const derived = new Map();
const D = p => derived.get(p.id) ?? derive(p);
