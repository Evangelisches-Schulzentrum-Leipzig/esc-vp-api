'use strict';

const params = new URLSearchParams(location.search);
const API = (params.get('api') || (location.protocol === 'file:' ? 'http://localhost:3000' : '')).replace(/\/$/, '');
const REFRESH_MS = 10000;

const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const state = {
    projectors: [],
    sort: JSON.parse(localStorage.getItem('ph.sort') || '{"key":"name","dir":1}'),
    filter: 'all',
    search: '',
    view: localStorage.getItem('ph.view') || 'table',
    selected: null,
    tab: 'state',
    showUnsupported: false,
    history: null,
    lastFetch: null,
    fetchError: null,
};

// ---- derived values ----

const cmd = (p, name) => p.commands?.[name];
const okVal = (p, name) => {
    const c = cmd(p, name);
    return c && c.status === 'ok' ? c : null;
};

const POWER = {
    '01': ['on', 'On'], '02': ['warm', 'Warming up'], '03': ['cool', 'Cooling'],
    '00': ['standby', 'Standby'], '04': ['standby', 'Standby (net)'], '05': ['bad', 'Abnormal standby'],
};

function derive(p) {
    const pwr = okVal(p, 'PWR');
    const [powerClass, powerText] = pwr ? (POWER[pwr.value] || ['standby', pwr.display]) : ['standby', '-'];
    const err = okVal(p, 'ERR');
    const alerts = [];
    if (['auth-failed', 'unreachable', 'unsupported', 'busy'].includes(p.connection.status)) {
        alerts.push(`Connection: ${p.connection.status}`);
    }
    if (err && err.value !== '00') alerts.push(`Error: ${err.display}`);
    if (okVal(p, 'FLWARNING')?.value === true) alerts.push('Filter warning');
    return {
        online: p.online,
        powerClass: p.online ? powerClass : 'bad',
        powerText: p.online ? powerText : p.connection.status,
        powerOn: pwr?.value === '01',
        standby: pwr && ['00', '04'].includes(pwr.value),
        alerts,
        mute: okVal(p, 'MUTE')?.value === true,
        freeze: okVal(p, 'FREEZE')?.value === true,
        signal: okVal(p, 'SIGNAL'),
        source: okVal(p, 'SOURCE')?.display ?? '',
        lamp: okVal(p, 'LAMP')?.value ?? null,
        ontime: okVal(p, 'ONTIME')?.value ?? null,
        err,
    };
}

function ago(iso) {
    if (!iso) return '-';
    const s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
}

// ---- columns ----

const COLUMNS = [
    { key: 'status', label: 'Status', sort: (p, d) => (p.online ? 0 : 1) * 10 + (d.alerts.length ? 0 : 1), cell: (p, d) => `<span class="dot ${d.powerClass}"></span>${esc(d.powerText)}` },
    { key: 'name', label: 'Name', cls: 'c-name', sort: p => (p.name || p.host).toLowerCase(), cell: p => `${esc(p.name || p.host)}<span class="sub">${esc(p.model || '')}</span>` },
    { key: 'host', label: 'IP', sort: p => p.host.split('.').map(n => n.padStart(3, '0')).join('.'), cell: p => `<span class="mono">${esc(p.host)}</span>` },
    { key: 'source', label: 'Source', sort: (p, d) => d.source.toLowerCase(), cell: (p, d) => esc(d.source || '-') },
    { key: 'signal', label: 'Signal', sort: (p, d) => d.signal?.value ?? '', cell: (p, d) => esc(d.signal?.display ?? '-') },
    { key: 'flags', label: 'Mute / Freeze', sort: (p, d) => (d.mute ? 1 : 0) + (d.freeze ? 2 : 0), cell: (p, d) => `${d.mute ? '<span class="badge yellow">MUTE</span>' : ''}${d.freeze ? '<span class="badge yellow">FREEZE</span>' : ''}` || '<span class="dim">-</span>' },
    { key: 'alerts', label: 'Alerts', sort: (p, d) => d.alerts.length, cell: (p, d) => d.alerts.map(a => `<span class="badge red">${esc(a)}</span>`).join(' ') || '<span class="dim">-</span>' },
    { key: 'lamp', label: 'Lamp h', sort: (p, d) => d.lamp ?? -1, cell: (p, d) => (d.lamp === null ? '-' : esc(d.lamp)) },
    { key: 'ontime', label: 'On-time h', sort: (p, d) => d.ontime ?? -1, cell: (p, d) => (d.ontime === null ? '-' : esc(d.ontime)) },
    { key: 'updated', label: 'Updated', sort: p => p.lastPollAt || '', cell: p => esc(ago(p.lastPollAt)) },
];

// ---- filtering / sorting ----

const FILTERS = [
    ['all', 'All', () => true],
    ['online', 'Online', (p, d) => d.online],
    ['on', 'Power on', (p, d) => d.online && d.powerOn],
    ['standby', 'Standby', (p, d) => d.online && d.standby],
    ['alerts', 'Alerts', (p, d) => d.alerts.length > 0],
    ['offline', 'Offline', (p, d) => !d.online],
];

function searchText(p, d) {
    return [p.name, p.host, p.model, p.serialNumber, p.macAddress, d.source].join(' ').toLowerCase();
}

function visibleList() {
    const filter = FILTERS.find(f => f[0] === state.filter)[2];
    const term = state.search.trim().toLowerCase();
    const col = COLUMNS.find(c => c.key === state.sort.key) || COLUMNS[1];
    return state.projectors
        .map(p => ({ p, d: derive(p) }))
        .filter(({ p, d }) => filter(p, d) && (!term || searchText(p, d).includes(term)))
        .sort((a, b) => {
            const x = col.sort(a.p, a.d), y = col.sort(b.p, b.d);
            return (x < y ? -1 : x > y ? 1 : 0) * state.sort.dir || a.p.host.localeCompare(b.p.host, undefined, { numeric: true });
        });
}

// ---- rendering ----

function renderStats(all) {
    const n = f => all.filter(({ p, d }) => f(p, d)).length;
    const stats = [
        ['Projectors', all.length], ['Online', n((p, d) => d.online)], ['Power on', n((p, d) => d.online && d.powerOn)],
        ['Alerts', n((p, d) => d.alerts.length)], ['Offline', n((p, d) => !d.online)],
    ];
    $('stats').innerHTML = stats.map(([l, v]) => `<span class="stat"><b>${v}</b>${l}</span>`).join('');
    $('filters').innerHTML = FILTERS.map(([k, l, f]) =>
        `<button data-filter="${k}" class="${state.filter === k ? 'active' : ''}">${l}<span class="n">${n(f)}</span></button>`).join('');
}

function renderTable(list) {
    $('thead').innerHTML = '<tr>' + COLUMNS.map(c => {
        const sorted = state.sort.key === c.key;
        return `<th data-sort="${c.key}" class="${sorted ? 'sorted' : ''}">${c.label}${sorted ? (state.sort.dir > 0 ? ' ▲' : ' ▼') : ''}</th>`;
    }).join('') + '</tr>';
    $('tbody').innerHTML = list.map(({ p, d }) =>
        `<tr data-id="${esc(p.id)}" class="${d.online ? '' : 'offline'} ${d.alerts.length ? 'has-alert' : ''}">` +
        COLUMNS.map(c => `<td class="${c.cls || ''}">${c.cell(p, d)}</td>`).join('') + '</tr>').join('');
}

function renderCards(list) {
    $('cards-view').innerHTML = list.map(({ p, d }) => `
        <div class="card ${d.online ? '' : 'offline'} ${d.alerts.length ? 'has-alert' : ''}" data-id="${esc(p.id)}">
          <h3><span class="dot ${d.powerClass}"></span>${esc(p.name || p.host)}</h3>
          <div class="meta mono">${esc(p.host)} ${p.model ? '· ' + esc(p.model) : ''}</div>
          <div class="kv">
            <span>Status</span><span>${esc(d.powerText)}</span>
            <span>Source</span><span>${esc(d.source || '-')}</span>
            <span>Signal</span><span>${esc(d.signal?.display ?? '-')}</span>
            <span>Lamp</span><span>${d.lamp === null ? '-' : esc(d.lamp) + ' h'}</span>
            <span>Updated</span><span>${esc(ago(p.lastPollAt))}</span>
          </div>
          <div>${d.mute ? '<span class="badge yellow">MUTE</span>' : ''}${d.freeze ? '<span class="badge yellow">FREEZE</span>' : ''}${d.alerts.map(a => `<span class="badge red">${esc(a)}</span>`).join('')}</div>
        </div>`).join('');
}

function render() {
    const all = state.projectors.map(p => ({ p, d: derive(p) }));
    renderStats(all);
    const list = visibleList();
    $('table-view').hidden = state.view !== 'table';
    $('cards-view').hidden = state.view !== 'cards';
    if (state.view === 'table') renderTable(list); else renderCards(list);
    $('empty').hidden = list.length > 0;
    $('empty').textContent = state.projectors.length ? 'No projectors match.' : 'No projectors discovered yet.';
    document.querySelectorAll('#view-switch button').forEach(b => b.classList.toggle('active', b.dataset.view === state.view));

    const banner = $('banner');
    banner.hidden = !state.fetchError;
    banner.textContent = state.fetchError ? `Cannot reach the server: ${state.fetchError}. Showing last known data.` : '';
    $('fetch-state').textContent = state.lastFetch ? `Updated ${state.lastFetch.toLocaleTimeString()}` : 'Loading...';
    renderDrawer();
}

function renderDrawer() {
    const p = state.projectors.find(x => x.id === state.selected);
    $('drawer').hidden = $('scrim').hidden = !p;
    if (!p) return;
    const d = derive(p);
    $('d-title').innerHTML = `<span class="dot ${d.powerClass}"></span>${esc(p.name || p.host)}`;
    $('d-meta').innerHTML = [
        `<span class="mono">${esc(p.host)}</span>`, p.model, p.serialNumber && `S/N ${esc(p.serialNumber)}`, p.macAddress, p.firmware && `FW ${esc(p.firmware)}`,
        `protocol ${esc(p.connection.protocolVersion || '?')}`, `polled ${esc(ago(p.lastPollAt))}`,
    ].filter(Boolean).join(' · ');
    document.querySelectorAll('#d-tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === state.tab));

    const body = $('d-body');
    const scroll = body.scrollTop;
    body.innerHTML = state.tab === 'state' ? stateHtml(p, d) : historyHtml();
    body.scrollTop = scroll;
}

function stateHtml(p, d) {
    let html = '';
    if (p.connection.error) html += `<div class="err-line">${esc(p.connection.status)}: ${esc(p.connection.error)}</div>`;
    d.alerts.forEach(a => { html += `<div class="err-line">${esc(a)}</div>`; });

    const cmds = Object.values(p.commands || {});
    const unsupported = cmds.filter(c => c.status === 'unsupported').length;
    html += `<label class="toggle"><input type="checkbox" id="chk-unsupported" ${state.showUnsupported ? 'checked' : ''}> Show ${unsupported} unsupported / unavailable commands</label>`;

    const cats = new Map();
    cmds.filter(c => state.showUnsupported || c.status !== 'unsupported').forEach(c => {
        if (!cats.has(c.category)) cats.set(c.category, []);
        cats.get(c.category).push(c);
    });
    for (const [cat, items] of cats) {
        html += `<section class="cat"><h4>${esc(cat)}</h4><table class="cmds">` + items.map(c => {
            const value = c.status === 'ok' ? esc(c.display) : c.status === 'unsupported' ? 'ERR (unsupported / unavailable)' : esc(c.error || 'error');
            const tip = `Last OK: ${c.lastOkAt || 'never'} · Changed: ${c.changedAt}`;
            return `<tr class="${c.status === 'ok' ? '' : 'unsupported'}" title="${esc(tip)}">
                <td><code>${esc(c.query)}</code></td><td>${esc(c.description)}${c.documented ? '' : ' <span class="badge grey">undocumented</span>'}</td>
                <td>${value}</td><td class="raw mono">${esc(c.raw ?? '')}</td><td class="when">${esc(ago(c.updatedAt))}</td></tr>`;
        }).join('') + '</table></section>';
    }
    return html;
}

function historyHtml() {
    if (!state.history) return '<p class="dim">Loading...</p>';
    if (!state.history.length) return '<p class="dim">No changes recorded yet.</p>';
    const fmt = x => (x.status === 'ok' ? x.display ?? x.raw : x.status);
    return '<table class="hist">' + state.history.map(h => {
        const what = h.type === 'connection'
            ? `Connection: ${esc(h.from)} → ${esc(h.to)}${h.error ? ` <span class="dim">(${esc(h.error)})</span>` : ''}`
            : `<code>${esc(h.command)}</code>: ${esc(fmt(h.from))} → ${esc(fmt(h.to))}`;
        return `<tr><td class="when dim">${esc(new Date(h.at).toLocaleString())}</td><td>${what}</td></tr>`;
    }).join('') + '</table>';
}

// ---- data ----

async function api(path, opts) {
    const res = await fetch(API + path, opts);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
}

async function refresh() {
    try {
        state.projectors = await api('/api/projectors?details=full');
        state.lastFetch = new Date();
        state.fetchError = null;
    } catch (err) {
        state.fetchError = err.message;
    }
    render();
}

async function loadHistory() {
    state.history = null;
    renderDrawer();
    try {
        state.history = await api(`/api/projectors/${encodeURIComponent(state.selected)}/history?limit=200`);
    } catch {
        state.history = [];
    }
    renderDrawer();
}

function select(id) {
    state.selected = id;
    state.tab = 'state';
    state.history = null;
    renderDrawer();
}

// ---- events ----

document.addEventListener('click', e => {
    const t = e.target.closest('[data-filter],[data-sort],[data-view],[data-tab],[data-id]');
    if (t?.dataset.filter) { state.filter = t.dataset.filter; render(); }
    else if (t?.dataset.sort) {
        const key = t.dataset.sort;
        state.sort = { key, dir: state.sort.key === key ? -state.sort.dir : 1 };
        localStorage.setItem('ph.sort', JSON.stringify(state.sort));
        render();
    } else if (t?.dataset.view) { state.view = t.dataset.view; localStorage.setItem('ph.view', state.view); render(); }
    else if (t?.dataset.tab) {
        state.tab = t.dataset.tab;
        if (state.tab === 'history') loadHistory(); else renderDrawer();
    } else if (t?.dataset.id) select(t.dataset.id);
});

$('search').addEventListener('input', e => { state.search = e.target.value; render(); });
$('d-close').onclick = $('scrim').onclick = () => { state.selected = null; renderDrawer(); };
document.addEventListener('keydown', e => { if (e.key === 'Escape' && state.selected) { state.selected = null; renderDrawer(); } });
document.addEventListener('change', e => {
    if (e.target.id === 'chk-unsupported') { state.showUnsupported = e.target.checked; renderDrawer(); }
});
$('d-refresh').onclick = async () => {
    await api(`/api/projectors/${encodeURIComponent(state.selected)}/refresh`, { method: 'POST' }).catch(() => {});
    setTimeout(refresh, 1500);
};
$('btn-discover').onclick = async () => {
    await api('/api/discovery', { method: 'POST' }).catch(() => {});
    setTimeout(refresh, 4000);
};

refresh();
setInterval(refresh, REFRESH_MS);
