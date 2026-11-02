'use strict';
// List-page views: KPI strip, table, cards, tiles and insights.

const pill = d => `<span class="pill s-${d.st}"><i class="dot"></i>${esc(d.meta.label)}</span>`;
const alertBadges = (d, max = 2) => {
    const shown = d.alerts.slice(0, max).map(a => `<span class="badge ${a.level}">${esc(a.text)}</span>`).join('');
    return shown + (d.alerts.length > max ? `<span class="badge grey">+${d.alerts.length - max}</span>` : '');
};
const flagBadges = d => `${d.mute ? '<span class="badge warn">MUTE</span>' : ''}${d.freeze ? '<span class="badge warn">FREEZE</span>' : ''}`;
const lampBar = d => (d.lamp === null ? '<span class="dim">-</span>'
    : `<span class="lamp"><span class="bar ${d.lampPct >= 100 ? 'crit' : d.lampPct >= 75 ? 'warn' : ''}"><i style="width:${d.lampPct}%"></i></span><span class="mono">${num(d.lamp)} h</span></span>`);
const dash = v => (v === null || v === undefined || v === '' ? '<span class="dim">-</span>' : esc(v));

// ---- columns ----

const COLUMNS = [
    { key: 'status', label: 'Status', sort: (p, d) => d.meta.order, cell: (p, d) => pill(d), csv: (p, d) => d.meta.label },
    { key: 'name', label: 'Name', cls: 'c-name', sort: (p, d) => d.name.toLowerCase(), cell: (p, d) => esc(d.name), csv: (p, d) => d.name },
    { key: 'host', label: 'IP', sort: p => ipKey(p.host), cell: p => `<span class="mono">${esc(p.host)}</span>`, csv: p => p.host },
    { key: 'model', label: 'Model type', sort: (p, d) => d.model, cell: (p, d) => dash(d.model), csv: (p, d) => d.model },
    { key: 'serial', label: 'Serial', sort: p => p.serialNumber || '', cell: p => dash(p.serialNumber), csv: p => p.serialNumber },
    { key: 'mac', label: 'MAC', sort: p => p.macAddress || '', cell: p => `<span class="mono">${dash(p.macAddress)}</span>`, csv: p => p.macAddress },
    { key: 'firmware', label: 'Firmware', sort: (p, d) => d.firmware, cell: (p, d) => `<span class="mono">${dash(d.firmware)}</span>`, csv: (p, d) => d.firmware },
    { key: 'source', label: 'Source', sort: (p, d) => d.source.toLowerCase(), cell: (p, d) => dash(d.source), csv: (p, d) => d.source },
    { key: 'signal', label: 'Signal', sort: (p, d) => d.signal?.value ?? '', cell: (p, d) => dash(d.signal?.display), csv: (p, d) => d.signal?.display },
    { key: 'flags', label: 'Mute / Freeze', sort: (p, d) => (d.mute ? 1 : 0) + (d.freeze ? 2 : 0), cell: (p, d) => flagBadges(d) || '<span class="dim">-</span>', csv: (p, d) => [d.mute && 'mute', d.freeze && 'freeze'].filter(Boolean).join(' ') },
    { key: 'alerts', label: 'Alerts', sort: (p, d) => d.alerts.length + (d.crit ? 100 : 0), cell: (p, d) => alertBadges(d) || '<span class="dim">-</span>', csv: (p, d) => d.alerts.map(a => a.text).join('; ') },
    { key: 'lamp', label: 'Lamp', sort: (p, d) => d.lamp, cell: (p, d) => lampBar(d), csv: (p, d) => d.lamp },
    { key: 'ontime', label: 'On-time', sort: (p, d) => d.ontime, cell: (p, d) => (d.ontime === null ? '<span class="dim">-</span>' : `<span class="mono">${num(d.ontime)} h</span>`), csv: (p, d) => d.ontime },
    { key: 'filter', label: 'Filter h', sort: (p, d) => d.filterH, cell: (p, d) => (d.filterH === null ? '<span class="dim">-</span>' : `<span class="mono">${num(d.filterH)} h</span>`), csv: (p, d) => d.filterH },
    { key: 'essid', label: 'Wi-Fi ESSID', sort: (p, d) => d.essid, cell: (p, d) => dash(d.essid), csv: (p, d) => d.essid },
    { key: 'proto', label: 'Protocol', sort: p => p.connection.protocolVersion || '', cell: p => dash(p.connection.protocolVersion), csv: p => p.connection.protocolVersion },
    { key: 'updated', label: 'Updated', sort: p => p.lastPollAt || '', cell: p => `<span data-ago="${esc(p.lastPollAt)}">${esc(ago(p.lastPollAt))}</span>`, csv: p => p.lastPollAt },
];
const COL = Object.fromEntries(COLUMNS.map(c => [c.key, c]));

// ---- filtering, sorting, grouping ----

const FILTERS = {
    all: { label: 'Projectors', test: () => true },
    projecting: { label: 'Projecting', test: (p, d) => d.projecting, cls: 'on' },
    standby: { label: 'Standby', test: (p, d) => d.st === 'standby', cls: 'standby' },
    alerts: { label: 'Alerts', test: (p, d) => d.alerts.length > 0, cls: 'bad' },
    offline: { label: 'Not connected', test: (p, d) => !d.online, cls: 'off' },
    lamp: { label: 'Lamp over limit', test: (p, d) => d.lampHigh, cls: 'warn' },
};

const GROUPS = {
    none: { label: 'No grouping' },
    state: { label: 'Status', key: (p, d) => d.meta.label, order: (p, d) => d.meta.order },
    subnet: { label: 'Subnet', key: (p, d) => d.subnet },
    model: { label: 'Model type', key: (p, d) => d.model || 'Unknown' },
    firmware: { label: 'Firmware', key: (p, d) => d.firmware || 'Unknown' },
    source: { label: 'Source', key: (p, d) => d.source || 'None' },
};

const isEmpty = v => v === null || v === undefined || v === '';
function compare(a, b) {
    if (isEmpty(a) || isEmpty(b)) return isEmpty(a) === isEmpty(b) ? 0 : isEmpty(a) ? 1 : -1; // empty always last
    return typeof a === 'number' && typeof b === 'number' ? a - b : String(a).localeCompare(String(b), undefined, { numeric: true });
}

function visibleList() {
    const test = FILTERS[state.filter].test;
    const term = state.search.trim().toLowerCase();
    const col = COL[settings.sort.key] || COL.name;
    const dir = settings.sort.dir;
    return state.projectors
        .map(p => ({ p, d: D(p) }))
        .filter(({ p, d }) => test(p, d) && (!term || [d.name, p.host, d.model, p.serialNumber, p.macAddress, d.firmware, d.source, d.essid, d.meta.label].join(' ').toLowerCase().includes(term)))
        .sort((a, b) => {
            const x = col.sort(a.p, a.d), y = col.sort(b.p, b.d);
            // Keep empty values last in both directions.
            if (isEmpty(x) || isEmpty(y)) return compare(x, y);
            return compare(x, y) * dir || compare(ipKey(a.p.host), ipKey(b.p.host));
        });
}

function groupItems(list) {
    const g = GROUPS[settings.group];
    if (!g.key) return [{ label: null, items: list }];
    const map = new Map();
    for (const it of list) {
        const label = g.key(it.p, it.d);
        if (!map.has(label)) map.set(label, { label, order: g.order ? g.order(it.p, it.d) : label, items: [] });
        map.get(label).items.push(it);
    }
    return [...map.values()].sort((a, b) => compare(a.order, b.order));
}

const miniBar = items => {
    const counts = {};
    items.forEach(({ d }) => { counts[d.st] = (counts[d.st] || 0) + 1; });
    return `<span class="mini">${Object.entries(counts).sort((a, b) => STATE_META[a[0]].order - STATE_META[b[0]].order)
        .map(([s, n]) => `<i class="s-${s}" style="flex:${n}" title="${n} ${STATE_META[s].label}"></i>`).join('')}</span>`;
};

function groupHeader(g, extra = '') {
    if (g.label === null) return '';
    const open = !state.collapsed.has(g.label);
    return `<div class="group-h ${open ? '' : 'closed'}" data-group="${esc(g.label)}">${icon('down', 'chev')}<b>${esc(g.label)}</b><span class="dim">${g.items.length}</span>${miniBar(g.items)}${extra}</div>`;
}

// ---- KPI strip & toolbar ----

function renderKpis() {
    const all = state.projectors.map(p => ({ p, d: D(p) }));
    $('#kpis').innerHTML = Object.entries(FILTERS).map(([key, f]) => {
        const n = all.filter(({ p, d }) => f.test(p, d)).length;
        const label = key === 'lamp' ? `Lamp ≥ ${num(settings.lampWarn)} h` : f.label;
        return `<button class="kpi ${f.cls || ''} ${state.filter === key ? 'active' : ''}" data-kpi="${key}"><b>${n}</b><span>${esc(label)}</span></button>`;
    }).join('');
}

function renderToolbar() {
    const table = settings.view === 'table', insights = settings.view === 'insights';
    $('#group-by').innerHTML = Object.entries(GROUPS).map(([k, g]) => `<option value="${k}" ${settings.group === k ? 'selected' : ''}>${g.label}</option>`).join('');
    $('#sort-by').innerHTML = COLUMNS.map(c => `<option value="${c.key}" ${settings.sort.key === c.key ? 'selected' : ''}>${c.label}</option>`).join('');
    $('#sort-dir').innerHTML = settings.sort.dir > 0 ? '▲' : '▼';
    $('#tb-group').hidden = $('#tb-sort').hidden = insights;
    $('#btn-columns').hidden = !table;
    $('#view-switch').querySelectorAll('button').forEach(b => b.classList.toggle('active', b.dataset.view === settings.view));
}

// ---- views ----

function renderTable(groups) {
    const cols = COLUMNS.filter(c => settings.columns.includes(c.key));
    const head = '<tr>' + cols.map(c => {
        const on = settings.sort.key === c.key;
        return `<th data-sort="${c.key}" class="${on ? 'sorted' : ''}">${c.label}${on ? (settings.sort.dir > 0 ? ' ▲' : ' ▼') : ''}</th>`;
    }).join('') + '</tr>';
    const body = groups.map(g => {
        const hdr = g.label === null ? '' : `<tr class="group-row"><td colspan="${cols.length}">${groupHeader(g)}</td></tr>`;
        if (state.collapsed.has(g.label)) return hdr;
        return hdr + g.items.map(({ p, d }) =>
            `<tr data-id="${esc(p.id)}" class="${d.online ? '' : 'is-off'} ${d.crit ? 'has-crit' : d.alerts.length ? 'has-warn' : ''} ${state.flash.has(p.id) ? 'flash' : ''}">` +
            cols.map(c => `<td class="${c.cls || ''}">${c.cell(p, d)}</td>`).join('') + '</tr>').join('');
    }).join('');
    return `<div class="table-wrap"><table class="overview"><thead>${head}</thead><tbody>${body}</tbody></table></div>`;
}

function renderCards(groups) {
    return groups.map(g => `<section class="group">${groupHeader(g)}${state.collapsed.has(g.label) ? '' : `<div class="cards">${g.items.map(({ p, d }) => `
        <article class="card s-${d.st} ${d.crit ? 'has-crit' : d.alerts.length ? 'has-warn' : ''} ${state.flash.has(p.id) ? 'flash' : ''}" data-id="${esc(p.id)}" tabindex="0">
          <header><h3>${esc(d.name)}</h3>${pill(d)}</header>
          <div class="meta mono">${esc(p.host)}${d.model ? ' · ' + esc(d.model) : ''}</div>
          <dl>
            <dt>Source</dt><dd>${dash(d.source)}</dd>
            <dt>Signal</dt><dd>${dash(d.signal?.display)}</dd>
            <dt>Lamp</dt><dd>${lampBar(d)}</dd>
            <dt>On-time</dt><dd>${d.ontime === null ? '<span class="dim">-</span>' : num(d.ontime) + ' h'}</dd>
            <dt>Firmware</dt><dd class="mono">${dash(d.firmware)}</dd>
          </dl>
          <footer>${flagBadges(d)}${alertBadges(d, 3)}<span class="dim ago" data-ago="${esc(p.lastPollAt)}">${esc(ago(p.lastPollAt))}</span></footer>
        </article>`).join('')}</div>`}</section>`).join('');
}

function renderTiles(groups) {
    return groups.map(g => `<section class="group">${groupHeader(g)}${state.collapsed.has(g.label) ? '' : `<div class="tiles">${g.items.map(({ p, d }) => {
        const short = '.' + p.host.split('.').slice(2).join('.');
        const line = d.projecting && d.source ? d.source : d.online ? (d.pwrDisplay || d.meta.label) : d.meta.label;
        const tip = [d.name, p.host, d.meta.label, d.source, ...d.alerts.map(a => a.text)].filter(Boolean).join(' · ');
        return `<button class="tile s-${d.st} ${d.crit ? 'has-crit' : d.alerts.length ? 'has-warn' : ''} ${state.flash.has(p.id) ? 'flash' : ''}" data-id="${esc(p.id)}" title="${esc(tip)}">
            <span class="t-name">${esc(d.name)}</span>
            <span class="t-ip mono">${esc(short)}</span>
            <span class="t-line">${esc(line)}</span>
            ${d.alerts.length ? `<span class="t-alert ${d.crit ? 'crit' : 'warn'}">${icon('alert')}</span>` : ''}
            ${d.lamp !== null ? `<span class="bar thin ${d.lampPct >= 100 ? 'crit' : d.lampPct >= 75 ? 'warn' : ''}"><i style="width:${d.lampPct}%"></i></span>` : ''}
        </button>`;
    }).join('')}</div>`}</section>`).join('');
}

// ---- insights ----

const panel = (title, body, cls = '') => `<section class="panel ${cls}"><h3>${esc(title)}</h3>${body}</section>`;

function barList(rows, { empty = 'No data' } = {}) {
    if (!rows.length) return `<p class="dim">${empty}</p>`;
    const max = Math.max(...rows.map(r => r.n), 1);
    return '<div class="bl">' + rows.map(r =>
        `<div class="bl-row ${r.id ? 'clickable' : ''}" ${r.id ? `data-id="${esc(r.id)}"` : ''}><span class="bl-label" title="${esc(r.label)}">${esc(r.label)}</span><span class="bl-bar"><i class="${r.cls || ''}" style="width:${(r.n / max) * 100}%"></i></span><span class="bl-n mono">${esc(r.text ?? r.n)}</span></div>`).join('') + '</div>';
}

function tally(list, fn) {
    const m = new Map();
    list.forEach(it => { const k = fn(it); m.set(k, (m.get(k) || 0) + 1); });
    return [...m.entries()].map(([label, n]) => ({ label, n })).sort((a, b) => b.n - a.n || String(a.label).localeCompare(String(b.label), undefined, { numeric: true }));
}

function describeHistory(h, { withName = false } = {}) {
    const who = withName ? `<b>${esc(h.name || h.host)}</b> ` : '';
    const fmt = x => esc(x.status === 'ok' ? (x.display ?? x.raw) : x.status);
    if (h.type === 'connection') return `${who}connection <span class="pill s-${CONN_STATE[h.to] || 'offline'}"><i class="dot"></i>${esc(h.from)} → ${esc(h.to)}</span>${h.error ? ` <span class="dim">${esc(h.error)}</span>` : ''}`;
    return `${who}<code>${esc(h.command)}</code> ${fmt(h.from)} → ${fmt(h.to)}`;
}

function renderInsights(list) {
    const n = list.length;
    if (!n) return '';
    const states = Object.keys(STATE_META).map(s => ({ s, n: list.filter(it => it.d.st === s).length })).filter(x => x.n);
    const fleet = `<div class="stack">${states.map(x => `<i class="s-${x.s}" style="flex:${x.n}" title="${x.n} ${STATE_META[x.s].label}"></i>`).join('')}</div>
        <div class="legend">${states.map(x => `<span><i class="dot s-${x.s}"></i>${STATE_META[x.s].label} <b>${x.n}</b></span>`).join('')}</div>`;

    const lamps = list.filter(it => it.d.lamp !== null);
    const step = 1000, top = Math.max(...lamps.map(it => it.d.lamp), settings.lampWarn);
    const buckets = Array.from({ length: Math.ceil((top + 1) / step) }, (_, i) => ({ label: `${num(i * step)}–${num((i + 1) * step)} h`, n: 0, cls: (i + 1) * step > settings.lampWarn ? 'crit' : '' }));
    lamps.forEach(it => { buckets[Math.min(Math.floor(it.d.lamp / step), buckets.length - 1)].n++; });
    const topLamps = [...lamps].sort((a, b) => b.d.lamp - a.d.lamp).slice(0, 8)
        .map(it => ({ label: it.d.name, n: it.d.lamp, text: `${num(it.d.lamp)} h`, id: it.p.id, cls: it.d.lampHigh ? 'crit' : '' }));

    const alerts = list.filter(it => it.d.alerts.length).sort((a, b) => Number(b.d.crit) - Number(a.d.crit))
        .map(it => `<div class="alert-row clickable" data-id="${esc(it.p.id)}"><b>${esc(it.d.name)}</b><span class="mono dim">${esc(it.p.host)}</span>${alertBadges(it.d, 4)}</div>`).join('');

    const subnets = tally(list, it => it.d.subnet).map(r => ({ ...r, text: `${list.filter(it => it.d.subnet === r.label && it.d.online).length}/${r.n} online` }));
    const activity = state.activity.slice(0, 12).map(h =>
        `<div class="act"><span class="dim when" title="${esc(fmtTime(h.at))}">${esc(ago(h.at))}</span><span>${describeHistory(h, { withName: true })}</span></div>`).join('');

    return `<div class="insights">
        ${panel('Fleet status', fleet, 'wide')}
        ${panel('Lamp hours', barList(buckets.filter((b, i) => b.n || i < 6), { empty: 'No lamp data yet' }) + `<h4>Highest usage</h4>` + barList(topLamps, { empty: 'No lamp data yet' }))}
        ${panel(`Alerts (${list.filter(it => it.d.alerts.length).length})`, `<div class="scroll">${alerts || '<p class="dim">No alerts. All good.</p>'}</div>`)}
        ${panel('Sources in use', barList(tally(list.filter(it => it.d.projecting && it.d.source), it => it.d.source), { empty: 'Nothing projecting right now' }))}
        ${panel('Model types', barList(tally(list, it => it.d.model || 'Unknown')))}
        ${panel('Firmware versions', barList(tally(list, it => it.d.firmware || 'Unknown')))}
        ${panel('Subnets', barList(subnets))}
        ${panel('Recent activity', activity || '<p class="dim">No changes recorded since the server started.</p>', 'wide')}
    </div>`;
}

// ---- list page ----

function renderList() {
    renderKpis();
    renderToolbar();
    const list = visibleList();
    const groups = groupItems(list);
    const v = settings.view;
    $('#content').innerHTML = !list.length ? '' : v === 'table' ? renderTable(groups) : v === 'cards' ? renderCards(groups) : v === 'tiles' ? renderTiles(groups) : renderInsights(list);
    const empty = $('#empty');
    empty.hidden = list.length > 0;
    if (!list.length) empty.textContent = state.projectors.length ? 'No projectors match the current filter.' : state.lastFetch ? 'No projectors discovered yet.' : 'Loading...';
    $('#result-count').textContent = list.length === state.projectors.length ? `${list.length} projectors` : `${list.length} of ${state.projectors.length}`;
    $('#btn-clear').hidden = state.filter === 'all' && !state.search;
}

function exportCsv() {
    const cols = COLUMNS.filter(c => settings.columns.includes(c.key));
    const q = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const rows = visibleList().map(({ p, d }) => cols.map(c => q(c.csv(p, d))).join(','));
    const blob = new Blob([[cols.map(c => q(c.label)).join(','), ...rows].join('\r\n')], { type: 'text/csv' });
    const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: `projectors-${new Date().toISOString().slice(0, 10)}.csv` });
    a.click();
    URL.revokeObjectURL(a.href);
}
