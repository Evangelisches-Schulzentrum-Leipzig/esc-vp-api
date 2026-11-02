'use strict';
// Detail page for a single projector.

const TABS = [['overview', 'Overview'], ['network', 'Network'], ['commands', 'Commands'], ['history', 'History'], ['raw', 'Raw data']];

const OVERVIEW_CARDS = [
    ['Status', ['PWR', 'PWSTATUS', 'SOURCE', 'SIGNAL', 'ERR', 'MUTE', 'MSEL', 'FREEZE']],
    ['Image & projection', ['ASPECT', 'CMODE', 'LUMINANCE', 'LUMCONST', 'BRIGHT', 'CONTRAST', 'TINT', 'ZOOM', 'AUTOKEYSTONE', 'VKEYSTONE', 'HKEYSTONE', 'HREVERSE', 'VREVERSE']],
    ['Audio & captions', ['AUDIO', 'VOL', 'TONEH', 'TONEL', 'CCAP']],
    ['Maintenance', ['LAMP', 'LAMPS', 'ONTIME', 'FILTER', 'FLWARNING']],
];

const cmdOf = (p, n) => p.commands?.[n];
const okCmd = (p, n) => {
    const c = cmdOf(p, n);
    return c && c.status === 'ok' ? c : null;
};
const kv = (label, html) => `<dt>${esc(label)}</dt><dd>${html}</dd>`;
const kvCmd = (p, n, label) => {
    const c = okCmd(p, n);
    return c ? kv(label || c.description, esc(c.display)) : '';
};
const card = (title, body, cls = '') => `<section class="panel ${cls}"><h3>${esc(title)}</h3>${body}</section>`;

function detailNeighbors(id) {
    const ids = visibleList().map(it => it.p.id);
    const i = ids.indexOf(id);
    return i < 0 ? { i: -1, n: ids.length } : { i, n: ids.length, prev: ids[(i - 1 + ids.length) % ids.length], next: ids[(i + 1) % ids.length] };
}

function heroTile(label, html, cls = '') {
    return `<div class="hero-tile ${cls}"><span class="h-label">${esc(label)}</span><span class="h-value">${html}</span></div>`;
}

function renderDetailTop(p, d) {
    const nb = detailNeighbors(p.id);
    const since = d.stateSince ? `<span class="dim" title="${esc(fmtTime(d.stateSince))}">changed ${esc(ago(d.stateSince))}</span>` : '';
    const err = okCmd(p, 'ERR');
    const filter = d.filterH === null ? '<span class="dim">-</span>' : `${num(d.filterH)} h`;
    const lampHtml = d.lamp === null ? '<span class="dim">-</span>' : `${num(d.lamp)} h<span class="sub">${Math.round((d.lamp / settings.lampWarn) * 100)}% of ${num(settings.lampWarn)} h limit</span>${`<span class="bar ${d.lampPct >= 100 ? 'crit' : d.lampPct >= 75 ? 'warn' : ''}"><i style="width:${d.lampPct}%"></i></span>`}`;

    $('#d-top').innerHTML = `
      <div class="d-nav">
        <button class="ghost" data-act="back">${icon('left')}All projectors</button>
        <span class="spacer"></span>
        ${nb.i >= 0 ? `<span class="dim">${nb.i + 1} / ${nb.n}</span><button class="icon-btn" data-act="goto" data-id="${esc(nb.prev)}" title="Previous (←)">${icon('left')}</button><button class="icon-btn" data-act="goto" data-id="${esc(nb.next)}" title="Next (→)">${icon('right')}</button>` : ''}
      </div>
      <div class="d-head">
        <div>
          <h2>${esc(d.name)} ${pill(d)} ${since}</h2>
          <div class="meta">
            <span class="mono">${esc(p.host)}</span><button class="icon-btn sm" data-act="copy" data-text="${esc(p.host)}" title="Copy IP">${icon('copy')}</button>
            ${d.model ? `<span>· model type ${esc(d.model)}</span>` : ''}${p.serialNumber ? `<span>· S/N ${esc(p.serialNumber)}</span>` : ''}${p.macAddress ? `<span class="mono">· ${esc(p.macAddress)}</span>` : ''}${d.firmware ? `<span>· FW ${esc(d.firmware)}</span>` : ''}
          </div>
        </div>
        <div class="d-actions">
          <a class="btn" href="http://${esc(p.host)}/" target="_blank" rel="noopener">${icon('external')}Web UI</a>
          <button data-act="refresh-one">${icon('refresh')}Refresh now</button>
        </div>
      </div>
      ${d.alerts.map(a => `<div class="notice ${a.level}">${icon('alert')}${esc(a.text)}${p.connection.error && !d.online ? ` <span class="dim">— ${esc(p.connection.error)}</span>` : ''}</div>`).join('')}
      ${d.online && d.st === 'standby' ? `<div class="notice info">${icon('power')}In standby: most settings and signal data can only be read while the projector is on.</div>` : ''}
      <div class="hero">
        ${heroTile('Power', `${esc(d.pwrDisplay || d.meta.label)}`, `s-${d.st}`)}
        ${heroTile('Source', d.source ? esc(d.source) : '<span class="dim">-</span>')}
        ${heroTile('Signal', d.signal ? esc(d.signal.display) : '<span class="dim">-</span>')}
        ${heroTile('Error', err ? esc(err.display) : '<span class="dim">-</span>', err && err.value !== '00' ? 'crit' : '')}
        ${heroTile('Lamp', lampHtml, d.lampHigh ? 'warn' : '')}
        ${heroTile('On-time', d.ontime === null ? '<span class="dim">-</span>' : `${num(d.ontime)} h`)}
        ${heroTile('Filter', filter)}
        ${heroTile('Mute / Freeze', okCmd(p, 'MUTE') || okCmd(p, 'FREEZE') ? flagBadges(d) || '<span class="dim">off</span>' : '<span class="dim">-</span>')}
      </div>
      <nav class="tabs" role="tablist">${TABS.map(([k, l]) => `<button role="tab" class="${state.route.tab === k ? 'active' : ''}" data-act="tab" data-tab="${k}">${l}${k === 'commands' ? ` <span class="dim">${Object.keys(p.commands || {}).length}</span>` : ''}</button>`).join('')}</nav>`;
}

// ---- tab bodies ----

function overviewTab(p, d) {
    const cards = OVERVIEW_CARDS.map(([title, names]) => {
        const rows = names.map(n => kvCmd(p, n)).join('');
        const missing = names.filter(n => cmdOf(p, n) && !okCmd(p, n)).length;
        return card(title, (rows ? `<dl class="kv">${rows}</dl>` : '<p class="dim">Not available right now.</p>') +
            (missing && rows ? `<p class="dim small">${missing} more not readable in this state</p>` : ''), rows ? '' : 'muted');
    });

    const sl = okCmd(p, 'SOURCELIST')?.value;
    const cur = okCmd(p, 'SOURCE')?.value;
    cards.push(card('Inputs', sl?.length
        ? `<div class="chips">${sl.map(s => `<span class="chip ${s.code === cur ? 'active' : ''}" title="code ${esc(s.code)}">${esc(s.name)}</span>`).join('')}</div>${cur ? '' : '<p class="dim small">Active input is only reported while the projector is on.</p>'}`
        : '<p class="dim">Source list not available.</p>', sl?.length ? '' : 'muted'));

    const disc = p.discovery;
    cards.push(card('Identity', `<dl class="kv">
        ${kv('Name', esc(d.name))}${kvCmd(p, 'IMNWPNAME', 'Network name')}${p.serialNumber ? kv('Serial number', esc(p.serialNumber)) : ''}
        ${p.macAddress ? kv('Wired MAC', esc(p.macAddress)) : ''}${kvCmd(p, 'NWWLMAC', 'Wireless MAC')}
        ${d.firmware ? kv('Firmware', esc(d.firmware)) : ''}${(okCmd(p, 'VER')?.value?.otherBanks || []).length ? kv('Other firmware', esc(okCmd(p, 'VER').value.otherBanks.join(', '))) : ''}
        ${disc ? kv('Model type', esc(disc.imType || '-')) + kv('Command type', esc(disc.commandType || '-')) + kv('Discovered via', esc(disc.via)) + kv('Last seen (UDP)', esc(ago(disc.lastSeenAt))) : ''}
    </dl>`));

    const c = p.connection;
    cards.push(card('Connection', `<dl class="kv">
        ${kv('Status', `<span class="badge ${p.online ? 'ok' : 'warn'}">${esc(c.status)}</span>`)}${kv('Protocol', esc(c.protocolVersion || '-'))}
        ${kv('Last poll', esc(ago(p.lastPollAt)) + (p.lastPollDurationMs ? ` <span class="dim">(${p.lastPollDurationMs} ms)</span>` : ''))}
        ${kv('Last connected', esc(ago(c.lastConnectedAt)))}${kv('Last attempt', esc(ago(c.lastAttemptAt)))}${kv('Failed attempts', esc(c.consecutiveFailures))}
        ${c.error ? kv('Last error', `<span class="err">${esc(c.error)}</span>`) : ''}
    </dl>`));
    return `<div class="panels">${cards.join('')}</div>`;
}

function networkTab(p) {
    const net = okCmd(p, 'NWCNF')?.value;
    const wl = (okCmd(p, 'NWWLCNFS') || okCmd(p, 'NWWLCNF'))?.value;
    const sec = okCmd(p, 'NWWLSEC')?.value;
    const dns = c => { const v = okCmd(p, c)?.value; return v ? kv('DNS', esc(`${v.primary}${v.secondary ? ', ' + v.secondary : ''}`)) : ''; };
    const ipRows = v => v ? kv('DHCP', v.dhcp === null ? '-' : v.dhcp ? 'On' : 'Off') + kv('IP address', `<span class="mono">${esc(v.ip)}</span>`) + kv('Subnet mask', `<span class="mono">${esc(v.subnet)}</span>`) + kv('Gateway', `<span class="mono">${esc(v.gateway)}</span>`) : '';
    const wired = [kvCmd(p, 'NWIF', 'Active interface'), kvCmd(p, 'NWPRIMIF', 'Priority interface'), kvCmd(p, 'NWMAC', 'MAC address'), ipRows(net), dns('NWDNS'), kvCmd(p, 'NWIPDISP', 'IP shown on projector')].join('');
    const wireless = [kvCmd(p, 'NWWLMAC', 'MAC address'), wl ? kv('ESSID', esc(wl.essid || '-')) + kv('Ad-hoc', wl.adHoc ? 'Yes' : 'No') : '', ipRows(wl),
        sec ? kv('Encryption', esc(sec.encryption)) + kv('Key length', esc(sec.keyLength)) + kv('EAP', esc(sec.eap)) + kv('Authentication', esc(sec.authentication)) : '',
        dns('NWWLDNS'), kvCmd(p, 'NWWLIPDISP', 'IP shown on projector'), kvCmd(p, 'NWESSDISP', 'ESSID display')].join('');
    return `<div class="panels">
        ${card('Wired LAN', wired ? `<dl class="kv">${wired}</dl>` : '<p class="dim">Network data not available. It is read every few minutes while the projector is reachable.</p>', wired ? '' : 'muted')}
        ${card('Wireless LAN', wireless ? `<dl class="kv">${wireless}</dl>` : '<p class="dim">No wireless data reported.</p>', wireless ? '' : 'muted')}
    </div>`;
}

function commandsRows(p) {
    const q = state.cmdQuery.trim().toLowerCase();
    const rows = Object.values(p.commands || {}).filter(c => (state.cmdStatus === 'all' || c.status === state.cmdStatus) &&
        (!q || `${c.command} ${c.description} ${c.category} ${c.display} ${c.raw}`.toLowerCase().includes(q)));
    if (!rows.length) return '<tr><td colspan="6" class="dim center">No commands match.</td></tr>';
    return rows.map(c => `<tr class="${c.status === 'ok' ? '' : 'is-off'}" title="Last OK: ${esc(fmtTime(c.lastOkAt))} · Changed: ${esc(fmtTime(c.changedAt))}">
        <td><code>${esc(c.query)}</code></td><td>${esc(c.description)}${c.documented ? '' : ' <span class="badge grey">undocumented</span>'}<div class="dim small">${esc(c.category)}</div></td>
        <td>${c.status === 'ok' ? esc(c.display) : c.status === 'unsupported' ? '<span class="dim">ERR (unsupported or unavailable now)</span>' : `<span class="err">${esc(c.error || 'error')}</span>`}</td>
        <td class="mono dim wrap">${esc(c.raw ?? '')}</td>
        <td><span class="badge ${c.status === 'ok' ? 'ok' : c.status === 'error' ? 'crit' : 'grey'}">${esc(c.status)}</span></td>
        <td class="dim nowrap">${esc(ago(c.updatedAt))}</td></tr>`).join('');
}

function commandsTab(p) {
    const counts = { ok: 0, unsupported: 0, error: 0 };
    Object.values(p.commands || {}).forEach(c => { counts[c.status] = (counts[c.status] || 0) + 1; });
    const opt = (v, l) => `<option value="${v}" ${state.cmdStatus === v ? 'selected' : ''}>${l}</option>`;
    return `<div class="toolbar inner">
        <label class="search sm">${icon('search')}<input id="cmd-search" type="search" placeholder="Filter commands..." value="${esc(state.cmdQuery)}" autocomplete="off"></label>
        <select id="cmd-status">${opt('ok', `Readable (${counts.ok})`)}${opt('unsupported', `Unsupported / unavailable (${counts.unsupported})`)}${opt('error', `Errors (${counts.error})`)}${opt('all', 'All')}</select>
    </div>
    <div class="table-wrap"><table class="cmds"><thead><tr><th>Query</th><th>Description</th><th>Value</th><th>Raw</th><th>Status</th><th>Updated</th></tr></thead><tbody id="cmd-rows">${commandsRows(p)}</tbody></table></div>`;
}

function historyTab() {
    if (!state.history) return '<p class="dim">Loading...</p>';
    const f = state.histFilter;
    const items = state.history.filter(h => f === 'all' || h.type === f);
    const opt = (v, l) => `<option value="${v}" ${f === v ? 'selected' : ''}>${l}</option>`;
    return `<div class="toolbar inner"><select id="hist-filter">${opt('all', 'All changes')}${opt('command', 'Command values')}${opt('connection', 'Connection')}</select><span class="dim">Since the server started; newest first</span></div>` +
        (items.length ? `<div class="timeline">${items.map(h => `<div class="tl-item ${h.type}"><span class="dim when" title="${esc(fmtTime(h.at))}">${esc(new Date(h.at).toLocaleTimeString())}<br><small>${esc(ago(h.at))}</small></span><span class="tl-text">${describeHistory(h)}</span></div>`).join('')}</div>` : '<p class="dim">No changes recorded yet.</p>');
}

function rawTab(p) {
    return `<div class="toolbar inner"><button data-act="copy" data-text="${esc(JSON.stringify(p, null, 2))}">${icon('copy')}Copy JSON</button></div><pre class="raw">${esc(JSON.stringify(p, null, 2))}</pre>`;
}

// ---- page ----

function renderDetail(full = true) {
    const p = state.byId.get(state.route.id);
    if (!p) {
        $('#d-top').innerHTML = `<div class="d-nav"><button class="ghost" data-act="back">${icon('left')}All projectors</button></div>`;
        $('#d-body').innerHTML = `<p class="empty">${state.lastFetch ? 'Unknown projector.' : 'Loading...'}</p>`;
        return;
    }
    const d = D(p);
    renderDetailTop(p, d);
    const body = $('#d-body');
    if (!full && body.contains(document.activeElement) && document.activeElement.matches('input,select')) return;
    const scroll = window.scrollY;
    const tab = state.route.tab;
    body.innerHTML = tab === 'network' ? networkTab(p) : tab === 'commands' ? commandsTab(p) : tab === 'history' ? historyTab() : tab === 'raw' ? rawTab(p) : overviewTab(p, d);
    window.scrollTo(0, scroll);
}

async function loadHistory() {
    const id = state.route.id;
    try {
        const h = DEMO ? [] : await api(`/api/projectors/${encodeURIComponent(id)}/history?limit=300`);
        if (state.route.id === id) state.history = h;
    } catch {
        state.history = [];
    }
    if (state.route.page === 'detail' && state.route.tab === 'history') renderDetail(false);
}
