'use strict';
// Routing, data refresh, popovers and event wiring.

const loadScript = src => new Promise((resolve, reject) => {
    document.head.append(Object.assign(document.createElement('script'), { src, onload: resolve, onerror: reject }));
});

// ---- data ----

function ingest(list) {
    derived.clear();
    state.byId = new Map(list.map(p => [p.id, p]));
    state.projectors = list;
    const first = state.prev.size === 0;
    const next = new Map();
    for (const p of list) {
        const d = derive(p);
        derived.set(p.id, d);
        const sig = `${d.st}|${d.source}`;
        next.set(p.id, sig);
        if (!first && state.prev.get(p.id) !== sig) state.flash.add(p.id);
    }
    state.prev = next;
    if (state.flash.size) setTimeout(() => state.flash.clear(), 4000);
}

async function refresh() {
    try {
        ingest(DEMO ? demoProjectors(Number(DEMO) || 50) : await api('/api/projectors?details=full'));
        state.lastFetch = new Date();
        state.fetchError = null;
        if (settings.view === 'insights' && state.route.page === 'list') {
            state.activity = DEMO ? demoActivity() : await api('/api/history?limit=50').catch(() => state.activity);
        }
        if (state.route.page === 'detail' && state.route.tab === 'history') loadHistory();
    } catch (err) {
        state.fetchError = err.message;
    }
    render();
}

let timer = null;
function restartTimer() {
    clearInterval(timer);
    if (settings.refreshSec > 0) timer = setInterval(() => !document.hidden && refresh(), settings.refreshSec * 1000);
}

// ---- rendering ----

function updateStatus() {
    const el = $('#fetch-state');
    const live = $('#live');
    live.className = 'live ' + (state.fetchError ? 'bad' : settings.refreshSec ? 'ok' : 'paused');
    el.textContent = state.fetchError ? `Server unreachable (${state.fetchError})`
        : !state.lastFetch ? 'Loading...' : `${settings.refreshSec ? 'Live' : 'Paused'} · updated ${ago(state.lastFetch.toISOString())}`;
    $('#banner').hidden = !state.fetchError;
    $('#banner').textContent = state.fetchError ? `Cannot reach the server (${state.fetchError}). Showing the last known data.` : '';
}

function render() {
    updateStatus();
    if (state.route.page === 'list') renderList(); else renderDetail(false);
}

function tick() {
    updateStatus();
    $$('[data-ago]').forEach(el => { el.textContent = ago(el.dataset.ago); });
}

// ---- routing ----

function listQuery() {
    const q = new URLSearchParams();
    if (settings.view !== 'table') q.set('view', settings.view);
    if (state.filter !== 'all') q.set('filter', state.filter);
    if (state.search) q.set('q', state.search);
    if (settings.group !== 'none') q.set('group', settings.group);
    const s = q.toString();
    return '#/' + (s ? '?' + s : '');
}
const syncHash = () => state.route.page === 'list' && history.replaceState(null, '', listQuery());

let listScroll = 0;
function applyRoute() {
    const [path, qs = ''] = (location.hash.replace(/^#/, '') || '/').split('?');
    const q = new URLSearchParams(qs);
    const m = path.match(/^\/p\/(.+)$/);
    if (m) {
        if (state.route.page === 'list') listScroll = window.scrollY;
        const id = decodeURIComponent(m[1]);
        if (state.route.id !== id) state.history = null;
        state.route = { page: 'detail', id, tab: q.get('tab') || 'overview' };
    } else {
        state.route = { page: 'list', id: null, tab: 'overview' };
        if (q.has('view') || q.has('filter') || q.has('q') || q.has('group')) {
            if (['table', 'cards', 'tiles', 'insights'].includes(q.get('view'))) settings.view = q.get('view');
            if (FILTERS[q.get('filter')]) state.filter = q.get('filter');
            if (GROUPS[q.get('group')]) settings.group = q.get('group');
            state.search = q.get('q') || '';
            $('#search').value = state.search;
        }
    }
    $('#list-page').hidden = state.route.page !== 'list';
    $('#detail-page').hidden = state.route.page !== 'detail';
    document.title = state.route.page === 'detail' ? `${state.byId.get(state.route.id)?.name || state.route.id} · Projector Hub` : 'Projector Hub';
    if (state.route.page === 'detail') {
        renderDetail(true);
        window.scrollTo(0, 0);
        if (state.route.tab === 'history') loadHistory();
    } else {
        if (settings.view === 'insights') refresh(); else renderList();
        window.scrollTo(0, listScroll);
    }
}

const openProjector = id => { location.hash = `#/p/${encodeURIComponent(id)}`; };
const backToList = () => { location.hash = listQuery(); };

function setTab(tab) {
    state.route.tab = tab;
    history.replaceState(null, '', `#/p/${encodeURIComponent(state.route.id)}${tab === 'overview' ? '' : '?tab=' + tab}`);
    if (tab === 'history') loadHistory();
    renderDetail(true);
}

// ---- popovers & toasts ----

function toast(msg) {
    const el = Object.assign(document.createElement('div'), { className: 'toast', textContent: msg });
    $('#toasts').append(el);
    setTimeout(() => el.remove(), 2600);
}

function closePopovers() { $$('.popover').forEach(p => { p.hidden = true; }); }
function togglePopover(id, anchor) {
    const pop = $('#' + id);
    const open = pop.hidden;
    closePopovers();
    if (!open) return;
    pop.hidden = false;
    const r = anchor.getBoundingClientRect();
    pop.style.top = `${r.bottom + 6}px`;
    pop.style.left = `${Math.max(8, Math.min(r.right - pop.offsetWidth, innerWidth - pop.offsetWidth - 8))}px`;
}

function fillSettings() {
    const opt = (v, l, cur) => `<option value="${v}" ${String(cur) === String(v) ? 'selected' : ''}>${l}</option>`;
    $('#set-theme').innerHTML = [['auto', 'System'], ['dark', 'Dark'], ['light', 'Light']].map(([v, l]) => opt(v, l, settings.theme)).join('');
    $('#set-density').innerHTML = [['comfortable', 'Comfortable'], ['compact', 'Compact']].map(([v, l]) => opt(v, l, settings.density)).join('');
    $('#set-refresh').innerHTML = [[5, '5 s'], [10, '10 s'], [30, '30 s'], [60, '1 min'], [0, 'Paused']].map(([v, l]) => opt(v, l, settings.refreshSec)).join('');
    $('#set-lamp').value = settings.lampWarn;
    $('#col-list').innerHTML = COLUMNS.map(c => `<label><input type="checkbox" data-col="${c.key}" ${settings.columns.includes(c.key) ? 'checked' : ''}>${c.label}</label>`).join('');
}

function copyText(text) {
    const done = () => toast('Copied to clipboard');
    if (navigator.clipboard?.writeText) return navigator.clipboard.writeText(text).then(done, () => toast('Copy failed'));
    const ta = Object.assign(document.createElement('textarea'), { value: text });
    document.body.append(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
    done();
}

// ---- events ----

function rerenderAll() {
    ingest(state.projectors);
    render();
}

document.addEventListener('click', e => {
    const t = e.target;
    if (!t.closest('.popover') && !t.closest('[data-pop]')) closePopovers();

    const pop = t.closest('[data-pop]');
    if (pop) return togglePopover(pop.dataset.pop, pop);

    const act = t.closest('[data-act]');
    if (act) {
        const a = act.dataset.act;
        if (a === 'back') return backToList();
        if (a === 'goto') return openProjector(act.dataset.id);
        if (a === 'tab') return setTab(act.dataset.tab);
        if (a === 'copy') return copyText(act.dataset.text);
        if (a === 'refresh-one') {
            if (!DEMO) api(`/api/projectors/${encodeURIComponent(state.route.id)}/refresh`, { method: 'POST' }).catch(() => {});
            toast('Refresh requested');
            return setTimeout(refresh, 1500);
        }
    }

    const view = t.closest('[data-view]');
    if (view) {
        settings.view = view.dataset.view;
        saveSettings();
        syncHash();
        return settings.view === 'insights' ? refresh() : renderList();
    }
    const kpi = t.closest('[data-kpi]');
    if (kpi) { state.filter = state.filter === kpi.dataset.kpi ? 'all' : kpi.dataset.kpi; syncHash(); return renderList(); }
    const th = t.closest('[data-sort]');
    if (th) {
        const key = th.dataset.sort;
        settings.sort = { key, dir: settings.sort.key === key ? -settings.sort.dir : 1 };
        saveSettings();
        return renderList();
    }
    const grp = t.closest('.group-h');
    if (grp) {
        const g = grp.dataset.group;
        if (!state.collapsed.delete(g)) state.collapsed.add(g);
        return renderList();
    }
    const item = t.closest('#content [data-id]');
    if (item) return openProjector(item.dataset.id);

    if (t.closest('#btn-clear')) {
        state.filter = 'all'; state.search = ''; $('#search').value = '';
        syncHash();
        return renderList();
    }
    if (t.closest('#btn-export')) return exportCsv();
    if (t.closest('#sort-dir')) { settings.sort.dir *= -1; saveSettings(); return renderList(); }
    if (t.closest('#btn-refresh')) { refresh(); return toast('Refreshed'); }
    if (t.closest('#btn-discover')) {
        if (!DEMO) api('/api/discovery', { method: 'POST' }).catch(() => {});
        toast('Network discovery started');
        return setTimeout(refresh, 4500);
    }
});

document.addEventListener('input', e => {
    const t = e.target;
    if (t.id === 'search') { state.search = t.value; syncHash(); renderList(); }
    else if (t.id === 'cmd-search') {
        state.cmdQuery = t.value;
        const p = state.byId.get(state.route.id);
        if (p) $('#cmd-rows').innerHTML = commandsRows(p);
    } else if (t.id === 'set-lamp') {
        settings.lampWarn = Math.max(1, Number(t.value) || 4000);
        saveSettings();
        rerenderAll();
    }
});

document.addEventListener('change', e => {
    const t = e.target;
    if (t.id === 'group-by') { settings.group = t.value; saveSettings(); syncHash(); renderList(); }
    else if (t.id === 'sort-by') { settings.sort.key = t.value; saveSettings(); renderList(); }
    else if (t.id === 'cmd-status') { state.cmdStatus = t.value; renderDetail(true); }
    else if (t.id === 'hist-filter') { state.histFilter = t.value; renderDetail(true); }
    else if (t.id === 'set-theme') { settings.theme = t.value; saveSettings(); applyTheme(); }
    else if (t.id === 'set-density') { settings.density = t.value; saveSettings(); applyTheme(); }
    else if (t.id === 'set-refresh') { settings.refreshSec = Number(t.value); saveSettings(); restartTimer(); updateStatus(); }
    else if (t.dataset.col) {
        settings.columns = COLUMNS.map(c => c.key).filter(k => (k === t.dataset.col ? t.checked : settings.columns.includes(k)));
        saveSettings();
        renderList();
    }
});

document.addEventListener('keydown', e => {
    const typing = e.target.matches('input,select,textarea');
    if (e.key === 'Escape') {
        if ($$('.popover').some(p => !p.hidden)) return closePopovers();
        if (typing) return e.target.blur();
        if (state.route.page === 'detail') return backToList();
        return;
    }
    if (e.key === 'Enter' && e.target.matches('.card[data-id]')) return openProjector(e.target.dataset.id);
    if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.key === '/' && state.route.page === 'list') { e.preventDefault(); $('#search').focus(); }
    else if (state.route.page === 'detail' && (e.key === 'ArrowLeft' || e.key === 'ArrowRight')) {
        const nb = detailNeighbors(state.route.id);
        if (nb.i >= 0) openProjector(e.key === 'ArrowLeft' ? nb.prev : nb.next);
    } else if (state.route.page === 'list' && '1234'.includes(e.key) && e.key) {
        settings.view = ['table', 'cards', 'tiles', 'insights'][Number(e.key) - 1];
        saveSettings();
        syncHash();
        settings.view === 'insights' ? refresh() : renderList();
    }
});

window.addEventListener('hashchange', applyRoute);
document.addEventListener('visibilitychange', () => !document.hidden && refresh());

// ---- init ----

(async function init() {
    applyTheme();
    $$('[data-icon]').forEach(el => el.insertAdjacentHTML('afterbegin', icon(el.dataset.icon)));
    if (DEMO) await loadScript('js/demo.js');
    fillSettings();
    applyRoute();
    await refresh();
    restartTimer();
    setInterval(tick, 1000);
})();
