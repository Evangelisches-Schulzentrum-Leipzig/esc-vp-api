'use strict';
const http = require('http');
const { catalog } = require('./commands');

function createApi(manager, { startedAt = Date.now() } = {}) {
    const send = (res, status, body) => {
        const json = JSON.stringify(body);
        res.writeHead(status, {
            'Content-Type': 'application/json; charset=utf-8',
            'Content-Length': Buffer.byteLength(json),
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
        });
        res.end(json);
    };

    const handle = (req, res) => {
        if (req.method === 'OPTIONS') return send(res, 204, {});
        const url = new URL(req.url, 'http://localhost');
        const parts = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
        if (parts[0] !== 'api') return send(res, 404, { error: 'Not found' });
        const route = parts.slice(1);
        const isGet = req.method === 'GET';
        const isPost = req.method === 'POST';

        if (isGet && route.length === 1 && route[0] === 'health') {
            return send(res, 200, { status: 'ok', projectors: manager.projectors.size, uptimeSeconds: Math.round((Date.now() - startedAt) / 1000) });
        }
        if (isGet && route.length === 1 && route[0] === 'commands') return send(res, 200, catalog());

        if (isPost && route.length === 1 && route[0] === 'discovery') {
            manager.discoverNow();
            return send(res, 202, { status: 'discovery started' });
        }

        if (route[0] === 'projectors') {
            if (route.length === 1 && isGet) {
                const full = url.searchParams.get('details') === 'full';
                return send(res, 200, manager.list().map(p => (full ? p.detail() : p.summary())));
            }
            const projector = route[1] ? manager.get(route[1]) : null;
            if (!projector) return send(res, 404, { error: 'Unknown projector' });

            if (route.length === 2 && isGet) return send(res, 200, projector.detail());
            if (route.length === 3 && route[2] === 'refresh' && isPost) {
                projector.refreshNow();
                return send(res, 202, { status: 'refresh scheduled' });
            }
            if (route.length === 3 && route[2] === 'history' && isGet) {
                const limit = Math.max(1, Math.min(Number(url.searchParams.get('limit')) || 100, 1000));
                return send(res, 200, projector.history.slice(-limit).reverse());
            }
            if (route.length === 4 && route[2] === 'commands' && isGet) {
                const cmd = projector.commands[route[3].toUpperCase()];
                return cmd ? send(res, 200, cmd) : send(res, 404, { error: 'Unknown or not yet polled command' });
            }
        }
        return send(res, 404, { error: 'Not found' });
    };

    return http.createServer((req, res) => {
        try {
            handle(req, res);
        } catch (err) {
            send(res, 500, { error: 'Internal error' });
        }
    });
}

module.exports = { createApi };
