'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { catalog } = require('./commands');

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };

function createApi(manager, { startedAt = Date.now(), clientDir = null } = {}) {
    const serveStatic = (req, res, pathname) => {
        const rel = pathname === '/' ? 'index.html' : decodeURIComponent(pathname).replace(/^\/+/, '');
        const file = clientDir && path.resolve(clientDir, rel);
        const type = file && MIME[path.extname(file)];
        if (req.method !== 'GET' || !type || !file.startsWith(path.resolve(clientDir) + path.sep) || !fs.existsSync(file)) {
            return send(res, 404, { error: 'Not found' });
        }
        res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-cache' });
        fs.createReadStream(file).pipe(res);
    };

    const send = (res, status, body) => {
        let payload = Buffer.from(JSON.stringify(body));
        const headers = {
            'Content-Type': 'application/json; charset=utf-8',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
        };
        if (payload.length > 1024 && /\bgzip\b/.test(res.req?.headers['accept-encoding'] ?? '')) {
            payload = zlib.gzipSync(payload);
            headers['Content-Encoding'] = 'gzip';
        }
        headers['Content-Length'] = payload.length;
        res.writeHead(status, headers);
        res.end(payload);
    };

    const handle = (req, res) => {
        if (req.method === 'OPTIONS') return send(res, 204, {});
        const url = new URL(req.url, 'http://localhost');
        const parts = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
        if (parts[0] !== 'api') return serveStatic(req, res, url.pathname);
        const route = parts.slice(1);
        const isGet = req.method === 'GET';
        const isPost = req.method === 'POST';

        if (isGet && route.length === 1 && route[0] === 'health') {
            return send(res, 200, { status: 'ok', projectors: manager.projectors.size, uptimeSeconds: Math.round((Date.now() - startedAt) / 1000) });
        }
        if (isGet && route.length === 1 && route[0] === 'commands') return send(res, 200, catalog());

        if (isGet && route.length === 1 && route[0] === 'history') {
            const limit = Math.max(1, Math.min(Number(url.searchParams.get('limit')) || 100, 1000));
            const feed = manager.list().flatMap(p => p.history.map(h => ({ host: p.host, name: p.summary().name, ...h })));
            return send(res, 200, feed.sort((a, b) => (a.at < b.at ? 1 : -1)).slice(0, limit));
        }

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
