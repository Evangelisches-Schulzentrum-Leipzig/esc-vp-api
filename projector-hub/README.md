# projector-hub

Read-only monitoring hub for Epson projectors (ESC/VP.net + ESC/VP21). The web client will live in `client/`.

## Client

Dependency-free static page in `client/`, served by the server at `http://localhost:3000/`.

- **Views:** table (sortable, column picker), cards, tiles (one compact tile per projector, built for ~50 at a glance)
  and insights (fleet status, lamp-hour histogram, alerts, sources in use, models, firmware, subnets, recent activity).
- **Overview tools:** clickable KPI filters, search, group by status/subnet/model/firmware/source, CSV export,
  highlighting of changed projectors, light/dark theme, configurable lamp-hour warning and refresh interval.
- **Detail page** (`#/p/<ip>`): key figures, grouped state, inputs, identity, connection, network, searchable command
  list, change history and raw JSON. `←`/`→` switch projectors, `Esc` goes back, `/` focuses search, `1`-`4` pick a view.
- The URL hash keeps view, filter, search and grouping, so views can be bookmarked or shared.
- `?demo=50` shows a synthetic fleet without a server. To host the page elsewhere use `?api=http://<server>:3000`.

## Server

```
cd server
npm start        # node index.js, no dependencies (Node >= 20)
npm test
```

On first start `server/config.json` is created from defaults (override the path with `ESCVP_CONFIG`). It holds:

- `credentials`: passwords tried in order on the first connection (`""` = no password).
- `protocol.versions`: protocol versions tried in order (`v2` digest, `v1` plain password).
- `discovery`: UDP HELLO broadcast on every local interface; add `broadcastAddresses` / `staticHosts` as needed.
- `polling`: `fastIntervalMs` (status/settings), `slowIntervalMs` (identity, network, hours), timeouts.
- `projectors`: learned `{ version, password }` per host, written after the first successful connection and reused
  afterwards. If they are rejected later, they are dropped and the credential list is tried again (at most every
  `authRetryMs` when everything fails, to avoid password lockouts).

`config.json` contains passwords and is git-ignored.

Only get-style queries (`CMD?`) are ever sent; the session layer rejects anything else. All spec get commands plus
observed ones (`PWSTATUS`, `VER`, `LAMPS`, `NWESSDISP`) are polled; get forms of the step commands (`VOL`, `BRIGHT`, ...)
and `MENUINFO? 00` are inferred and flagged `documented: false` (see `GET /api/commands`). A reply of `ERR` is stored
as `unsupported` (the protocol cannot distinguish unsupported from unavailable-in-this-state). The wireless WEP key is
redacted from `NWWLCNF`.

## REST API (no auth, CORS open)

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Liveness, projector count |
| GET | `/api/projectors` | Summaries; `?details=full` returns every projector with all command results |
| GET | `/api/projectors/:id` | Full state (`id` = IP address) |
| GET | `/api/projectors/:id/commands/:cmd` | One command result |
| GET | `/api/projectors/:id/history?limit=100` | Recent state/connection changes, newest first |
| GET | `/api/commands` | Command catalog |
| POST | `/api/discovery` | Run discovery now |
| POST | `/api/projectors/:id/refresh` | Poll that projector now |

Each command result: `status` (`ok` / `unsupported` / `error`), `raw`, `value` (structured), `display`, `updatedAt`,
`lastOkAt`, `changedAt`. Connection status is one of `online`, `unreachable`, `auth-failed`, `unsupported`, `refused`, `busy`.
