# ratel web: HTTP API

Served by `ratel web` (unprivileged; reads what `ratel watch` writes). All JSON.
Times are Unix seconds (float) unless a field says `time` (local string).
Every `/api/*` route needs a session cookie (see Auth); without one they return
`401 {"error":"login"}` and the frontend should go to `/login`.

## Auth
- `GET /login`: login page (served by the backend, not the SPA).
- `POST /login` (form field `token`): on success sets cookie `ratel_session`
  (HttpOnly, SameSite=Strict, Path=/) and redirects to `/`.
- `POST /logout`: clears the session; requires the CSRF header; returns `{"ok":true}`.
- A failed login redirects to `/login?error=1#error` (the login page shows the error via CSS `:target`).
- Status: `alive` is false whenever `stopped` is true.
- `GET /api/session` → `{"csrf": "<hex>", "expires": <t>}`. Every POST from the
  SPA must send header `X-Ratel-CSRF: <csrf>`.

## Read endpoints
### `GET /api/status`
The daemon's status file, plus `alive` and `age_s` computed by the server:
```json
{"alive": true, "age_s": 12.3, "stopped": false, "pid": 1234, "version": "0.1.0",
 "updated": 1793600000.0, "started": 1793590000.0, "uptime_s": 10000,
 "events": 123456, "netns": 3,
 "engine": {"entities": 42, "flows": 120, "connections": 300, "dns_domains": 80, "names": 900,
            "history_hours": 2.8, "learning": true},
 "capture": {"packets": 5000, "dropped": 0},
 "alerts": {"high": 2, "medium": 5, "low": 9},
 "last_alert": {"time": "2026-11-01 23:11:00", "title": "..."} | null,
 "notify_failures": 0,
 "extra": {"open_incidents": 3, "suppressions": 1, "capture": true, "root": true}}
```
If the daemon has never written a status file: `{"alive": false, "missing": true}`.

### `GET /api/live`
Snapshot written by the daemon every 30 s:
```json
{"updated": 1793600000.0, "learning": true, "history_hours": 2.8,
 "flows": [ {"entity": "/usr/sbin/nginx", "pid": 812, "dest": "203.0.113.9",
             "name": "files.example.net" | null, "port": 443, "class": "public|private|overlay",
             "inbound": false, "out10": 1200000, "in10": 4000, "out60": 80000000, "in60": 90000,
             "conns60": 4, "first_seen": 1793599000.0, "last_seen": 1793600000.0} ],
 "entities": [ {"name": "/usr/sbin/nginx", "first_seen": 1793500000.0, "server": true,
                "out24h": 123456789, "known_destinations": 812, "usual_peak_hour": 2000000 | null,
                "flag": 0, "static": "low 0.32 [network]" | null} ],
 "dns": [ {"entity": "?" , "domain": "example.com", "queries10": 12, "unique10": 3} ]}
```
`flows` are the busiest flows of the last 10 minutes (up to 100), `entities`
the processes seen in the last 24 h (up to 100, by upload), `dns` the busiest
base domains of the last 10 minutes (up to 50).

### `GET /api/alerts?since=<seconds back, default 86400>&min=<low|medium|high>&limit=<0..1000, default 1000>`
`limit=0` returns only `counts` and `hourly` (cheap, for the overview). `hourly` always covers
the last 48 h regardless of `since`. Alerts in this list carry no `context` (see the incident).
```json
{"alerts": [ <alert>, ... newest first, at most 1000 ],
 "counts": {"high": 1, "medium": 2, "low": 3},
 "hourly": [ {"t": 1793596400.0, "high": 0, "medium": 1, "low": 0}, ... 48 entries, oldest first ]}
```
An `<alert>` is a line of `alerts.jsonl`:
```json
{"t": 1793600000.0, "severity": "high|medium|low", "kind": "exfil|beacon|dns|dga|icmp|scan|flood|spam|mining|flow|process|file|health",
 "entity": "/usr/bin/python3.12 [x.py]", "pid": 544, "dest": "203.0.113.9 (name)" | "", "score": 0.9,
 "title": "...", "evidence": ["...", "model score 0.98 because of: ..."],
 "incident": "20261101-192000-exfil" | absent, "context": {...} | absent}
```

### `GET /api/incidents?limit=<n, default 200>`
```json
{"incidents": [ {"id": "20261101-192000-exfil", "t": 1793600000.0, "time": "2026-11-01 19:20:00",
                 "title": "...", "severity": "high", "kinds": ["exfil", "beacon"], "alerts": 2,
                 "entities": ["/usr/bin/x"],
                 "ack": null | {"t": 1793600100.0, "fp": true, "note": "backup job"} } ]}
```
Newest first.

### `GET /api/incident/<id>`
```json
{"id": "...", "t": 1793600000.0, "time": "2026-11-01 19:20:00", "title": "...", "severity": "high", "kinds": ["exfil"],
 "alerts": [ <alert>, ... ],
 "context": {"process": {"pid": 544, "user": "root", "uid": 0, "exe": "/usr/bin/python3.14",
                          "sha256": "...", "origin": {"kind": "package|modified|allowlisted|unknown", "pkg": "python"},
                          "cmdline": "...", "cwd": "...", "started": "2026-11-01 19:19:41",
                          "container": null, "parents": ["541 timeout 500 ...", "..."], "open_fds": 12}
                         | {"pid": 544, "gone": true},
             "profile": {"first_seen": 1793599000.0, "server": true, "known_destinations": 3,
                         "usual_peak_hour_upload": null, "largest_hour_to_one_host": 0, "static": null},
             "destination": {"ip": "203.0.113.9", "dns_name": null, "class": "Public",
                             "first_seen_by_entity": null, "first_seen_here": null}},
 "activity": {"endpoints": [ {"endpoint": "203.0.113.9:8443", "sent": 83900000, "received": 1,
                               "conns": 1, "first": 1793599990.0, "last": 1793600005.0} ],
              "dns": [ {"name": "a.b.example", "count": 3} ], "dns_total": 41,
              "flags": [ {"t": 1793600010.0, "rule": "reverse_shell", "detail": "..."} ],
              "events_before": 202, "events_after": 5},
 "ack": null | {"t": ..., "fp": false, "note": "..."}}
```
`404 {"error":"not found"}` for unknown ids.

## Actions
### `POST /api/ack` (JSON body, CSRF header required)
`{"id": "<incident>", "fp": true|false, "any_dest": false, "note": "optional"}`
→ `{"ok": true, "suppress": [["entity", "dest or *", "kind"], ...]}`. With `fp`, the running
monitor stops alerting on those (entity, destination, kind) within a minute, and announces
the new suppression as an alert. Unidentified entities (`unattributed`, `?`, `uid:N`, `host:…`)
never get a `*` destination; if nothing in the incident can be silenced the answer is
`422 {"error": "..."}` (mark it reviewed instead).
