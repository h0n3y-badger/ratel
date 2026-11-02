// ratel web dashboard. Vanilla JS, no innerHTML anywhere: every string that
// reaches the page goes through textContent / text nodes / setAttribute.
'use strict';
(() => {
  const SEV = { high: 3, medium: 2, low: 1 };
  const SEVS = ['high', 'medium', 'low'];
  const WINDOWS = [[3600, '1 h'], [86400, '24 h'], [604800, '7 d'], [2592000, '30 d']];
  const REFRESH_MS = 30000;
  const SVGNS = 'http://www.w3.org/2000/svg';

  // ---------- DOM helpers ----------
  function setProps(e, props) {
    if (!props) return;
    for (const k of Object.keys(props)) {
      const v = props[k];
      if (v == null || v === false) continue;
      if (k === 'class') e.setAttribute('class', v);
      else if (k === 'text') e.textContent = vis(String(v));
      else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2), v);
      else if (!(e instanceof SVGElement) && k in e) e[k] = v;
      else e.setAttribute(k, v === true ? '' : String(v));
    }
  }
  function append(e, kids) {
    for (const k of kids) {
      if (k == null || k === false) continue;
      if (Array.isArray(k)) append(e, k);
      else e.append(k instanceof Node ? k : vis(String(k)));
    }
  }
  function el(tag, props, ...kids) {
    const e = document.createElement(tag);
    setProps(e, props);
    append(e, kids);
    return e;
  }
  function svg(tag, attrs, ...kids) {
    const e = document.createElementNS(SVGNS, tag);
    setProps(e, attrs);
    append(e, kids);
    return e;
  }
  const $ = (id) => document.getElementById(id);
  const muted = (t) => el('span', { class: 'muted' }, t);
  const mono = (t) => el('code', { class: 'mono' }, str(t));
  const tag = (t, cls) => el('span', { class: 'tag' + (cls ? ' ' + cls : '') }, t);
  const uniq = (xs) => [...new Set(xs)];
  const incHref = (id) => '#/incident/' + encodeURIComponent(id);
  // Attacker-controlled text (process names, DNS names, paths) may carry bidi overrides or
  // invisible characters that make it *look* like something else; show them as escapes.
  const INVIS = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g;
  function vis(t) {
    return t.replace(INVIS, (c) => '\\u{' + c.codePointAt(0).toString(16) + '}');
  }
  function str(v) {
    if (v == null) return '—';
    if (typeof v === 'object') return JSON.stringify(v);
    return vis(String(v));
  }
  function join(nodes, sep) {
    const out = [];
    nodes.forEach((n, i) => { if (i) out.push(sep); out.push(n); });
    return out;
  }

  // ---------- formatting ----------
  const pad = (n) => String(n).padStart(2, '0');
  function num(n) {
    if (n == null || n === '' || isNaN(n)) return '—';
    return Number(n).toLocaleString('en-US', { maximumFractionDigits: 1 });
  }
  function bytes(n) {
    if (n == null || isNaN(n)) return '—';
    n = Number(n);
    if (Math.abs(n) < 1000) return Math.round(n) + ' B';
    const u = ['kB', 'MB', 'GB', 'TB', 'PB'];
    let i = -1;
    do { n /= 1000; i++; } while (Math.abs(n) >= 999.5 && i < u.length - 1);
    return (n < 10 ? n.toFixed(2) : n < 100 ? n.toFixed(1) : n.toFixed(0)) + ' ' + u[i];
  }
  function dur(sec) {
    sec = Math.max(0, Math.round(Number(sec) || 0));
    if (sec < 60) return sec + ' s';
    const m = Math.floor(sec / 60);
    if (m < 60) return m + ' min';
    const h = Math.floor(m / 60);
    if (h < 48) return h + ' h ' + (m % 60) + ' min';
    return Math.floor(h / 24) + ' d ' + (h % 24) + ' h';
  }
  function short(sec) {
    if (sec < 90) return Math.round(sec) + ' s';
    if (sec < 90 * 60) return Math.round(sec / 60) + ' min';
    if (sec < 48 * 3600) return Math.round(sec / 3600) + ' h';
    return Math.round(sec / 86400) + ' d';
  }
  function ago(t) {
    if (t == null || !isFinite(t)) return '—';
    const d = Date.now() / 1000 - t;
    if (Math.abs(d) < 10) return 'just now';
    return d < 0 ? 'in ' + short(-d) : short(d) + ' ago';
  }
  function stamp(t) {
    const d = new Date(t * 1000);
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' +
      pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }
  // Relative time, absolute in the tooltip.
  function when(t) {
    if (t == null || !isFinite(t)) return muted('—');
    return el('time', { class: 'when', title: stamp(t) }, ago(t));
  }
  function whenFull(t) {
    if (t == null || !isFinite(t)) return muted('—');
    return el('span', { class: 'when' }, stamp(t), ' ', muted('(' + ago(t) + ')'));
  }
  // Time of day (date in the tooltip): for events that cluster within minutes.
  function clock(t) {
    if (t == null || !isFinite(t)) return muted('—');
    return el('time', { class: 'when', title: stamp(t) + ' (' + ago(t) + ')' }, stamp(t).slice(11));
  }
  // Server fields are either Unix seconds or already-formatted local strings.
  function tval(v) {
    if (typeof v === 'number') return whenFull(v);
    return v == null ? muted('unknown') : str(v);
  }
  const sevOf = (x) => (SEV[x] ? x : 'low');
  const sevBadge = (x) => el('span', { class: 'sev sev-' + sevOf(x) }, sevOf(x));
  function ackTag(ack) {
    if (!ack) return tag('open', 'open');
    return ack.fp ? tag('false alarm', 'fp') : tag('reviewed', 'rev');
  }

  // ---------- API ----------
  class AuthError extends Error {}
  let csrf = null;
  function toLogin() {
    if (!toLogin.done) {
      toLogin.done = true;
      // remember where we were; login.html has no script, the SPA restores it after login
      try { if (location.hash.length > 2) sessionStorage.setItem('ratel.next', location.hash); } catch (e) { /* storage off */ }
      location.assign('/login');
    }
    throw new AuthError('login');
  }
  async function parse(r) {
    if (r.status === 401) toLogin();
    let body = null;
    try { body = await r.json(); } catch (e) { /* non-JSON */ }
    if (!r.ok) {
      const err = new Error((body && typeof body.error === 'string' && body.error) || 'HTTP ' + r.status);
      err.status = r.status;
      throw err;
    }
    return body;
  }
  async function api(path) {
    const r = await fetch(path, { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } });
    return parse(r);
  }
  const soft = (e) => { if (e instanceof AuthError) throw e; return null; };
  async function session(force) {
    if (!csrf || force) {
      const s = await api('/api/session');
      csrf = s && typeof s.csrf === 'string' ? s.csrf : null;
    }
    return csrf;
  }
  async function post(path, data) {
    for (let attempt = 0; ; attempt++) {
      const tok = await session(attempt > 0);
      const r = await fetch(path, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'Content-Type': 'application/json', 'X-Ratel-CSRF': tok || '' },
        body: JSON.stringify(data || {}),
      });
      if (r.status === 403 && attempt === 0) continue; // token may have rotated; refetch once
      return parse(r);
    }
  }

  // ---------- generic widgets ----------
  function card(title, ...kids) {
    return el('section', { class: 'card' }, title ? el('h2', null, title) : null, kids);
  }
  function kv(pairs) {
    const dl = el('dl', { class: 'kv' });
    for (const p of pairs) if (p) dl.append(el('dt', null, p[0]), el('dd', null, p[1]));
    return dl;
  }
  // cols: [{h, f(row) -> node|string|array, cls}]; the 'lead' column becomes
  // the card title on narrow screens.
  function table(cols, rows, empty) {
    if (!rows || !rows.length) return el('p', { class: 'empty' }, empty || 'Nothing here.');
    const t = el('table', { class: 'rt' },
      el('thead', null, el('tr', null, cols.map((c) => el('th', { class: c.cls }, c.h)))),
      el('tbody', null, rows.map((r) => el('tr', null, cols.map((c) =>
        el('td', { class: c.cls, 'data-label': c.h }, el('span', { class: 'cv' }, c.f(r))))))));
    return el('div', { class: 'tablewrap' }, t);
  }
  function seg(label, items) {
    return el('div', { class: 'seg' }, el('span', { class: 'seglbl' }, label),
      el('div', { class: 'segbtns' }, items.map(([href, text, on]) =>
        el('a', { href, class: on ? 'on' : null, 'aria-current': on ? 'true' : null }, text))));
  }
  function copyText(text, btn) {
    const done = (ok) => {
      btn.textContent = ok ? 'copied' : 'copy failed';
      setTimeout(() => { btn.textContent = 'copy'; }, 1500);
    };
    const fallback = () => {
      const ta = el('textarea', { class: 'offscreen', readOnly: true });
      ta.value = text;
      document.body.append(ta);
      ta.select();
      let ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      ta.remove();
      done(ok);
    };
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(() => done(true), fallback);
    else fallback();
  }
  function hashNode(h) {
    if (!h) return muted('—');
    h = String(h);
    const code = el('code', { class: 'mono hash', title: 'click to show the full hash' },
      h.length > 24 ? h.slice(0, 12) + '…' + h.slice(-8) : h);
    code.addEventListener('click', () => { code.textContent = h; code.classList.add('full'); });
    const btn = el('button', { type: 'button', class: 'btn tiny' }, 'copy');
    btn.addEventListener('click', () => copyText(h, btn));
    return el('span', { class: 'hashrow' }, code, btn);
  }
  function evidenceList(lines) {
    if (!Array.isArray(lines) || !lines.length) return null;
    return el('ul', { class: 'evidence' }, lines.map((l) =>
      el('li', { class: /^model score/i.test(String(l)) ? 'model' : null }, str(l))));
  }
  function alertCard(a, withLink) {
    const meta = [];
    if (a.entity) meta.push(mono(a.entity));
    if (a.pid) meta.push(muted('pid ' + a.pid));
    if (a.dest) meta.push(el('span', null, '→ ', mono(a.dest)));
    if (a.score != null) meta.push(muted('score ' + Number(a.score).toFixed(2)));
    return el('article', { class: 'alert s-' + sevOf(a.severity) },
      el('div', { class: 'ahead' },
        sevBadge(a.severity), tag(str(a.kind), 'kind'),
        el('span', { class: 'atitle' }, str(a.title)),
        el('span', { class: 'atime' }, when(a.t))),
      meta.length ? el('div', { class: 'ameta' }, join(meta, ' ')) : null,
      evidenceList(a.evidence),
      withLink && a.incident ? el('a', { class: 'more', href: incHref(a.incident) }, 'incident ' + a.incident + ' →') : null);
  }

  // 48-hour stacked bar chart, built with createElementNS.
  function hourlyChart(hourly) {
    hourly = Array.isArray(hourly) ? hourly : [];
    // Size the viewBox to the card's real width so axis text renders at 1:1.
    const mainW = ($('main').clientWidth || window.innerWidth) - 32;
    const W = Math.max(300, Math.round(mainW > 1000 ? (mainW - 12) / 2 - 30 : mainW - 22));
    const narrow = W < 560;
    const H = 150, L = 26, B = 18, T = 6;
    const n = Math.max(hourly.length, 1), bw = (W - L) / n, ph = H - B - T;
    const tot = hourly.map((h) => (h.high || 0) + (h.medium || 0) + (h.low || 0));
    const raw = Math.max(1, ...tot);
    const p10 = Math.pow(10, Math.floor(Math.log10(raw)));
    const max = [1, 2, 5, 10].map((m) => m * p10).find((m) => m >= raw);
    const y = (v) => T + ph - (v / max) * ph;
    const root = svg('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart', role: 'img',
      'aria-label': 'alerts per hour over the last 48 hours' });
    for (const v of [0, max / 2, max]) {
      root.append(svg('line', { x1: L, x2: W, y1: y(v), y2: y(v), class: 'grid' }));
      if (v === Math.round(v)) root.append(svg('text', { x: L - 4, y: y(v) + 3, class: 'axis', 'text-anchor': 'end' }, String(v)));
    }
    hourly.forEach((h, i) => {
      const x = L + i * bw;
      const g = svg('g', null, svg('title', null,
        stamp(h.t).slice(5, 16) + ' — ' + SEVS.map((s) => (h[s] || 0) + ' ' + s).join(', ')));
      g.append(svg('rect', { x, y: T, width: bw, height: ph, class: 'hit' }));
      let base = 0;
      for (const s of SEVS) {
        const v = h[s] || 0;
        if (!v) continue;
        g.append(svg('rect', { x: x + bw * 0.12, y: y(base + v), width: bw * 0.76, height: Math.max(1, y(base) - y(base + v)), class: 'b-' + s }));
        base += v;
      }
      root.append(g);
      const d = new Date(h.t * 1000);
      if (d.getHours() % (narrow ? 12 : 6) === 0) {
        root.append(svg('text', { x: x + bw / 2, y: H - 4, class: 'axis', 'text-anchor': 'middle' },
          d.getHours() === 0 ? pad(d.getMonth() + 1) + '-' + pad(d.getDate()) : pad(d.getHours()) + ':00'));
      }
    });
    const legend = el('div', { class: 'legend' }, SEVS.map((s) => el('span', null, el('i', { class: 'sw b-' + s }), s)));
    return el('div', { class: 'chartbox' }, root, legend);
  }

  // ---------- header ----------
  function renderHealth(st) {
    const pill = $('health'), meta = $('hmeta');
    const bits = [];
    let cls = 'grey', label = 'status unknown';
    if (st && st.missing) {
      cls = 'red'; label = 'NOT RUNNING';
      bits.push(muted('monitor has never written a status file'));
    } else if (st && st.stopped) {
      // The daemon wrote "stopped" on a clean exit; trust it over alive/age.
      cls = 'grey'; label = 'stopped cleanly';
      bits.push(muted('stopped ' + ago(st.updated)));
    } else if (st && st.alive && Number(st.age_s) < 120) {
      cls = 'green'; label = 'running';
      bits.push(el('span', { title: 'started ' + (st.started ? stamp(st.started) : '?') }, 'up ' + dur(st.uptime_s)));
    } else if (st) {
      cls = 'red'; label = 'NOT RUNNING';
      bits.push(el('span', { class: 'bad' }, 'last heartbeat ' + (st.updated ? ago(st.updated) : '?')));
    }
    if (st && !st.missing) {
      const eng = st.engine || {}, cap = st.capture || {};
      if (eng.learning) bits.push(tag('learning baselines', 'learn'));
      if (Number(cap.dropped) > 0) {
        const pct = cap.packets ? ' (' + (100 * cap.dropped / (cap.packets + cap.dropped)).toFixed(1) + '%)' : '';
        bits.push(tag(num(cap.dropped) + ' capture drops' + pct, 'warnt'));
      }
      if (Number(st.notify_failures) > 0) bits.push(tag(num(st.notify_failures) + ' notify failures', 'warnt'));
    }
    pill.className = 'pill ' + cls;
    pill.textContent = label;
    meta.replaceChildren(...join(bits, ' '));
    const open = st && st.extra && st.extra.open_incidents;
    const oc = $('opencount');
    oc.hidden = !open;
    oc.textContent = open ? String(open) : '';
  }

  // ---------- views ----------
  async function vOverview(route, stP) {
    const [st, al, inc, live] = await Promise.all([
      stP, api('/api/alerts?since=86400&limit=0'), api('/api/incidents?limit=200'), api('/api/live').catch(soft)]);
    const counts = (al && al.counts) || {};
    const incs = (inc && inc.incidents) || [];
    const open = incs.filter((i) => !i.ack).length;
    const tiles = el('div', { class: 'tiles' },
      SEVS.map((s) => el('a', { class: 'tile t-' + s, href: '#/alerts?since=86400&min=' + s },
        el('span', { class: 'big' }, num(counts[s] || 0)), el('span', { class: 'lbl' }, s + ' · 24 h'))),
      el('a', { class: 'tile t-open', href: '#/incidents?show=open' },
        el('span', { class: 'big' }, num(open)), el('span', { class: 'lbl' }, 'open incidents')));
    const last = st && st.last_alert;
    const lastLine = last ? el('p', { class: 'small lastalert' }, muted('last alert '), str(last.time), ' · ', str(last.title)) : null;

    const recent = incs.slice().sort((a, b) => (!!a.ack - !!b.ack) || (b.t - a.t)).slice(0, 8);
    const recentList = recent.length ? el('ul', { class: 'irows' }, recent.map((i) => el('li', null,
      sevBadge(i.severity),
      el('a', { href: incHref(i.id), class: 'ititle' }, str(i.title)),
      el('span', { class: 'imeta' }, when(i.t), i.ack ? ackTag(i.ack) : null)))) : el('p', { class: 'empty' }, 'No incidents.');

    const ents = ((live && live.entities) || []).slice().sort((a, b) => (b.out24h || 0) - (a.out24h || 0)).slice(0, 6);
    const top = ents.length ? (ents[0].out24h || 1) : 1;
    const uploaders = ents.length ? el('ul', { class: 'uplist' }, ents.map((e) => {
      const bar = el('span', { class: 'upbar' });
      bar.style.width = Math.max(1, Math.round(100 * (e.out24h || 0) / top)) + '%';
      return el('li', null, el('div', { class: 'uprow' }, mono(e.name), el('span', { class: 'num' }, bytes(e.out24h))),
        el('div', { class: 'uptrack' }, bar),
        el('div', { class: 'small muted' }, (e.server ? 'server · ' : '') + num(e.known_destinations) + ' known destinations' +
          (e.static ? ' · static ' + e.static : '')));
    })) : el('p', { class: 'empty' }, live ? 'No uploads recorded.' : 'No live snapshot yet.');

    const eng = (st && st.engine) || {}, cap = (st && st.capture) || {}, ex = (st && st.extra) || {};
    const stat = (k, v, bad) => el('div', { class: 'stat' + (bad ? ' badstat' : '') }, el('span', { class: 'sv' }, v), el('span', { class: 'sk' }, k));
    const stats = el('div', { class: 'stats' },
      stat('entities', num(eng.entities)), stat('flows', num(eng.flows)), stat('connections', num(eng.connections)),
      stat('events', num(st && st.events)), stat('DNS domains', num(eng.dns_domains)), stat('packets', num(cap.packets)),
      stat('capture drops', num(cap.dropped), cap.dropped > 0),
      stat('notify failures', num(st && st.notify_failures), st && st.notify_failures > 0),
      stat('history', eng.history_hours != null ? num(eng.history_hours) + ' h' : '—'),
      ex.suppressions != null ? stat('suppressions', num(ex.suppressions)) : null,
      stat('netns', num(st && st.netns)));
    const ver = st && st.version ? el('p', { class: 'small muted' }, 'ratel ' + str(st.version) + (st.pid ? ' · pid ' + st.pid : '') +
      (ex.root === false ? ' · not root' : '') + (ex.capture === false ? ' · packet capture off' : '')) : null;

    return el('div', { class: 'grid2' },
      el('div', { class: 'span2' }, tiles, lastLine),
      card('Alerts per hour · last 48 h', hourlyChart(al && al.hourly)),
      card('Recent incidents', recentList, el('a', { class: 'more', href: '#/incidents' }, 'all incidents →')),
      card('Top uploaders · 24 h', uploaders, el('a', { class: 'more', href: '#/live' }, 'live view →')),
      card('Engine', stats, ver));
  }

  const flowCols = [
    { h: 'Process', cls: 'lead', f: (r) => [mono(r.entity), r.pid ? muted(' pid ' + r.pid) : null] },
    { h: 'Destination', cls: 'wide', f: (r) => [el('span', { class: 'dir', title: r.inbound ? 'inbound' : 'outbound' }, r.inbound ? '← ' : '→ '),
      r.name ? [mono(r.name), ' ', el('code', { class: 'mono muted' }, str(r.dest))] : mono(r.dest)] },
    { h: 'Class', f: (r) => str(r.class) },
    { h: 'Port', cls: 'num', f: (r) => str(r.port) },
    { h: 'Out 10 min', cls: 'num', f: (r) => bytes(r.out10) },
    { h: 'In 10 min', cls: 'num', f: (r) => bytes(r.in10) },
    { h: 'Out 1 h', cls: 'num', f: (r) => bytes(r.out60) },
    { h: 'In 1 h', cls: 'num', f: (r) => bytes(r.in60) },
    { h: 'Conns 1 h', cls: 'num', f: (r) => num(r.conns60) },
    { h: 'Last seen', cls: 'num', f: (r) => when(r.last_seen) },
  ];
  const entCols = [
    { h: 'Process', cls: 'lead', f: (r) => [mono(r.name), r.flag ? [' ', tag('flag ' + r.flag, 'warnt')] : null] },
    { h: 'Uploaded 24 h', cls: 'num', f: (r) => bytes(r.out24h) },
    { h: 'Usual peak hour', cls: 'num', f: (r) => (r.usual_peak_hour == null ? muted('not learned') : bytes(r.usual_peak_hour)) },
    { h: 'Known dests', cls: 'num', f: (r) => num(r.known_destinations) },
    { h: 'Role', f: (r) => (r.server ? 'server' : 'client') },
    { h: 'First seen', cls: 'num', f: (r) => when(r.first_seen) },
    { h: 'Static scan', cls: 'wide', f: (r) => (r.static ? str(r.static) : muted('—')) },
  ];
  const dnsCols = [
    { h: 'Domain', cls: 'lead', f: (r) => mono(r.domain) },
    { h: 'Process', cls: 'wide', f: (r) => (r.entity && r.entity !== '?' ? mono(r.entity) : muted('unattributed')) },
    { h: 'Queries 10 min', cls: 'num', f: (r) => num(r.queries10) },
    { h: 'Unique names', cls: 'num', f: (r) => num(r.unique10) },
  ];
  async function vLive() {
    let lv;
    try { lv = await api('/api/live'); } catch (e) {
      if (e.status === 404) return card('Live', el('p', { class: 'empty' }, 'The monitor has not written a live snapshot yet.'));
      throw e;
    }
    return el('div', { class: 'stack' },
      el('p', { class: 'small muted' }, 'Snapshot ', when(lv.updated), ' · ', num(lv.history_hours), ' h of history',
        lv.learning ? [' ', tag('learning baselines', 'learn')] : null),
      card('Busiest flows · last 10 min', table(flowCols, lv.flows, 'No flows in the last 10 minutes.')),
      card('Processes · last 24 h, by upload', table(entCols, lv.entities, 'No processes seen.')),
      card('DNS · busiest domains, last 10 min', table(dnsCols, lv.dns, 'No DNS queries in the last 10 minutes.')));
  }

  async function vAlerts(route) {
    let since = Number(route.q.get('since')) || 86400;
    if (!WINDOWS.some((w) => w[0] === since)) since = 86400;
    let min = route.q.get('min');
    if (!SEV[min]) min = 'low';
    const d = await api('/api/alerts?since=' + since + '&min=' + encodeURIComponent(min));
    const alerts = (d && d.alerts) || [];
    const c = (d && d.counts) || {};
    const href = (s, m) => '#/alerts?since=' + s + '&min=' + m;
    const filters = el('div', { class: 'filters' },
      seg('Severity', [['low', 'all'], ['medium', 'medium +'], ['high', 'high']].map(([m, t]) => [href(since, m), t, m === min])),
      seg('Window', WINDOWS.map(([s, t]) => [href(s, min), t, s === since])));
    const summary = el('p', { class: 'small muted' }, num(alerts.length) + ' alert' + (alerts.length === 1 ? '' : 's') +
      ' · ' + SEVS.map((s) => num(c[s] || 0) + ' ' + s).join(' · ') + (alerts.length >= 1000 ? ' · showing the newest 1000' : ''));
    return el('div', { class: 'stack' }, filters, summary,
      alerts.length ? el('div', { class: 'alerts' }, alerts.map((a) => alertCard(a, true)))
        : el('p', { class: 'empty card' }, 'No alerts in this window.'));
  }

  async function vIncidents(route) {
    let show = route.q.get('show');
    if (show !== 'open' && show !== 'acked') show = 'all';
    const d = await api('/api/incidents?limit=500');
    const all = (d && d.incidents) || [];
    const rows = all.filter((i) => show === 'all' || (show === 'open' ? !i.ack : !!i.ack));
    const nOpen = all.filter((i) => !i.ack).length;
    const cols = [
      { h: 'Incident', cls: 'lead', f: (i) => [sevBadge(i.severity), ' ', el('a', { href: incHref(i.id) }, str(i.title))] },
      { h: 'Time', cls: 'num wide', f: (i) => [str(i.time), ' ', muted('(' + ago(i.t) + ')')] },
      { h: 'Kinds', cls: 'wide', f: (i) => join((i.kinds || []).map((k) => tag(str(k), 'kind')), ' ') },
      { h: 'Alerts', cls: 'num', f: (i) => num(i.alerts) },
      { h: 'Entities', cls: 'wide', f: (i) => join((i.entities || []).map(mono), ', ') },
      { h: 'State', cls: 'wide', f: (i) => [ackTag(i.ack), i.ack && i.ack.note ? [' ', muted(str(i.ack.note))] : null] },
    ];
    return el('div', { class: 'stack' },
      el('div', { class: 'filters' }, seg('Show', [['#/incidents', 'all (' + all.length + ')', show === 'all'],
        ['#/incidents?show=open', 'open (' + nOpen + ')', show === 'open'],
        ['#/incidents?show=acked', 'acknowledged (' + (all.length - nOpen) + ')', show === 'acked']])),
      card(null, table(cols, rows, 'No incidents.')));
  }

  // ----- incident detail -----
  const ui = { confirm: false, posting: false, note: null, expanded: {} };
  const ackResults = {};
  function busy() {
    const n = ui.note;
    return ui.posting || ui.confirm ||
      !!(n && n.isConnected && (document.activeElement === n || n.value.trim() !== ''));
  }
  function originNode(o) {
    if (!o || !o.kind) return muted('unknown');
    const pkg = o.pkg ? mono(o.pkg) : muted('?');
    switch (o.kind) {
      case 'package': return el('span', { class: 'good' }, 'unchanged package ', pkg);
      case 'modified': return el('strong', { class: 'bad' }, 'MODIFIED file of package ', pkg);
      case 'allowlisted': return el('span', { class: 'good' }, 'allowlisted');
      case 'unknown': return el('span', { class: 'warn' }, 'not from any package');
      default: return str(o.kind);
    }
  }
  function procTree(p) {
    const chain = (Array.isArray(p.parents) ? p.parents : []).slice().reverse();
    const line = (s, i, cls) => {
      s = str(s);
      const m = /^(\d+)\s+([\s\S]*)$/.exec(s);
      const row = el('div', { class: 'node' + (cls ? ' ' + cls : '') }, i ? el('span', { class: 'branch' }, '└ ') : null,
        m ? [el('span', { class: 'pid' }, m[1]), ' ', m[2]] : s);
      row.style.paddingLeft = (Math.min(i, 12) * 0.85) + 'em';
      return row;
    };
    return el('div', { class: 'tree mono' }, chain.map((s, i) => line(s, i)),
      line((p.pid != null ? p.pid + ' ' : '') + str(p.cmdline || p.exe), chain.length, 'self'));
  }
  function processCard(ctx, alerts) {
    const p = ctx.process;
    const ents = uniq(alerts.map((a) => a.entity).filter(Boolean));
    const entLine = ents.length ? el('p', { class: 'small entline' }, muted(ents.length > 1 ? 'alert entities: ' : 'alert entity: '), join(ents.map(mono), ', ')) : null;
    if (!p) return card('Process', el('p', { class: 'muted' }, 'No process context was captured for this incident.'), entLine);
    if (p.gone) return card('Process', el('p', { class: 'warn' }, 'Process had exited (pid ' + str(p.pid) + ') before ratel could look at it.'), entLine);
    return card('Process', entLine,
      kv([
        ['user', [str(p.user), ' ', muted('uid ' + str(p.uid))]],
        ['exe', mono(p.exe)],
        ['sha256', hashNode(p.sha256)],
        ['origin', originNode(p.origin)],
        ['command', el('code', { class: 'mono block' }, str(p.cmdline))],
        ['cwd', mono(p.cwd)],
        ['started', str(p.started)],
        ['container', p.container ? mono(p.container) : muted('none (host)')],
        ['pid', [str(p.pid), p.open_fds != null ? muted(' · ' + p.open_fds + ' open fds') : null]],
      ]),
      el('h3', null, 'Parent chain'),
      p.parents && p.parents.length ? procTree(p) : el('p', { class: 'empty' }, 'No parents recorded.'));
  }
  function destCard(ctx, alerts) {
    const d = ctx.destination;
    const dests = uniq(alerts.map((a) => a.dest).filter(Boolean));
    const many = dests.length > 1 ? el('p', { class: 'small muted' }, 'Alerts here involve ' + dests.length + ' targets: ',
      join(dests.map(mono), ', ')) : null;
    if (!d) {
      if (!dests.length) return null;
      return card('Target', kv([['alert target', join(dests.map(mono), ', ')]]),
        el('p', { class: 'small muted' }, 'No destination context was captured.'));
    }
    return card('Destination', kv([
      ['address', [mono(d.ip), d.class ? [' ', tag(str(d.class))] : null]],
      ['DNS name', d.dns_name ? mono(d.dns_name) : el('span', { class: 'warn' }, 'no DNS lookup returned it')],
      ['first seen by this process', tval(d.first_seen_by_entity)],
      ['first seen by this host', tval(d.first_seen_here)],
    ]), many);
  }
  function profileCard(ctx) {
    const p = ctx.profile;
    if (!p) return null;
    return card('Learned profile', kv([
      ['first seen', tval(p.first_seen)],
      ['role', p.server ? 'server (accepts connections)' : 'client'],
      ['known destinations', num(p.known_destinations)],
      ['usual peak-hour upload', p.usual_peak_hour_upload == null ? muted('none learned yet') : bytes(p.usual_peak_hour_upload)],
      ['largest hour to one host', bytes(p.largest_hour_to_one_host)],
      ['static scan', p.static ? str(p.static) : muted('—')],
    ]));
  }
  function activityCard(inc) {
    const act = inc.activity || {};
    const eps = (act.endpoints || []).slice().sort((a, b) => ((b.sent || 0) + (b.received || 0)) - ((a.sent || 0) + (a.received || 0)));
    const dns = (act.dns || []).slice().sort((a, b) => (b.count || 0) - (a.count || 0));
    const flags = act.flags || [];
    const key = inc.id;
    const dnsShown = ui.expanded[key] ? dns : dns.slice(0, 20);
    let dnsMore = null;
    if (dns.length > dnsShown.length) {
      dnsMore = el('button', { type: 'button', class: 'btn tiny' }, 'show all ' + dns.length);
      dnsMore.addEventListener('click', () => { ui.expanded[key] = true; refresh(); });
    }
    return card('Activity',
      el('p', { class: 'small muted' }, num(act.events_before) + ' events recorded before the alert, ' + num(act.events_after) + ' after.'),
      el('h3', null, 'Endpoints by bytes'),
      table([
        { h: 'Endpoint', cls: 'lead', f: (r) => mono(r.endpoint) },
        { h: 'Sent', cls: 'num', f: (r) => bytes(r.sent) },
        { h: 'Received', cls: 'num', f: (r) => bytes(r.received) },
        { h: 'Conns', cls: 'num', f: (r) => num(r.conns) },
        { h: 'First', cls: 'num', f: (r) => clock(r.first) },
        { h: 'Last', cls: 'num', f: (r) => clock(r.last) },
      ], eps, 'No network endpoints recorded.'),
      el('h3', null, 'DNS lookups'),
      dns.length ? el('ul', { class: 'dnslist' }, dnsShown.map((r) => el('li', null, mono(r.name), muted(' ×' + num(r.count))))) : el('p', { class: 'empty' }, 'No DNS lookups recorded.'),
      dnsMore,
      el('h3', null, 'Flags'),
      table([
        { h: 'Rule', cls: 'lead', f: (r) => mono(r.rule) },
        { h: 'Time', cls: 'num', f: (r) => clock(r.t) },
        { h: 'Detail', cls: 'wide', f: (r) => str(r.detail) },
      ], flags, 'No process flags.'));
  }
  function suppressTable(rows) {
    return table([
      { h: 'Process', cls: 'lead', f: (r) => mono(r[0]) },
      { h: 'Destination', cls: 'wide', f: (r) => (r[1] === '*' ? el('strong', null, 'any destination') : mono(r[1])) },
      { h: 'Kind', f: (r) => tag(str(r[2]), 'kind') },
    ], rows, 'Nothing.');
  }
  function decideCard(inc, alerts) {
    const id = inc.id;
    const note = el('textarea', { id: 'acknote', rows: 2, maxLength: 500, placeholder: 'optional note, e.g. "nightly backup to the NAS"' });
    ui.note = note;
    const anyDest = el('input', { type: 'checkbox', id: 'ackany' });
    const btnRev = el('button', { type: 'button', class: 'btn' }, 'Reviewed');
    const btnFp = el('button', { type: 'button', class: 'btn warnbtn' }, 'False alarm…');
    const confirmBox = el('div', { class: 'confirm', hidden: true });
    const msg = el('div', { class: 'ackmsg' });
    const prior = ackResults[id];
    if (prior) {
      msg.append(prior.fp
        ? el('p', { class: 'good' }, 'Saved as false alarm. The monitor stops alerting on these within a minute:')
        : el('p', { class: 'good' }, 'Saved as reviewed.'));
      if (prior.fp || prior.suppress.length) msg.append(suppressTable(prior.suppress));
    }
    const setDisabled = (v) => { for (const b of [btnRev, btnFp, anyDest, note]) b.disabled = v; };
    async function submit(fp) {
      ui.posting = true;
      setDisabled(true);
      msg.replaceChildren(muted('Saving…'));
      try {
        const res = await post('/api/ack', { id, fp, any_dest: anyDest.checked, note: note.value.trim() });
        ackResults[id] = { fp, suppress: Array.isArray(res && res.suppress) ? res.suppress : [] };
        note.value = '';
        ui.confirm = false;
        ui.posting = false;
        refresh();
      } catch (e) {
        ui.posting = false;
        setDisabled(false);
        if (!(e instanceof AuthError)) msg.replaceChildren(el('p', { class: 'bad' }, 'Could not save: ' + e.message));
      }
    }
    function preview() {
      const rows = [], seen = new Set();
      for (const a of alerts) {
        const ent = String(a.entity || ''), kind = String(a.kind || ''), dest = String(a.dest || '').split(' ')[0];
        const catchAll = /^(unattributed|unattributed-udp|\?|ratel)$|^(uid|host):/.test(ent) || ent === '';
        if (!kind || kind === 'health') continue;
        let d;
        if (catchAll || kind === 'process' || kind === 'file') {
          if (!dest || (catchAll && kind !== 'dns' && !/^[0-9a-f.:]+$/i.test(dest))) continue; // can't be silenced
          d = dest;
        } else d = anyDest.checked || !dest ? '*' : dest;
        const r = [str(ent), str(d), str(kind)];
        const k = r.join('\u0000');
        if (!seen.has(k)) { seen.add(k); rows.push(r); }
      }
      return rows;
    }
    function showConfirm() {
      ui.confirm = true;
      const yes = el('button', { type: 'button', class: 'btn dangerbtn' }, 'Yes, it is a false alarm');
      const no = el('button', { type: 'button', class: 'btn' }, 'Cancel');
      yes.addEventListener('click', () => submit(true));
      no.addEventListener('click', () => { ui.confirm = false; confirmBox.hidden = true; });
      confirmBox.replaceChildren(
        el('p', null, el('strong', null, 'This silences future alerts. '),
          'The running monitor will stop alerting on each (process, destination, kind) below from now on. ' +
          'Anything real that matches them later will not be reported either.'),
        suppressTable(preview()),
        el('p', { class: 'small muted' }, 'Expected list; the server returns the exact one after saving.'),
        el('div', { class: 'btnrow' }, yes, no));
      confirmBox.hidden = false;
    }
    btnRev.addEventListener('click', () => submit(false));
    btnFp.addEventListener('click', showConfirm);
    anyDest.addEventListener('change', () => { if (ui.confirm) showConfirm(); });
    let state = null;
    if (inc.ack) {
      state = el('p', { class: 'ackstate' }, ackTag(inc.ack), ' ', inc.ack.t ? ago(inc.ack.t) : '',
        inc.ack.note ? [' · ', el('q', null, str(inc.ack.note))] : null);
    }
    return card('Decision', state,
      el('p', { class: 'small muted' }, inc.ack ? 'You can change the decision.' : 'Is this real? Mark it once you have looked.'),
      el('label', { class: 'lbl', htmlFor: 'acknote' }, 'Note'), note,
      el('label', { class: 'check', htmlFor: 'ackany' }, anyDest,
        ' for any destination ', muted('(false alarm: silence this process + kind everywhere, not only for this destination)')),
      el('div', { class: 'btnrow' }, btnRev, btnFp),
      confirmBox, msg);
  }
  async function vIncident(route) {
    let id = route.arg;
    try { id = decodeURIComponent(id); } catch (e) { /* keep raw */ }
    let inc;
    try { inc = await api('/api/incident/' + encodeURIComponent(id)); } catch (e) {
      if (e.status === 404) {
        return card('Not found', el('p', null, 'No incident with id ', mono(id), '. It may have been pruned.'),
          el('a', { class: 'more', href: '#/incidents' }, '← incidents'));
      }
      throw e;
    }
    const alerts = Array.isArray(inc.alerts) ? inc.alerts : [];
    const ctx = inc.context || {};
    const sev = alerts.reduce((m, a) => (SEV[sevOf(a.severity)] > SEV[m] ? sevOf(a.severity) : m), 'low');
    const ts = alerts.map((a) => a.t).filter((t) => isFinite(t));
    const first = ts.length ? Math.min(...ts) : null;
    const kinds = uniq(alerts.map((a) => a.kind).filter(Boolean));
    const head = el('div', { class: 'ihead' },
      el('a', { class: 'back', href: '#/incidents' }, '← incidents'),
      el('h1', null, sevBadge(sev), ' ', str(inc.title)),
      el('p', { class: 'small muted' }, str(inc.time), first ? ' (' + ago(first) + ')' : '', ' · ', mono(inc.id), ' · ',
        alerts.length + ' alert' + (alerts.length === 1 ? '' : 's'), ' · ', join(kinds.map((k) => tag(str(k), 'kind')), ' ')),
      inc.ack ? el('div', { class: 'ackbar ' + (inc.ack.fp ? 'fp' : 'rev') },
        inc.ack.fp ? 'Marked false alarm ' : 'Reviewed ', inc.ack.t ? ago(inc.ack.t) : '',
        inc.ack.note ? [' · note: ', el('q', null, str(inc.ack.note))] : null) : null);
    const withOrder = (node, o) => { if (node) node.classList.add('o' + o); return node; };
    return el('div', null, head,
      el('div', { class: 'cols' },
        el('div', { class: 'col' },
          withOrder(card('Alerts', el('div', { class: 'alerts' }, alerts.map((a) => alertCard(a, false)))), 1),
          withOrder(activityCard(inc), 5)),
        el('div', { class: 'col' },
          withOrder(processCard(ctx, alerts), 2),
          withOrder(destCard(ctx, alerts), 3),
          withOrder(profileCard(ctx), 4),
          withOrder(decideCard(inc, alerts), 6))));
  }

  // ---------- routing + refresh loop ----------
  const VIEWS = { overview: vOverview, live: vLive, alerts: vAlerts, incidents: vIncidents, incident: vIncident };
  function parseHash() {
    let h = location.hash.replace(/^#\/?/, '');
    let q = '';
    const i = h.indexOf('?');
    if (i >= 0) { q = h.slice(i + 1); h = h.slice(0, i); }
    const parts = h.split('/');
    return { name: parts[0] || 'overview', arg: parts.slice(1).join('/'), q: new URLSearchParams(q), key: location.hash };
  }
  let seq = 0, lastOk = 0, lastTry = 0, shownKey = null;
  function banner(text) {
    const b = $('banner');
    b.hidden = !text;
    b.textContent = text || '';
  }
  async function refresh() {
    const my = ++seq;
    lastTry = Date.now();
    const route = parseHash();
    for (const a of document.querySelectorAll('#nav a')) {
      const on = a.dataset.route === route.name || (route.name === 'incident' && a.dataset.route === 'incidents');
      a.classList.toggle('on', on);
    }
    const view = VIEWS[route.name];
    const stP = api('/api/status').catch(soft);
    try {
      const node = view ? await view(route, stP) : card('Not found', el('p', null, 'Unknown page.'), el('a', { class: 'more', href: '#/' }, '← overview'));
      const st = await stP;
      if (my !== seq) return;
      renderHealth(st);
      const sameView = shownKey === route.key;
      $('main').replaceChildren(node);
      if (!sameView) window.scrollTo(0, 0);
      shownKey = route.key;
      lastOk = Date.now();
      banner(null);
    } catch (e) {
      if (my !== seq || e instanceof AuthError) return;
      stP.then((st) => { if (my === seq) renderHealth(st); }, () => {});
      const text = 'Could not load: ' + (e && e.message ? e.message : 'network error');
      if (shownKey !== route.key) {
        $('main').replaceChildren(card('Error', el('p', { class: 'bad' }, text)));
        shownKey = route.key;
      } else banner(text + ' (showing older data)');
    }
    tick();
  }
  function tick() {
    const u = $('updated');
    if (!lastOk) { u.textContent = ''; return; }
    const s = Math.round((Date.now() - lastOk) / 1000);
    u.textContent = 'updated ' + (s < 2 ? 'just now' : s < 120 ? s + ' s ago' : short(s) + ' ago') + (busy() ? ' · paused' : '');
    u.classList.toggle('stale', s > 90);
  }
  function loop() {
    tick();
    if (!document.hidden && !busy() && Date.now() - lastTry >= REFRESH_MS) refresh();
  }

  function start() {
    $('logout').addEventListener('click', async () => {
      try { await post('/logout', {}); } catch (e) { if (e instanceof AuthError) return; }
      location.assign('/login');
    });
    $('updated').addEventListener('click', () => { if (!busy()) refresh(); });
    window.addEventListener('hashchange', () => {
      ui.confirm = false; ui.posting = false; ui.note = null;
      refresh();
    });
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden && !busy() && Date.now() - lastTry >= REFRESH_MS) refresh();
    });
    try {
      const next = sessionStorage.getItem('ratel.next');
      sessionStorage.removeItem('ratel.next');
      if (next && !location.hash && /^#\/[\w\-/%?=&.]*$/.test(next)) history.replaceState(null, '', next);
    } catch (e) { /* storage off */ }
    session().catch(() => {});
    refresh();
    setInterval(loop, 1000);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
