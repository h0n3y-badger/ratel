//! `ratel web`: a small, hardened, read-mostly dashboard over what `ratel watch`
//! writes (status, live snapshot, alert log, incidents). See src/web/API.md.
//!
//! Security model:
//! * runs as an unprivileged user, sandboxed with Landlock (read-only access to
//!   ratel's state/log/status directories, write access only to the feedback
//!   inbox `<state>/feedback.d/`), no new privileges, no core dumps;
//! * listens on 127.0.0.1 by default; TLS is terminated in front of it (stunnel
//!   with the Tailscale certificate) and `--secure-cookie` marks cookies Secure;
//!   binding a non-loopback address needs `--allow-remote`;
//! * a 256-bit access token, stored only as its SHA-256; per-IP login rate limit;
//! * sessions: 256-bit random ids, HttpOnly + SameSite=Strict cookies, idle and
//!   absolute expiry, per-session CSRF token plus Origin check on every POST;
//! * Host header allowlist (DNS rebinding), strict CSP and security headers,
//!   small request limits and timeouts, connection cap, no chunked bodies;
//! * every login and acknowledgement is logged; the root daemon announces every
//!   suppression it loads, so a compromised dashboard can't silently mute it.

pub mod sandbox;

use crate::watch::incidents::{feedback_files, local_time};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const INDEX: &str = include_str!("index.html");
const APP_JS: &str = include_str!("app.js");
const APP_CSS: &str = include_str!("app.css");
const LOGIN: &str = include_str!("login.html");

const MAX_HEADER: usize = 8 * 1024;
const MAX_BODY: usize = 8 * 1024;
const MAX_CONN: usize = 32;
const SESSION_IDLE: f64 = 12.0 * 3600.0;
const SESSION_MAX: f64 = 7.0 * 86_400.0;
const MAX_SESSIONS: usize = 64;
const READ_DEADLINE: Duration = Duration::from_secs(10);
const WRITE_DEADLINE: Duration = Duration::from_secs(20);
const LOG_TAIL: u64 = 16 << 20;
const INCIDENT_MAX: u64 = 32 << 20;

pub const USAGE: &str = "ratel web — dashboard for ratel watch (see src/web/API.md)

usage: ratel web [opts]
       ratel web --init-token [--token-file FILE]   create an access token (prints it once; stores only its hash)
  --listen ADDR        IP:PORT (default 127.0.0.1:8447) or unix:/path (recommended behind stunnel: no local
                       user can squat a UNIX socket in a private directory the way they can squat a port)
  --proxy-protocol     expect a PROXY v1 header (stunnel `protocol = proxy`) for the real client address
  --host NAME[:PORT]   accepted Host header (repeatable), e.g. homelab.tailnet.ts.net:8448
  --secure-cookie      cookies only over HTTPS (set when TLS terminates in front, e.g. stunnel)
  --allow-remote       allow a non-loopback --listen address (plain HTTP; only inside a VPN)
  --token-file FILE    default /etc/ratel/web-token
  --user NAME          user to drop to when started as root (default ratel-web)
  --state DIR          default /var/lib/ratel
  --log FILE           default /var/log/ratel/alerts.jsonl
  --status FILE        default /run/ratel/status.json
  --allow-unsandboxed  start even if the kernel has no Landlock (not recommended)
";

enum Listen {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

struct Cfg {
    listen: Listen,
    proxy_protocol: bool,
    hosts: HashSet<String>,
    secure_cookie: bool,
    allow_remote: bool,
    allow_unsandboxed: bool,
    token_file: PathBuf,
    user: String,
    state: PathBuf,
    log: PathBuf,
    status: PathBuf,
}

struct Session {
    csrf: String,
    created: f64,
    seen: f64,
}

struct Shared {
    cfg: Cfg,
    token_hash: [u8; 32],
    sessions: Mutex<HashMap<String, Session>>,
    /// Logins are checked one at a time with a delay on failure: brute force of a
    /// 256-bit token is hopeless anyway, and there is no lockout an attacker could
    /// trigger against the admin (behind stunnel all peers look alike).
    login_gate: Mutex<()>,
    active: AtomicUsize,
}

fn now() -> f64 {
    crate::watch::now()
}

fn die(m: &str) -> ! {
    eprintln!("ratel web: {m}");
    std::process::exit(2);
}

/// Attacker-supplied text in logs: printable only, bounded.
fn clean(s: &str, max: usize) -> String {
    let mut out: String = s.chars().take(max).map(|c| {
        let u = c as u32;
        if c.is_control() || (0x200B..=0x200F).contains(&u) || (0x202A..=0x202E).contains(&u) || (0x2066..=0x2069).contains(&u) || u == 0xFEFF {
            '?'
        } else {
            c
        }
    }).collect();
    if s.chars().count() > max {
        out.push('…');
    }
    out
}

static AUDIT: Mutex<(f64, u32, u64)> = Mutex::new((0.0, 0, 0));
const AUDIT_PER_MIN: u32 = 30;

/// Audit line to the service log (stderr). Rate-limited so nobody can fill the disk.
fn audit(m: &str) {
    let t = now();
    let mut a = AUDIT.lock().unwrap();
    if t - a.0 >= 60.0 {
        if a.2 > 0 {
            eprintln!("{} ratel web: {} audit lines suppressed (rate limit)", local_time(t), a.2);
        }
        *a = (t, 0, 0);
    }
    if a.1 >= AUDIT_PER_MIN {
        a.2 += 1;
        return;
    }
    a.1 += 1;
    eprintln!("{} ratel web: {}", local_time(t), clean(m, 300));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn parse_args(args: &[String]) -> (Cfg, bool) {
    let mut c = Cfg {
        listen: Listen::Tcp("127.0.0.1:8447".parse().unwrap()), proxy_protocol: false, hosts: HashSet::new(), secure_cookie: false, allow_remote: false,
        allow_unsandboxed: false, token_file: "/etc/ratel/web-token".into(), user: "ratel-web".into(),
        state: "/var/lib/ratel".into(), log: "/var/log/ratel/alerts.jsonl".into(), status: "/run/ratel/status.json".into(),
    };
    let mut init = false;
    let mut i = 0;
    let val = |i: &mut usize| -> String {
        *i += 1;
        args.get(*i).cloned().unwrap_or_else(|| die(&format!("{} needs a value", args[*i - 1])))
    };
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                let v = val(&mut i);
                c.listen = match v.strip_prefix("unix:") {
                    Some(p) => Listen::Unix(p.into()),
                    None => Listen::Tcp(v.parse().unwrap_or_else(|_| die("bad --listen (IP:PORT or unix:/path)"))),
                };
            }
            "--proxy-protocol" => c.proxy_protocol = true,
            "--host" => {
                c.hosts.insert(val(&mut i).to_ascii_lowercase());
            }
            "--secure-cookie" => c.secure_cookie = true,
            "--allow-remote" => c.allow_remote = true,
            "--allow-unsandboxed" => c.allow_unsandboxed = true,
            "--token-file" => c.token_file = val(&mut i).into(),
            "--user" => c.user = val(&mut i),
            "--state" => c.state = val(&mut i).into(),
            "--log" => c.log = val(&mut i).into(),
            "--status" => c.status = val(&mut i).into(),
            "--init-token" => init = true,
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            s => die(&format!("unknown option {s}\n\n{USAGE}")),
        }
        i += 1;
    }
    if let Listen::Tcp(a) = &c.listen {
        let port = a.port();
        c.hosts.insert(format!("{}:{port}", a.ip()));
        c.hosts.insert(format!("localhost:{port}"));
        c.hosts.insert(format!("127.0.0.1:{port}"));
    }
    (c, init)
}

fn init_token(path: &Path) {
    let tok = hex(&sandbox::random_bytes::<32>());
    let line = format!("sha256:{}\n", hex(&Sha256::digest(tok.as_bytes())));
    if let Some(d) = path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o640).open(path)
        .unwrap_or_else(|e| die(&format!("{}: {e}", path.display())));
    f.write_all(line.as_bytes()).unwrap_or_else(|e| die(&e.to_string()));
    // group-readable by the web user's group if it exists (root:ratel 0640)
    // SAFETY: getgrnam/chown with valid C strings.
    unsafe {
        let g = libc::getgrnam(c"ratel".as_ptr());
        if !g.is_null() {
            let p = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
            libc::chown(p.as_ptr(), u32::MAX, (*g).gr_gid);
        }
    }
    println!("access token (shown once, keep it in your password manager):\n{tok}\nstored as a SHA-256 hash in {}", path.display());
}

fn load_token_hash(path: &Path) -> [u8; 32] {
    let s = std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("{}: {e} (create one with: ratel web --init-token)", path.display())));
    let h = s.trim().strip_prefix("sha256:").unwrap_or_else(|| die("token file must contain sha256:<hex> (use --init-token)"));
    let mut out = [0u8; 32];
    if h.len() != 64 || !h.is_ascii() {
        die("token file: bad hash");
    }
    for i in 0..32 {
        out[i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap_or_else(|_| die("token file: bad hash"));
    }
    out
}

pub fn run(args: &[String]) {
    let (cfg, init) = parse_args(args);
    if init {
        init_token(&cfg.token_file);
        return;
    }
    if let Listen::Tcp(a) = &cfg.listen {
        if !a.ip().is_loopback() && !cfg.allow_remote {
            die("refusing to listen on a non-loopback address without --allow-remote (terminate TLS in front instead; see README)");
        }
    }
    if matches!(cfg.listen, Listen::Unix(_)) && cfg.hosts.is_empty() {
        die("with a UNIX socket, give the browser-facing name with --host NAME:PORT");
    }
    let token_hash = load_token_hash(&cfg.token_file);
    let listener = match &cfg.listen {
        Listen::Tcp(a) => Listener::Tcp(TcpListener::bind(a).unwrap_or_else(|e| die(&format!("bind {a}: {e}")))),
        Listen::Unix(p) => {
            if std::fs::symlink_metadata(p).is_ok_and(|m| std::os::unix::fs::FileTypeExt::is_socket(&m.file_type())) {
                let _ = std::fs::remove_file(p); // stale socket from a previous run
            }
            // owner + group (stunnel) only
            let old = unsafe { libc::umask(0o117) };
            let l = std::os::unix::net::UnixListener::bind(p).unwrap_or_else(|e| die(&format!("bind {}: {e}", p.display())));
            unsafe { libc::umask(old) };
            Listener::Unix(l)
        }
    };
    // Warm up anything that reads files lazily (time zone) before the sandbox closes them off.
    let _ = local_time(now());
    sandbox::drop_privileges(&cfg.user).unwrap_or_else(|e| die(&e));
    if unsafe { libc::geteuid() } == 0 {
        die("still root after privilege drop");
    }
    sandbox::harden_process().unwrap_or_else(|e| die(&e));
    let status_dir = cfg.status.parent().map(Path::to_path_buf).unwrap_or_else(|| "/run/ratel".into());
    let log_dir = cfg.log.parent().map(Path::to_path_buf).unwrap_or_else(|| "/var/log/ratel".into());
    let inbox = cfg.state.join("feedback.d");
    let rules = sandbox::Rules { read_dirs: vec![&cfg.state, &log_dir, &status_dir], write_dirs: vec![&inbox] };
    match sandbox::landlock(&rules) {
        Ok(desc) => {
            // prove it: no reads or writes outside ratel's directories, no outbound network
            if std::fs::read("/etc/passwd").is_ok() {
                die("sandbox self-test failed: /etc/passwd is still readable");
            }
            let probe = format!("/tmp/.ratel-web-selftest-{}", std::process::id());
            if std::fs::File::create(&probe).is_ok() {
                let _ = std::fs::remove_file(&probe);
                die("sandbox self-test failed: could create a file outside the feedback inbox");
            }
            let mut checks = vec!["/etc/passwd unreadable", "no writes outside the inbox"];
            if desc.contains("no outbound TCP") {
                match std::net::TcpStream::connect_timeout(&"127.0.0.1:9".parse().unwrap(), Duration::from_millis(300)) {
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => checks.push("outbound TCP denied"),
                    _ => die("sandbox self-test failed: outbound TCP not denied"),
                }
            }
            if desc.contains("no UDP") {
                let denied = std::net::UdpSocket::bind("127.0.0.1:0").and_then(|u| u.send_to(b"x", "127.0.0.1:9")).is_err();
                if !denied {
                    die("sandbox self-test failed: UDP send not denied");
                }
                checks.push("UDP denied");
            }
            eprintln!("ratel web: sandboxed ({desc}); self-test passed: {}", checks.join(", "));
        }
        Err(e) if cfg.allow_unsandboxed => eprintln!("ratel web: WARNING running without Landlock: {e}"),
        Err(e) => die(&format!("{e}\n(refusing to run unsandboxed; --allow-unsandboxed overrides)")),
    }
    let where_ = match &cfg.listen { Listen::Tcp(a) => format!("http://{a}"), Listen::Unix(p) => format!("unix:{}", p.display()) };
    eprintln!("ratel web: listening on {where_} (hosts: {}){}{}", cfg.hosts.iter().cloned().collect::<Vec<_>>().join(", "),
        if cfg.secure_cookie { ", secure cookies" } else { "" }, if cfg.proxy_protocol { ", PROXY protocol" } else { "" });
    let shared = Arc::new(Shared { cfg, token_hash, sessions: Mutex::new(HashMap::new()), login_gate: Mutex::new(()),
        active: AtomicUsize::new(0) });
    loop {
        let stream = match &listener {
            Listener::Tcp(l) => l.accept().map(|(s, _)| Conn::Tcp(s)),
            Listener::Unix(l) => l.accept().map(|(s, _)| Conn::Unix(s)),
        };
        let Ok(stream) = stream else { continue };
        if shared.active.load(Ordering::Relaxed) >= MAX_CONN {
            continue; // dropped: too many concurrent connections
        }
        shared.active.fetch_add(1, Ordering::Relaxed);
        let sh = shared.clone();
        std::thread::spawn(move || {
            handle(&sh, stream);
            sh.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

// ------------------------------------------------------------------ HTTP

enum Listener {
    Tcp(TcpListener),
    Unix(std::os::unix::net::UnixListener),
}

enum Conn {
    Tcp(TcpStream),
    Unix(std::os::unix::net::UnixStream),
}

impl Conn {
    fn set_read_timeout(&self, d: Duration) -> std::io::Result<()> {
        match self {
            Conn::Tcp(s) => s.set_read_timeout(Some(d)),
            Conn::Unix(s) => s.set_read_timeout(Some(d)),
        }
    }
    fn set_write_timeout(&self, d: Duration) -> std::io::Result<()> {
        match self {
            Conn::Tcp(s) => s.set_write_timeout(Some(d)),
            Conn::Unix(s) => s.set_write_timeout(Some(d)),
        }
    }
    /// The socket peer: an IP for TCP, None for a UNIX socket.
    fn peer(&self) -> Option<IpAddr> {
        match self {
            Conn::Tcp(s) => s.peer_addr().ok().map(|a| a.ip()),
            Conn::Unix(_) => None,
        }
    }
}

impl Read for Conn {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Tcp(s) => s.read(b),
            Conn::Unix(s) => s.read(b),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        match self {
            Conn::Tcp(s) => s.write(b),
            Conn::Unix(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Conn::Tcp(s) => s.flush(),
            Conn::Unix(s) => s.flush(),
        }
    }
}

/// One read bounded by the request's absolute deadline (no slowloris: trickling
/// bytes can't keep a connection past READ_DEADLINE in total).
fn read_by(s: &mut Conn, buf: &mut [u8], deadline: std::time::Instant) -> Result<usize, u16> {
    let left = deadline.saturating_duration_since(std::time::Instant::now());
    if left.is_zero() {
        return Err(408);
    }
    s.set_read_timeout(left.max(Duration::from_millis(1))).map_err(|_| 500u16)?;
    s.read(buf).map_err(|_| 408u16)
}

struct Req {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    peer: IpAddr,
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                match u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16) {
                    Ok(v) => {
                        out.push(v);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_form(s: &str) -> HashMap<String, String> {
    s.split('&').filter_map(|kv| kv.split_once('=')).map(|(k, v)| (url_decode(k), url_decode(v))).collect()
}

fn read_request(s: &mut Conn, proxy: bool) -> Result<Req, u16> {
    let deadline = std::time::Instant::now() + READ_DEADLINE;
    let mut peer = s.peer().unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let head_end;
    loop {
        let n = read_by(s, &mut chunk, deadline)?;
        if n == 0 {
            return Err(400);
        }
        buf.extend_from_slice(&chunk[..n]);
        if proxy && buf.len() >= 8 && buf.starts_with(b"PROXY ") {
            // PROXY protocol v1 line from stunnel: honoured only from a UNIX socket or loopback
            if let Some(e) = buf.windows(2).position(|w| w == b"\r\n") {
                if e > 107 || !(s.peer().is_none() || s.peer().is_some_and(|p| p.is_loopback())) {
                    return Err(400);
                }
                let line = std::str::from_utf8(&buf[6..e]).map_err(|_| 400u16)?.to_string();
                let f: Vec<&str> = line.split(' ').collect();
                if f.first().is_some_and(|p| *p == "TCP4" || *p == "TCP6") {
                    peer = f.get(1).and_then(|a| a.parse().ok()).ok_or(400u16)?;
                }
                buf.drain(..e + 2);
            } else if buf.len() > 107 {
                return Err(400);
            } else {
                continue;
            }
        } else if proxy && buf.len() >= 6 && !buf.starts_with(b"PROXY ") && !buf.starts_with(b"GET ") && !buf.starts_with(b"POST ") {
            return Err(400);
        }
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            if p > MAX_HEADER {
                return Err(431);
            }
            head_end = p;
            break;
        }
        if buf.len() > MAX_HEADER {
            return Err(431);
        }
    }
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| 400u16)?;
    // a bare CR or LF anywhere means a smuggling / log-injection attempt
    if head.split("\r\n").any(|l| l.contains('\r') || l.contains('\n')) {
        return Err(400);
    }
    let mut lines = head.split("\r\n");
    let mut rl = lines.next().ok_or(400u16)?.split(' ');
    let (method, target, ver) = (rl.next().ok_or(400u16)?, rl.next().ok_or(400u16)?, rl.next().ok_or(400u16)?);
    if ver != "HTTP/1.1" && ver != "HTTP/1.0" {
        return Err(505);
    }
    let mut headers = HashMap::new();
    for l in lines {
        let (k, v) = l.split_once(':').ok_or(400u16)?;
        if headers.len() > 64 {
            return Err(431);
        }
        let k = k.trim().to_ascii_lowercase();
        // security-relevant headers must not be duplicated
        if matches!(k.as_str(), "host" | "origin" | "cookie" | "content-length" | "x-ratel-csrf") && headers.contains_key(&k) {
            return Err(400);
        }
        headers.insert(k, v.trim().to_string());
    }
    if headers.contains_key("transfer-encoding") {
        return Err(501);
    }
    let len: usize = headers.get("content-length").map(|v| v.parse().map_err(|_| 400u16)).transpose()?.unwrap_or(0);
    if len > MAX_BODY {
        return Err(413);
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        let n = read_by(s, &mut chunk, deadline)?;
        if n == 0 {
            return Err(400);
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(len);
    let (path, q) = target.split_once('?').unwrap_or((target, ""));
    if !path.starts_with('/') || path.len() > 256 {
        return Err(400);
    }
    Ok(Req { method: method.to_string(), path: path.to_string(), query: parse_form(q), headers, body, peer })
}

struct Resp {
    status: u16,
    ctype: &'static str,
    body: Vec<u8>,
    extra: Vec<(&'static str, String)>,
}

fn resp(status: u16, ctype: &'static str, body: impl Into<Vec<u8>>) -> Resp {
    Resp { status, ctype, body: body.into(), extra: vec![] }
}

fn json_resp(status: u16, v: Value) -> Resp {
    resp(status, "application/json", v.to_string())
}

fn redirect(to: &str) -> Resp {
    let mut r = resp(303, "text/plain", "");
    r.extra.push(("Location", to.to_string()));
    r
}

fn reason(s: u16) -> &'static str {
    match s {
        200 => "OK", 303 => "See Other", 400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden", 404 => "Not Found",
        405 => "Method Not Allowed", 408 => "Request Timeout", 413 => "Payload Too Large", 421 => "Misdirected Request",
        422 => "Unprocessable Entity", 429 => "Too Many Requests", 431 => "Request Header Fields Too Large", 500 => "Internal Server Error",
        501 => "Not Implemented", 505 => "HTTP Version Not Supported", _ => "Error",
    }
}

fn write_resp(s: &mut Conn, r: Resp, secure: bool) {
    let mut h = format!("HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n", r.status,
        reason(r.status), r.ctype, r.body.len());
    h += "Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'\r\n";
    h += "X-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\n";
    h += "Cross-Origin-Opener-Policy: same-origin\r\nCross-Origin-Resource-Policy: same-origin\r\n";
    h += "Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=(), payment=()\r\nCache-Control: no-store\r\n";
    if secure {
        h += "Strict-Transport-Security: max-age=31536000\r\n";
    }
    for (k, v) in &r.extra {
        h += &format!("{k}: {v}\r\n");
    }
    h += "\r\n";
    // total write deadline: a client that reads slowly can't pin a thread
    let deadline = std::time::Instant::now() + WRITE_DEADLINE;
    for part in [h.as_bytes(), &r.body[..]] {
        for c in part.chunks(16 * 1024) {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() || s.set_write_timeout(left.max(Duration::from_millis(1))).is_err() || s.write_all(c).is_err() {
                return;
            }
        }
    }
}

fn cookie_name(sh: &Shared) -> &'static str {
    // __Host- prefix: browser-enforced Secure, Path=/, no Domain
    if sh.cfg.secure_cookie { "__Host-ratel_session" } else { "ratel_session" }
}

fn session_of(sh: &Shared, r: &Req) -> Option<(String, String)> {
    let name = cookie_name(sh);
    let c = r.headers.get("cookie")?;
    let id = c.split(';').filter_map(|kv| kv.trim().split_once('=')).find(|(k, _)| *k == name)?.1.to_string();
    let mut ss = sh.sessions.lock().unwrap();
    let t = now();
    let ok = ss.get(&id).is_some_and(|s| t - s.seen < SESSION_IDLE && t - s.created < SESSION_MAX);
    if !ok {
        ss.remove(&id);
        return None;
    }
    let s = ss.get_mut(&id).unwrap();
    s.seen = t;
    Some((id, s.csrf.clone()))
}

fn handle(sh: &Shared, mut s: Conn) {
    let secure = sh.cfg.secure_cookie;
    let r = match read_request(&mut s, sh.cfg.proxy_protocol) {
        Ok(r) => r,
        Err(code) => {
            write_resp(&mut s, resp(code, "text/plain", reason(code)), secure);
            return;
        }
    };
    let out = route(sh, &r).unwrap_or_else(|code| json_resp(code, json!({"error": reason(code)})));
    write_resp(&mut s, out, secure);
}

fn route(sh: &Shared, r: &Req) -> Result<Resp, u16> {
    // Host allowlist: blocks DNS rebinding and stray virtual hosts.
    let host = r.headers.get("host").map(|h| h.to_ascii_lowercase()).ok_or(400u16)?;
    if !sh.cfg.hosts.contains(&host) {
        return Err(421);
    }
    if r.method == "POST" {
        // Same-origin POSTs only (browsers always send Origin on POST).
        let origin = r.headers.get("origin").ok_or(403u16)?;
        let want = format!("{}://{host}", if sh.cfg.secure_cookie { "https" } else { "http" });
        if !origin.eq_ignore_ascii_case(&want) {
            audit(&format!("rejected cross-origin POST {} from {} (origin {})", clean(&r.path, 80), r.peer, clean(origin, 80)));
            return Err(403);
        }
    }
    let sess = session_of(sh, r);
    match (r.method.as_str(), r.path.as_str()) {
        ("GET", "/app.js") => return Ok(resp(200, "text/javascript; charset=utf-8", APP_JS)),
        ("GET", "/app.css") => return Ok(resp(200, "text/css; charset=utf-8", APP_CSS)),
        ("GET", "/login") => return Ok(if sess.is_some() { redirect("/") } else { resp(200, "text/html; charset=utf-8", LOGIN) }),
        ("POST", "/login") => return login(sh, r),
        ("GET", "/") => return Ok(if sess.is_some() { resp(200, "text/html; charset=utf-8", INDEX) } else { redirect("/login") }),
        _ => {}
    }
    let Some((sid, csrf)) = sess else {
        return Ok(json_resp(401, json!({"error": "login"})));
    };
    if r.method == "POST" {
        let got = r.headers.get("x-ratel-csrf").map(String::as_str).unwrap_or("");
        if !ct_eq(got.as_bytes(), csrf.as_bytes()) {
            audit(&format!("rejected POST {} from {}: bad CSRF token", clean(&r.path, 80), r.peer));
            return Err(403);
        }
    }
    match (r.method.as_str(), r.path.as_str()) {
        ("GET", "/api/session") => {
            let exp = sh.sessions.lock().unwrap().get(&sid).map_or(0.0, |s| (s.seen + SESSION_IDLE).min(s.created + SESSION_MAX));
            Ok(json_resp(200, json!({"csrf": csrf, "expires": exp})))
        }
        ("POST", "/logout") => {
            sh.sessions.lock().unwrap().remove(&sid);
            let mut out = json_resp(200, json!({"ok": true}));
            out.extra.push(("Set-Cookie", format!("{}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict{}", cookie_name(sh),
                if sh.cfg.secure_cookie { "; Secure" } else { "" })));
            Ok(out)
        }
        ("GET", "/api/status") => Ok(json_resp(200, api_status(sh))),
        ("GET", "/api/live") => Ok(json_resp(200, read_json(&sh.cfg.status.with_file_name("live.json"), 8 << 20)
            .unwrap_or_else(|| json!({"missing": true, "flows": [], "entities": [], "dns": []})))),
        ("GET", "/api/alerts") => Ok(json_resp(200, api_alerts(sh, r))),
        ("GET", "/api/incidents") => Ok(json_resp(200, api_incidents(sh, r))),
        ("GET", p) if p.starts_with("/api/incident/") => api_incident(sh, &p["/api/incident/".len()..]).map(|v| json_resp(200, v)),
        ("POST", "/api/ack") => match api_ack(sh, r) {
            Err(422) => Ok(json_resp(422, json!({"error": "these alerts come from unidentified processes (or have no concrete destination), so they can't be silenced; mark the incident reviewed instead"}))),
            other => other.map(|v| json_resp(200, v)),
        },
        (_, p) if p.starts_with("/api/") || p == "/logout" => Err(if ["GET", "POST"].contains(&r.method.as_str()) { 404 } else { 405 }),
        _ => Err(404),
    }
}

fn login(sh: &Shared, r: &Req) -> Result<Resp, u16> {
    let t = now();
    let form = parse_form(std::str::from_utf8(&r.body).unwrap_or(""));
    let tok = form.get("token").map(|s| s.trim()).unwrap_or("");
    let _gate = sh.login_gate.lock().unwrap();
    if tok.is_empty() || tok.len() > 256 || !ct_eq(&Sha256::digest(tok.as_bytes()), &sh.token_hash) {
        audit(&format!("login FAILED from {}", r.peer));
        std::thread::sleep(Duration::from_millis(500));
        return Ok(redirect("/login?error=1#error"));
    }
    let id = hex(&sandbox::random_bytes::<32>());
    let csrf = hex(&sandbox::random_bytes::<32>());
    {
        let mut ss = sh.sessions.lock().unwrap();
        ss.retain(|_, s| t - s.seen < SESSION_IDLE && t - s.created < SESSION_MAX);
        if ss.len() >= MAX_SESSIONS {
            if let Some(oldest) = ss.iter().min_by(|a, b| a.1.seen.partial_cmp(&b.1.seen).unwrap()).map(|(k, _)| k.clone()) {
                ss.remove(&oldest);
            }
        }
        ss.insert(id.clone(), Session { csrf, created: t, seen: t });
    }
    audit(&format!("login ok from {}", r.peer));
    let mut out = redirect("/");
    out.extra.push(("Set-Cookie", format!("{}={id}; Max-Age={}; Path=/; HttpOnly; SameSite=Strict{}", cookie_name(sh), SESSION_MAX as u64,
        if sh.cfg.secure_cookie { "; Secure" } else { "" })));
    Ok(out)
}

// ------------------------------------------------------------------ data

fn read_capped(p: &Path, max: u64) -> Option<Vec<u8>> {
    let f = std::fs::File::open(p).ok()?;
    if f.metadata().ok()?.len() > max {
        return None;
    }
    let mut v = vec![];
    f.take(max).read_to_end(&mut v).ok()?;
    Some(v)
}

fn read_json(p: &Path, max: u64) -> Option<Value> {
    serde_json::from_slice(&read_capped(p, max)?).ok()
}

/// The last `max` bytes of a log, starting at a line boundary.
fn tail_lines(p: &Path, max: u64) -> Vec<String> {
    let Ok(mut f) = std::fs::File::open(p) else { return vec![] };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(max);
    if f.seek(SeekFrom::Start(start)).is_err() {
        return vec![];
    }
    let mut v = vec![];
    let _ = f.take(max).read_to_end(&mut v);
    let s = String::from_utf8_lossy(&v);
    let mut lines: Vec<String> = s.lines().map(str::to_string).collect();
    if start > 0 && !lines.is_empty() {
        lines.remove(0); // partial first line
    }
    lines
}

fn sev_rank(s: &str) -> u8 {
    crate::watch::notify::sev_rank(s)
}

fn api_status(sh: &Shared) -> Value {
    let Some(mut v) = read_json(&sh.cfg.status, 1 << 20) else { return json!({"alive": false, "missing": true}) };
    let age = now() - v["updated"].as_f64().unwrap_or(0.0);
    let stopped = v["stopped"].as_bool() == Some(true);
    v["age_s"] = json!((age * 10.0).round() / 10.0);
    v["alive"] = json!(!stopped && age < 120.0);
    v
}

fn alerts_from_log(sh: &Shared) -> Vec<Value> {
    tail_lines(&sh.cfg.log, LOG_TAIL).iter().filter_map(|l| serde_json::from_str::<Value>(l).ok()).collect()
}

fn api_alerts(sh: &Shared, r: &Req) -> Value {
    let t = now();
    let since: f64 = r.query.get("since").and_then(|s| s.parse().ok()).unwrap_or(86_400.0f64).clamp(60.0, 400.0 * 86_400.0);
    let min = sev_rank(r.query.get("min").map(String::as_str).unwrap_or("low")).max(1);
    let limit: usize = r.query.get("limit").and_then(|s| s.parse().ok()).unwrap_or(1000).min(1000);
    let all = alerts_from_log(sh);
    let mut hourly: Vec<BTreeMap<&str, f64>> = (0..48).map(|h| {
        let mut m = BTreeMap::new();
        m.insert("t", (t / 3600.0).floor() * 3600.0 - (47 - h) as f64 * 3600.0);
        m.insert("high", 0.0);
        m.insert("medium", 0.0);
        m.insert("low", 0.0);
        m
    }).collect();
    let mut counts: BTreeMap<String, u64> = [("high", 0), ("medium", 0), ("low", 0)].iter().map(|(k, v)| (k.to_string(), *v)).collect();
    let mut sel = vec![];
    for a in all.into_iter().rev() {
        let at = a["t"].as_f64().unwrap_or(0.0);
        let sev = a["severity"].as_str().unwrap_or("").to_string();
        if sev_rank(&sev) < min {
            continue;
        }
        let first = hourly[0]["t"];
        if at >= first {
            let i = (((at - first) / 3600.0) as usize).min(47);
            if let Some(c) = hourly[i].get_mut(sev.as_str()) {
                *c += 1.0;
            }
        }
        if at >= t - since {
            *counts.entry(sev).or_default() += 1;
            if sel.len() < limit {
                let mut a = a;
                if let Some(o) = a.as_object_mut() {
                    o.remove("context"); // heavy; the incident view has it
                }
                sel.push(a);
            }
        }
    }
    json!({"alerts": sel, "counts": counts, "hourly": hourly})
}

fn ack_map(sh: &Shared) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for f in feedback_files(&sh.cfg.state) {
        let Some(b) = read_capped(&f, 4 << 20) else { continue };
        for l in String::from_utf8_lossy(&b).lines() {
            if let Ok(v) = serde_json::from_str::<Value>(l) {
                if let Some(id) = v["id"].as_str() {
                    m.insert(id.to_string(), json!({"t": v["t"], "fp": v["fp"], "note": v["note"], "via": v["via"]}));
                }
            }
        }
    }
    m
}

fn api_incidents(sh: &Shared, r: &Req) -> Value {
    let limit: usize = r.query.get("limit").and_then(|s| s.parse().ok()).unwrap_or(200).min(1000);
    let acks = ack_map(sh);
    let mut by: HashMap<String, (f64, String, String, HashSet<String>, usize, HashSet<String>)> = HashMap::new();
    for a in alerts_from_log(sh) {
        let Some(id) = a["incident"].as_str().filter(|s| !s.is_empty()) else { continue };
        let t = a["t"].as_f64().unwrap_or(0.0);
        let sev = a["severity"].as_str().unwrap_or("low").to_string();
        let e = by.entry(id.to_string()).or_insert((t, a["title"].as_str().unwrap_or("").to_string(), sev.clone(), HashSet::new(), 0, HashSet::new()));
        if t < e.0 {
            e.0 = t;
            e.1 = a["title"].as_str().unwrap_or("").to_string();
        }
        if sev_rank(&sev) > sev_rank(&e.2) {
            e.2 = sev;
        }
        e.3.insert(a["kind"].as_str().unwrap_or("").to_string());
        e.4 += 1;
        if e.5.len() < 8 {
            e.5.insert(a["entity"].as_str().unwrap_or("").to_string());
        }
    }
    let mut v: Vec<(f64, Value)> = by.into_iter().map(|(id, (t, title, sev, kinds, n, ents))| {
        let mut kinds: Vec<String> = kinds.into_iter().collect();
        kinds.sort();
        let mut ents: Vec<String> = ents.into_iter().collect();
        ents.sort();
        let ack = acks.get(&id).cloned().unwrap_or(Value::Null);
        (t, json!({"id": id, "t": t, "time": local_time(t), "title": title, "severity": sev, "kinds": kinds, "alerts": n,
            "entities": ents, "ack": ack}))
    }).collect();
    v.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    json!({"incidents": v.into_iter().take(limit).map(|x| x.1).collect::<Vec<_>>()})
}

/// Incident ids are created by the daemon as YYYYMMDD-HHMMSS-<kind>[n]; anything else is rejected
/// before it gets near a file path.
fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() >= 17 && b.len() <= 40 && b[..8].iter().all(u8::is_ascii_digit) && b[8] == b'-' && b[9..15].iter().all(u8::is_ascii_digit)
        && b[15] == b'-' && b[16..].iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

fn incident_lines(sh: &Shared, id: &str) -> Result<Vec<Value>, u16> {
    if !valid_id(id) {
        return Err(404);
    }
    let p = sh.cfg.state.join("incidents").join(format!("{id}.jsonl"));
    let b = read_capped(&p, INCIDENT_MAX).ok_or(404u16)?;
    Ok(String::from_utf8_lossy(&b).lines().filter_map(|l| serde_json::from_str(l).ok()).collect())
}

fn api_incident(sh: &Shared, id: &str) -> Result<Value, u16> {
    let lines = incident_lines(sh, id)?;
    let head = lines.iter().find(|l| l["type"] == "incident").cloned().unwrap_or(Value::Null);
    let alerts: Vec<Value> = lines.iter().filter(|l| l["type"] == "alert").map(|l| l["alert"].clone()).collect();
    let context = alerts.iter().find(|a| !a["context"].is_null()).map(|a| a["context"].clone()).unwrap_or(Value::Null);
    #[derive(Default)]
    struct Agg {
        sent: u64,
        recv: u64,
        conns: u32,
        first: f64,
        last: f64,
    }
    let mut per: HashMap<String, Agg> = HashMap::new();
    let mut seen: HashMap<u64, (u64, u64)> = HashMap::new();
    let mut dns: HashMap<String, u64> = HashMap::new();
    let mut flags = vec![];
    let (mut nb, mut na) = (0u64, 0u64);
    for l in &lines {
        let phase = l["type"].as_str().unwrap_or("");
        if phase != "before" && phase != "after" {
            continue;
        }
        if phase == "before" { nb += 1 } else { na += 1 }
        let e = &l["ev"];
        let t = e["t"].as_f64().unwrap_or(0.0);
        match e["e"].as_str() {
            Some(k @ ("tcp" | "udp")) => {
                let key = format!("{}:{}", e["rip"].as_str().unwrap_or("?"), e["rport"]);
                let a = per.entry(key).or_insert_with(|| Agg { first: t, ..Default::default() });
                a.last = t;
                if k == "udp" {
                    let b = e["len"].as_u64().unwrap_or(0) * e["scale"].as_u64().unwrap_or(1);
                    if e["inbound"] == true { a.recv += b } else { a.sent += b }
                } else {
                    let cid = e["id"].as_u64().unwrap_or(0);
                    let (s, r) = (e["sent"].as_u64().unwrap_or(0), e["recv"].as_u64().unwrap_or(0));
                    match seen.get(&cid) {
                        Some((ps, pr)) => {
                            a.sent += s.saturating_sub(*ps);
                            a.recv += r.saturating_sub(*pr);
                        }
                        None => {
                            a.conns += 1;
                            if phase == "after" {
                                a.sent += s;
                                a.recv += r;
                            }
                        }
                    }
                    seen.insert(cid, (s, r));
                }
            }
            Some("dns") if e["resp"] != true => *dns.entry(e["name"].as_str().unwrap_or("?").to_string()).or_default() += 1,
            Some("proc") if flags.len() < 50 => flags.push(json!({"t": t, "rule": e["rule"], "detail": e["detail"]})),
            _ => {}
        }
    }
    let mut eps: Vec<(String, Agg)> = per.into_iter().collect();
    eps.sort_by(|a, b| (b.1.sent + b.1.recv).cmp(&(a.1.sent + a.1.recv)));
    let mut dns: Vec<(String, u64)> = dns.into_iter().collect();
    dns.sort_by(|a, b| b.1.cmp(&a.1));
    let dns_total = dns.len();
    let severity = alerts.iter().filter_map(|a| a["severity"].as_str()).max_by_key(|s| sev_rank(s)).unwrap_or("low").to_string();
    let mut kinds: Vec<String> = alerts.iter().filter_map(|a| a["kind"].as_str().map(str::to_string)).collect();
    kinds.sort();
    kinds.dedup();
    Ok(json!({
        "id": id, "t": head["t"], "time": head["time"], "title": head["title"], "severity": severity, "kinds": kinds,
        "alerts": alerts, "context": context,
        "activity": {
            "endpoints": eps.into_iter().take(50).map(|(k, a)| json!({"endpoint": k, "sent": a.sent, "received": a.recv, "conns": a.conns,
                "first": a.first, "last": a.last})).collect::<Vec<_>>(),
            "dns": dns.into_iter().take(30).map(|(n, c)| json!({"name": n, "count": c})).collect::<Vec<_>>(),
            "dns_total": dns_total, "flags": flags, "events_before": nb, "events_after": na,
        },
        "ack": ack_map(sh).get(id).cloned().unwrap_or(Value::Null),
    }))
}

fn api_ack(sh: &Shared, r: &Req) -> Result<Value, u16> {
    let v: Value = serde_json::from_slice(&r.body).map_err(|_| 400u16)?;
    let id = v["id"].as_str().ok_or(400u16)?;
    let fp = v["fp"].as_bool().unwrap_or(false);
    let any = v["any_dest"].as_bool().unwrap_or(false);
    let note: String = v["note"].as_str().unwrap_or("").chars().filter(|c| !c.is_control()).take(500).collect();
    let lines = incident_lines(sh, id)?;
    let alerts: Vec<Value> = lines.iter().filter(|l| l["type"] == "alert").map(|l| l["alert"].clone()).collect();
    let sup = crate::watch::incidents::suppressions_for(&alerts, any);
    if fp && sup.is_empty() {
        return Err(422);
    }
    let rec = json!({"id": id, "t": now(), "fp": fp, "note": if note.is_empty() { Value::Null } else { note.clone().into() },
        "suppress": if fp { sup.clone() } else { vec![] }, "via": "web", "ip": r.peer.to_string()});
    let dir = sh.cfg.state.join("feedback.d");
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("web.jsonl")).map_err(|e| {
        audit(&format!("ack {id} failed: {e}"));
        500u16
    })?;
    writeln!(f, "{rec}").map_err(|_| 500u16)?;
    audit(&format!("ack {id} fp={fp} from {}{}", r.peer, if fp { format!(": suppress {sup:?}") } else { String::new() }));
    Ok(json!({"ok": true, "suppress": if fp { sup } else { vec![] }}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_decoding() {
        assert!(valid_id("20261101-192000-exfil"));
        assert!(valid_id("20261101-192013-process2"));
        assert!(!valid_id("../../etc/passwd"));
        assert!(!valid_id("20261101-192000-exfil/../x"));
        assert!(!valid_id("20261101-192000-EXFIL"));
        assert_eq!(url_decode("a%2Fb+c%zz"), "a/b c%zz");
        assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd") && !ct_eq(b"ab", b"abc"));
    }
}
