//! Alert delivery through the homelab notify socket (see ~/Projects/notify-sdk):
//! write-only Unix stream socket, "Subject:/Source:" headers, blank line, body,
//! close. Batches alerts, respects the server-wide rate limit (one message per
//! 6 s after a burst of 20), and falls back to syslog when the socket is down.

use super::engine::Alert;
use std::io::Write;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::time::{Duration, Instant};

pub struct Notifier {
    path: String,
    pub enabled: bool,
    min_sev: u8,
    pending: Vec<Alert>,
    first_pending: Option<Instant>,
    last_sent: Option<Instant>,
    /// Hold alerts this long to send several as one message.
    batch: Duration,
    sent_today: (u64, u32),
    pub daily_cap: u32,
}

pub fn sev_rank(s: &str) -> u8 {
    match s {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl Notifier {
    pub fn new(enabled: bool, min_sev: &str) -> Notifier {
        Notifier {
            path: std::env::var("NOTIFY_SOCKET").unwrap_or_else(|_| "/run/prosody/notify.sock".into()),
            enabled, min_sev: sev_rank(min_sev).max(1), pending: vec![], first_pending: None, last_sent: None,
            batch: Duration::from_secs(30), sent_today: (0, 0), daily_cap: 60,
        }
    }

    pub fn push(&mut self, a: &Alert) {
        if !self.enabled || sev_rank(a.severity) < self.min_sev {
            return;
        }
        if self.pending.is_empty() {
            self.first_pending = Some(Instant::now());
        }
        self.pending.push(a.clone());
    }

    /// Send what is due. Call regularly (every loop iteration).
    pub fn flush(&mut self, force: bool) {
        let Some(first) = self.first_pending else { return };
        let high = self.pending.iter().any(|a| a.severity == "high");
        let due = force || first.elapsed() >= self.batch || (high && first.elapsed() >= Duration::from_secs(5));
        let spaced = self.last_sent.is_none_or(|l| l.elapsed() >= Duration::from_secs(10));
        if !due || (!spaced && !force) {
            return;
        }
        let day = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()) / 86_400;
        if self.sent_today.0 != day {
            self.sent_today = (day, 0);
        }
        let alerts = std::mem::take(&mut self.pending);
        self.first_pending = None;
        let (subject, body) = render(&alerts);
        if self.sent_today.1 >= self.daily_cap {
            syslog(&format!("{subject} (daily XMPP cap reached) {}", one_line(&body)));
            return;
        }
        self.sent_today.1 += 1;
        self.last_sent = Some(Instant::now());
        if let Err(e) = send(&self.path, &subject, "ratel", &body) {
            // Notification lost, not a failure of the monitor: log and carry on.
            syslog(&format!("notify failed ({e}): {subject}"));
        }
    }
}

pub fn render(alerts: &[Alert]) -> (String, String) {
    let worst = alerts.iter().max_by_key(|a| sev_rank(a.severity)).unwrap();
    let subject = if alerts.len() == 1 {
        format!("[{}] {}", worst.severity.to_uppercase(), worst.title)
    } else {
        format!("[{}] {} (+{} more)", worst.severity.to_uppercase(), worst.title, alerts.len() - 1)
    };
    let mut body = String::new();
    let mut sorted: Vec<&Alert> = alerts.iter().collect();
    sorted.sort_by_key(|a| std::cmp::Reverse(sev_rank(a.severity)));
    for a in sorted {
        body += &format!("{} {}\n", a.severity.to_uppercase(), a.title);
        if a.pid != 0 {
            body += &format!("  pid {} ({})\n", a.pid, a.entity);
        }
        for e in a.evidence.iter().take(5) {
            body += &format!("  - {e}\n");
        }
        if body.len() > 3500 {
            body += "…more in /var/log/ratel/alerts.jsonl\n";
            break;
        }
    }
    (one_line(&subject).chars().take(190).collect(), body)
}

/// One message over the write-only socket (protocol from notify-sdk).
pub fn send(path: &str, subject: &str, source: &str, body: &str) -> std::io::Result<()> {
    let msg = format!("Subject: {}\nSource: {}\n\n{}", one_line(subject), one_line(source), body);
    let mut s = UnixStream::connect(path)?;
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(msg.as_bytes())
    // drop = clean close = message sent
}

pub fn syslog(msg: &str) {
    eprintln!("ratel: {msg}");
    if let Ok(s) = UnixDatagram::unbound() {
        // <12> = facility user, severity warning
        let _ = s.send_to(format!("<12>ratel: {}", one_line(msg)).as_bytes(), "/dev/log");
    }
}
