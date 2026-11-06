//! Continuous ping test for one device: latency, jitter and packet loss.
//!
//! A single background thread sends one echo request per interval (like
//! `ping -i`), so the test costs one sleeping thread and one tiny packet per
//! second. If ICMP is not allowed for this user, it measures TCP connect time
//! to a port instead (a closed port works too: the device's "refused" reply
//! still measures the round trip).
//!
//! The statistics are kept incrementally ([`PingStats`]) and the raw samples
//! are capped at [`MAX_SAMPLES`], so even a test left running for days uses a
//! few kilobytes.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use super::ping;

/// Samples kept for the chart (one hour at one ping per second).
pub const MAX_SAMPLES: usize = 3_600;

/// How the round trip is measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    Icmp,
    /// TCP connect time to this port.
    Tcp(u16),
}

/// One result: `None` = lost (no reply within the timeout).
pub enum PingMsg {
    Sample(Option<Duration>),
    Done,
}

/// Options chosen in the ping test window.
#[derive(Clone, Copy, Debug)]
pub struct PingOptions {
    /// Number of pings; 0 = until stopped.
    pub count: u32,
    pub interval: Duration,
    pub timeout: Duration,
}

/// A running ping test.
pub struct PingTest {
    pub probe: Probe,
    pub rx: Receiver<PingMsg>,
    cancel: Arc<AtomicBool>,
    pub running: bool,
    pub stats: PingStats,
    /// Latest samples in milliseconds (`None` = lost), oldest first.
    pub samples: VecDeque<Option<f32>>,
}

impl PingTest {
    /// Start pinging `ip`. `open_ports` (if the device was port-scanned) gives
    /// a good TCP port to use when ICMP is unavailable. `on_result` is called
    /// from the background thread after every ping (the window uses it to
    /// redraw only when there is something new, instead of on a timer).
    pub fn start(
        ip: Ipv4Addr,
        options: PingOptions,
        open_ports: &[u16],
        on_result: impl Fn() + Send + 'static,
    ) -> PingTest {
        let probe =
            if ping::icmp_available() { Probe::Icmp } else { Probe::Tcp(open_ports.first().copied().unwrap_or(80)) };
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let stop = cancel.clone();
        let started = std::thread::Builder::new().name("ping-test".into()).stack_size(128 * 1024).spawn(move || {
            let mut seq: u16 = 1;
            let mut sent = 0u32;
            while !stop.load(Ordering::Relaxed) && (options.count == 0 || sent < options.count) {
                let t0 = Instant::now();
                let rtt = match probe {
                    Probe::Icmp => ping::icmp_ping(ip, options.timeout, seq).ok().flatten(),
                    Probe::Tcp(port) => tcp_rtt(ip, port, options.timeout),
                };
                sent += 1;
                seq = seq.wrapping_add(1);
                if tx.send(PingMsg::Sample(rtt)).is_err() {
                    return; // window closed
                }
                on_result();
                // Wait for the rest of the interval (in short steps so Stop is instant).
                let next = t0 + options.interval;
                while !stop.load(Ordering::Relaxed) && Instant::now() < next {
                    std::thread::sleep(next.saturating_duration_since(Instant::now()).min(Duration::from_millis(50)));
                }
            }
            let _ = tx.send(PingMsg::Done);
            on_result();
        });
        PingTest { probe, rx, running: started.is_ok(), cancel, stats: PingStats::default(), samples: VecDeque::new() }
    }

    /// Stop the test (the thread ends after its current ping).
    pub fn stop(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// Take all new results from the background thread. Returns true if
    /// anything changed (so the window knows to redraw).
    pub fn poll(&mut self) -> bool {
        let mut changed = false;
        while let Ok(msg) = self.rx.try_recv() {
            changed = true;
            match msg {
                PingMsg::Sample(rtt) => {
                    let ms = rtt.map(|d| d.as_secs_f32() * 1000.0);
                    self.stats.add(ms);
                    if self.samples.len() == MAX_SAMPLES {
                        self.samples.pop_front();
                    }
                    self.samples.push_back(ms);
                }
                PingMsg::Done => self.running = false,
            }
        }
        changed
    }
}

impl Drop for PingTest {
    /// Stop the background thread when the test is dropped.
    fn drop(&mut self) {
        // Closing the window stops the thread.
        self.stop();
    }
}

/// Running statistics (no need to keep every sample).
#[derive(Clone, Copy, Debug, Default)]
pub struct PingStats {
    pub sent: u32,
    pub received: u32,
    pub min: f32,
    pub max: f32,
    sum: f64,
    /// Mean absolute difference between consecutive replies (RFC 3550 idea).
    jitter_sum: f64,
    jitter_n: u32,
    last: Option<f32>,
    pub last_ms: Option<f32>,
}

impl PingStats {
    /// Record one ping: `Some(ms)` = reply time, `None` = lost.
    pub fn add(&mut self, ms: Option<f32>) {
        self.sent += 1;
        self.last_ms = ms;
        let Some(ms) = ms else { return };
        if self.received == 0 {
            self.min = ms;
            self.max = ms;
        } else {
            self.min = self.min.min(ms);
            self.max = self.max.max(ms);
        }
        self.received += 1;
        self.sum += f64::from(ms);
        if let Some(prev) = self.last {
            self.jitter_sum += f64::from((ms - prev).abs());
            self.jitter_n += 1;
        }
        self.last = Some(ms);
    }

    /// Number of pings that got no reply.
    pub fn lost(&self) -> u32 {
        self.sent - self.received
    }

    /// Packet loss in percent.
    pub fn loss_percent(&self) -> f32 {
        if self.sent == 0 { 0.0 } else { self.lost() as f32 * 100.0 / self.sent as f32 }
    }

    /// Average reply time in ms (None before the first reply).
    pub fn avg(&self) -> Option<f32> {
        (self.received > 0).then(|| (self.sum / f64::from(self.received)) as f32)
    }

    /// Jitter: average change between consecutive reply times, in ms.
    pub fn jitter(&self) -> Option<f32> {
        (self.jitter_n > 0).then(|| (self.jitter_sum / f64::from(self.jitter_n)) as f32)
    }
}

/// Round-trip time of a TCP handshake (accepted or refused both count).
fn tcp_rtt(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<Duration> {
    let t = Instant::now();
    match TcpStream::connect_timeout(&SocketAddr::V4(SocketAddrV4::new(ip, port)), timeout) {
        Ok(_) => Some(t.elapsed()),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => Some(t.elapsed()),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats() {
        let mut s = PingStats::default();
        for v in [Some(10.0), None, Some(20.0), Some(15.0), None] {
            s.add(v);
        }
        assert_eq!((s.sent, s.received, s.lost()), (5, 3, 2));
        assert_eq!(s.loss_percent(), 40.0);
        assert_eq!((s.min, s.max), (10.0, 20.0));
        assert_eq!(s.avg(), Some(15.0));
        assert_eq!(s.jitter(), Some(7.5)); // |20-10| and |15-20|
    }

    #[test]
    fn localhost_test_runs_and_stops() {
        let opts = PingOptions { count: 3, interval: Duration::from_millis(50), timeout: Duration::from_millis(300) };
        let mut t = PingTest::start(Ipv4Addr::LOCALHOST, opts, &[], || {});
        let deadline = Instant::now() + Duration::from_secs(5);
        while t.running && Instant::now() < deadline {
            t.poll();
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!t.running);
        assert_eq!(t.stats.sent, 3);
        assert_eq!(t.samples.len(), 3);
    }
}
