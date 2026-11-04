//! The scanning engine. It knows nothing about the user interface: the GUI
//! and the command-line mode both start a [`Job`] and read [`Event`]s from it.
//!
//! ## Threads and resources
//!
//! A job runs on one coordinator thread plus a fixed pool of worker threads
//! (`Settings::threads`, default 64, hard maximum [`MAX_THREADS`]). Workers
//! take the next address from a shared atomic counter, so there is no queue to
//! grow, and they use small 256 KiB stacks. Network waits are blocking calls
//! with timeouts, so idle workers use no CPU. Only *alive* hosts are stored and
//! sent to the UI, which keeps memory small even for a /16 scan.
//!
//! Cancelling sets an atomic flag that every worker checks before taking new
//! work; the longest a worker can still be busy is one timeout.
//!
//! ## Slow ("polite") probing
//!
//! [`Speed`] profiles reduce the number of workers, add a random pause after
//! every probe and visit hosts/ports in a shuffled order. This avoids
//! tripping rate limits, port-scan detection and fragile IoT devices, at the
//! cost of a longer scan.

pub mod mac;
pub mod names;
pub mod ping;
pub mod pingtest;
pub mod ports;
pub mod range;
pub mod vendor;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use mac::Mac;
use ports::OpenPort;

/// Upper limit for worker threads, whatever the settings say.
pub const MAX_THREADS: usize = 256;
/// Stack size for worker threads (they only hold small buffers).
const WORKER_STACK: usize = 256 * 1024;

/// User-adjustable scan options (shown in the Settings window).
#[derive(Clone, Debug)]
pub struct Settings {
    /// Parallel workers (1–[`MAX_THREADS`]).
    pub threads: usize,
    /// How long to wait for each ping reply.
    pub ping_timeout_ms: u64,
    /// How many pings to send before giving up on an address (1–5).
    pub ping_attempts: u8,
    /// Look up names with reverse DNS.
    pub resolve_dns: bool,
    /// Ask devices for their NetBIOS (Windows/Samba) name.
    pub netbios: bool,
    /// How long to wait for each TCP port to connect.
    pub port_timeout_ms: u64,
    /// Read the greeting line services send on their own.
    pub grab_banners: bool,
    /// Ask devices for their mDNS (Bonjour/Avahi) and LLMNR names.
    pub multicast_names: bool,
    /// After finding devices, check the common ports on each of them.
    pub auto_ports: bool,
    /// How fast to probe (see [`Speed`]).
    pub speed: Speed,
}

/// Probe pacing. Normal is the fastest; the others trade time for stealth
/// and kindness to the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Speed {
    #[default]
    Normal,
    /// At most 8 workers, 150–400 ms pause after each probe, shuffled order.
    Polite,
    /// 2 workers, 1–3 s pause after each probe, shuffled order. Hard for
    /// intrusion-detection systems to spot, but slow (≈ 1 000 probes per 20 min).
    Slow,
}

impl Speed {
    pub const ALL: [Speed; 3] = [Speed::Normal, Speed::Polite, Speed::Slow];

    pub fn label(self) -> &'static str {
        match self {
            Speed::Normal => "Normal (fast)",
            Speed::Polite => "Polite (slower)",
            Speed::Slow => "Slow / stealthy",
        }
    }

    /// (max workers, pause range in ms, shuffle order)
    fn pacing(self) -> (usize, (u64, u64), bool) {
        match self {
            Speed::Normal => (MAX_THREADS, (0, 0), false),
            Speed::Polite => (8, (150, 400), true),
            Speed::Slow => (2, (1_000, 3_000), true),
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            threads: 64,
            ping_timeout_ms: 800,
            ping_attempts: 2,
            resolve_dns: true,
            netbios: true,
            port_timeout_ms: 500,
            grab_banners: false,
            multicast_names: true,
            auto_ports: true,
            speed: Speed::Normal,
        }
    }
}

impl Settings {
    /// Clamp every value to a safe range (protects against bad input and
    /// against settings that would overload the computer or the network).
    pub fn sanitized(&self) -> Settings {
        let (max_workers, _, _) = self.speed.pacing();
        Settings {
            threads: self.threads.clamp(1, max_workers),
            ping_timeout_ms: self.ping_timeout_ms.clamp(100, 10_000),
            ping_attempts: self.ping_attempts.clamp(1, 5),
            port_timeout_ms: self.port_timeout_ms.clamp(100, 10_000),
            ..self.clone()
        }
    }
}

/// What a device is to us.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Role {
    #[default]
    Device,
    /// The default gateway of one of our networks.
    Router,
    /// One of this computer's own addresses.
    ThisComputer,
}

/// How we learned that a host is up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Ping,
    Tcp,
    /// Did not answer ping, but answered ARP (firewall drops ping).
    Arp,
    /// One of our own addresses.
    Local,
}

impl Method {
    pub fn label(self) -> &'static str {
        match self {
            Method::Ping => "Ping",
            Method::Tcp => "TCP",
            Method::Arp => "ARP",
            Method::Local => "Local",
        }
    }
}

/// Everything known about one live device.
#[derive(Clone, Debug)]
pub struct Host {
    pub ip: Ipv4Addr,
    pub role: Role,
    pub method: Method,
    pub rtt: Option<Duration>,
    pub mac: Option<Mac>,
    pub vendor: Option<&'static str>,
    pub dns_name: Option<String>,
    pub netbios_name: Option<String>,
    /// Name the device announces over mDNS (Bonjour/Avahi) or LLMNR.
    pub local_name: Option<String>,
    /// UPnP friendly name (TVs, media players, routers, printers…).
    pub upnp_name: Option<String>,
    pub workgroup: Option<String>,
    /// `None` = ports not scanned yet; `Some(list)` = scanned (list may be empty).
    pub ports: Option<Vec<OpenPort>>,
    /// Operating system, from Nmap ("Identify with Nmap").
    pub os: Option<String>,
    /// Output of Nmap's identification scripts: `("443 ssl-cert", output)`.
    pub nmap_scripts: Vec<(String, String)>,
}

impl Host {
    /// Best name to show: what the device calls itself (NetBIOS, then
    /// mDNS/LLMNR, then its UPnP friendly name), then what DNS calls it.
    pub fn display_name(&self) -> &str {
        self.netbios_name
            .as_deref()
            .or(self.local_name.as_deref())
            .or(self.upnp_name.as_deref())
            .or(self.dns_name.as_deref())
            .unwrap_or("")
    }

    /// Fill in a name from the multicast sweep if the host has none of that kind yet.
    pub fn apply_swept(&mut self, kind: names::SweepKind, name: &str) {
        let slot = match kind {
            names::SweepKind::Mdns => &mut self.local_name,
            names::SweepKind::Upnp => &mut self.upnp_name,
        };
        if slot.is_none() {
            *slot = Some(name.to_string());
        }
    }
}

/// One IPv4 network this computer is connected to.
#[derive(Clone, Debug)]
pub struct LocalNet {
    pub interface: String,
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
    pub mac: Option<Mac>,
    pub gateway: Option<Ipv4Addr>,
}

impl LocalNet {
    /// Is `ip` inside this network (so ARP can see it)?
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = if self.prefix_len == 0 { 0 } else { u32::MAX << (32 - u32::from(self.prefix_len.min(32))) };
        u32::from(ip) & mask == u32::from(self.addr) & mask
    }
}

/// List the IPv4 networks of all active, non-loopback interfaces.
pub fn local_networks() -> Vec<LocalNet> {
    let mut nets = Vec::new();
    for iface in netdev::get_interfaces() {
        if !iface.is_up() || iface.is_loopback() {
            continue;
        }
        let name = iface.friendly_name.clone().unwrap_or_else(|| iface.name.clone());
        let mac = iface.mac_addr.map(|m| Mac(m.octets())).filter(Mac::is_valid);
        let gateway = iface.gateway.as_ref().and_then(|g| g.ipv4.first().copied());
        for net in &iface.ipv4 {
            let addr = net.addr();
            if addr.is_loopback() || addr.is_link_local() {
                continue;
            }
            nets.push(LocalNet { interface: name.clone(), addr, prefix_len: net.prefix_len(), mac, gateway });
        }
    }
    // Interfaces with a gateway (the "real" network) first.
    nets.sort_by_key(|n| n.gateway.is_none());
    nets
}

/// Messages from a running job.
pub enum Event {
    /// A live host was found (discovery jobs).
    Host(Box<Host>),
    /// An open port was found (port-scan jobs).
    OpenPort(Ipv4Addr, OpenPort),
    /// Names found by the multicast sweep; may arrive after the hosts
    /// themselves, so receivers apply them to existing and later hosts.
    Names(Vec<(Ipv4Addr, names::SweepKind, String)>),
    /// The job has stopped (finished or cancelled).
    Finished,
}

/// A running (or finished) scan.
pub struct Job {
    cancel: Arc<AtomicBool>,
    done: Arc<AtomicUsize>,
    pub rx: Receiver<Event>,
    pub total: usize,
    pub started: Instant,
    /// Set by the UI when `Event::Finished` arrives.
    pub finished_at: Option<Instant>,
    /// Was ICMP ping usable (discovery jobs)?
    pub icmp: bool,
}

impl Job {
    /// Ask all workers to stop. Returns immediately.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
    /// Number of work items completed so far.
    pub fn done(&self) -> usize {
        self.done.load(Ordering::Relaxed)
    }
    pub fn elapsed(&self) -> Duration {
        self.finished_at.unwrap_or_else(Instant::now) - self.started
    }
}

/// Run `work(i)` for every `i` in `0..total` on a pool of `threads` workers,
/// in the background, paced according to `speed`.
///
/// Work items are just numbers handed out by an atomic counter, so the job
/// never allocates a list of all items (a port scan of 256 hosts × 65 535
/// ports would otherwise need hundreds of megabytes). The coordinator thread
/// waits for all workers (scoped threads) and then sends [`Event::Finished`].
#[allow(clippy::too_many_arguments)] // each is a distinct, documented knob
fn spawn_pool<F>(
    total: usize,
    threads: usize,
    speed: Speed,
    cancel: Arc<AtomicBool>,
    done: Arc<AtomicUsize>,
    tx: Sender<Event>,
    wait_for: Option<std::thread::JoinHandle<()>>,
    work: F,
) where
    F: Fn(usize, &Sender<Event>) + Send + Sync + 'static,
{
    let (max_workers, (pause_min, pause_max), shuffle) = speed.pacing();
    let order = if shuffle { Shuffle::new(total, seed()) } else { Shuffle::identity() };
    let fallback_tx = tx.clone();
    let spawned = std::thread::Builder::new().name("scan-coordinator".into()).spawn(move || {
        let next = AtomicUsize::new(0);
        let workers = threads.clamp(1, max_workers).min(total.max(1));
        std::thread::scope(|s| {
            for w in 0..workers {
                let tx = tx.clone();
                let (next, cancel, done, work, order) = (&next, &cancel, &done, &work, &order);
                let started = std::thread::Builder::new().stack_size(WORKER_STACK).spawn_scoped(s, move || {
                    let mut rng = Rng(seed() ^ (w as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15));
                    while !cancel.load(Ordering::Relaxed) {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= total {
                            break;
                        }
                        work(order.map(i, total), &tx);
                        done.fetch_add(1, Ordering::Relaxed);
                        if pause_max > 0 {
                            pause(rng.between(pause_min, pause_max), cancel);
                        }
                    }
                });
                // If the OS refuses more threads, carry on with the ones we have.
                if started.is_err() {
                    break;
                }
            }
        });
        // Helper work (the name sweep) must finish before the job does.
        if let Some(h) = wait_for {
            let _ = h.join();
        }
        let _ = tx.send(Event::Finished);
    });
    // Could not even start the coordinator (out of threads): end the job
    // cleanly instead of crashing; the UI shows it as finished.
    if spawned.is_err() {
        let _ = fallback_tx.send(Event::Finished);
    }
}

/// Sleep `ms` milliseconds in small steps so Stop still reacts quickly.
pub(crate) fn pause(ms: u64, cancel: &AtomicBool) {
    let end = Instant::now() + Duration::from_millis(ms);
    while !cancel.load(Ordering::Relaxed) {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        std::thread::sleep(left.min(Duration::from_millis(100)));
    }
}

/// A seed from the clock (no need for cryptographic randomness here: it
/// only decides probe order and pause lengths).
pub(crate) fn seed() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x1234_5678);
    nanos | 1
}

/// Tiny xorshift random number generator.
pub(crate) struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0.max(1);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    /// Uniform-ish value in `lo..=hi`.
    pub fn between(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo { lo } else { lo + self.next() % (hi - lo + 1) }
    }
}

/// A memory-free shuffle of `0..n`: `i ↦ (a·i + b) mod n` visits every index
/// exactly once when `gcd(a, n) = 1`. Not cryptographic, but it scatters the
/// order of hosts and ports so probes don't arrive in an obvious sequence.
struct Shuffle {
    a: u64,
    b: u64,
}

impl Shuffle {
    fn identity() -> Shuffle {
        Shuffle { a: 1, b: 0 }
    }

    fn new(n: usize, seed: u64) -> Shuffle {
        let n = n.max(1) as u64;
        let mut rng = Rng(seed);
        // Start from a large random multiplier and step until it is coprime with n.
        let mut a = (rng.next() % n.max(2)) | 1;
        while gcd(a, n) != 1 {
            a += 1;
        }
        Shuffle { a, b: rng.next() % n }
    }

    fn map(&self, i: usize, n: usize) -> usize {
        let n = n.max(1) as u128;
        ((u128::from(self.a) * i as u128 + u128::from(self.b)) % n) as usize
    }
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// Start finding live hosts among `ips`.
pub fn start_discovery(ips: Vec<Ipv4Addr>, settings: &Settings, nets: Vec<LocalNet>) -> Job {
    let settings = settings.sanitized();
    let (tx, rx) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicUsize::new(0));
    // Decide once whether unprivileged ICMP works here.
    let icmp = ping::icmp_available();
    let total = ips.len();

    // Multicast name sweep (mDNS + UPnP) for targets in our own networks,
    // running alongside the ping sweep. Results go into `swept` (read by the
    // workers) and are also sent as one `Event::Names` for hosts already found.
    let swept: SweptNames = Default::default();
    let local: Vec<Ipv4Addr> = nets.iter().map(|n| n.addr).collect();
    let in_lan: Vec<Ipv4Addr> = ips.iter().copied().filter(|ip| nets.iter().any(|n| n.contains(*ip))).collect();
    let sweeper = (settings.multicast_names && !in_lan.is_empty() && in_lan.len() <= 4096 && !local.is_empty())
        .then(|| {
            let (tx, swept) = (tx.clone(), swept.clone());
            std::thread::Builder::new()
                .name("name-sweep".into())
                .stack_size(512 * 1024)
                .spawn(move || {
                    let found = names::sweep(&in_lan, &local, Duration::from_millis(2_500));
                    if let Ok(mut map) = swept.write() {
                        for (ip, kind, name) in &found {
                            map.entry(*ip).or_default().push((*kind, name.clone()));
                        }
                    }
                    if !found.is_empty() {
                        let _ = tx.send(Event::Names(found));
                    }
                })
                .ok()
        })
        .flatten();

    let ctx = Arc::new(DiscoveryCtx { settings: settings.clone(), nets, icmp, swept });
    spawn_pool(total, settings.threads, settings.speed, cancel.clone(), done.clone(), tx, sweeper, move |i, tx| {
        if let Some(host) = ips.get(i).and_then(|ip| discover(*ip, &ctx)) {
            let _ = tx.send(Event::Host(Box::new(host)));
        }
    });

    Job { cancel, done, rx, total, started: Instant::now(), finished_at: None, icmp }
}

/// Largest port scan accepted in one go (e.g. a whole /24 × all 65 535 ports).
pub const MAX_PORT_CHECKS: usize = 17_000_000;

/// Start scanning `ports` on every address in `targets`.
///
/// Returns an error message if the scan would exceed [`MAX_PORT_CHECKS`].
pub fn start_port_scan(targets: Vec<Ipv4Addr>, ports: Vec<u16>, settings: &Settings) -> Result<Job, String> {
    let total = targets.len().saturating_mul(ports.len());
    if total > MAX_PORT_CHECKS {
        return Err(format!(
            "That is {total} port checks — too many for one scan. Pick fewer ports or fewer devices (limit {MAX_PORT_CHECKS})."
        ));
    }
    let settings = settings.sanitized();
    let (tx, rx) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicUsize::new(0));

    // Item i = (host i % hosts, port i / hosts): each port is tried on every
    // host before moving to the next port, so no single device receives a
    // burst of connections.
    let timeout = Duration::from_millis(settings.port_timeout_ms);
    let banners = settings.grab_banners;
    let n_hosts = targets.len().max(1);
    spawn_pool(total, settings.threads, settings.speed, cancel.clone(), done.clone(), tx, None, move |i, tx| {
        let (Some(&ip), Some(&port)) = (targets.get(i % n_hosts), ports.get(i / n_hosts)) else { return };
        if let Some(open) = ports::probe(ip, port, timeout, banners) {
            let _ = tx.send(Event::OpenPort(ip, open));
        }
    });

    Ok(Job { cancel, done, rx, total, started: Instant::now(), finished_at: None, icmp: true })
}

/// Names from the multicast sweep, shared between the sweep thread and workers.
type SweptNames = Arc<std::sync::RwLock<HashMap<Ipv4Addr, Vec<(names::SweepKind, String)>>>>;

/// Shared, read-only data for discovery workers.
struct DiscoveryCtx {
    settings: Settings,
    nets: Vec<LocalNet>,
    icmp: bool,
    /// Names from the multicast sweep (filled in while the scan runs).
    swept: SweptNames,
}

/// Check one address. Returns `None` if nobody is there.
fn discover(ip: Ipv4Addr, ctx: &DiscoveryCtx) -> Option<Host> {
    let s = &ctx.settings;
    let timeout = Duration::from_millis(s.ping_timeout_ms);
    let own = ctx.nets.iter().find(|n| n.addr == ip);
    let local_net = ctx.nets.iter().find(|n| n.contains(ip));

    // 1. Is it alive?
    let (mut method, mut rtt) = (None, None);
    if own.is_some() {
        method = Some(Method::Local);
    } else {
        for attempt in 0..s.ping_attempts {
            let reply = if ctx.icmp {
                let seq = (u32::from(ip) as u16).wrapping_add(u16::from(attempt));
                ping::icmp_ping(ip, timeout, seq).ok().flatten()
            } else {
                ping::tcp_probe(ip, timeout)
            };
            if reply.is_some() {
                rtt = reply;
                method = Some(if ctx.icmp { Method::Ping } else { Method::Tcp });
                break;
            }
        }
        // Outside our own networks ARP cannot help, so try TCP as well.
        if method.is_none() && ctx.icmp && local_net.is_none() {
            rtt = ping::tcp_probe(ip, timeout);
            method = rtt.map(|_| Method::Tcp);
        }
    }

    // 2. Hardware address (local networks only). The ping above already made
    //    the OS do an ARP request for this address.
    let mac = match own {
        Some(n) => n.mac,
        None if local_net.is_some() => mac::lookup(ip),
        None => None,
    };
    // On our own network a real TCP answer always leaves an ARP entry. No
    // entry means the "answer" came from a firewall or proxy in between, not
    // from a device at this address — so it does not count.
    if method == Some(Method::Tcp) && local_net.is_some() && mac.is_none() {
        method = None;
        rtt = None;
    }
    if method.is_none() {
        // A complete ARP entry means the device exists even though it
        // ignored our pings (typical for Windows PCs with the firewall on).
        mac?;
        method = Some(Method::Arp);
    }

    // 3. Names (only for live hosts, so dead addresses stay cheap).
    //    NetBIOS, mDNS, LLMNR, UPnP and a PTR query to the router all go out
    //    together. The system resolver is only asked if the router had no
    //    answer (it can be slow when no PTR record exists).
    let query = names::NameQuery {
        netbios: s.netbios,
        device_names: s.multicast_names,
        dns_server: if s.resolve_dns { local_net.and_then(|n| n.gateway) } else { None },
    };
    let asked = names::ask_device(ip, query, Duration::from_millis(700));
    let dns_name = asked.router_dns.clone().or_else(|| if s.resolve_dns { names::reverse_dns(ip) } else { None });
    let (netbios_name, workgroup) = asked.netbios.map(|n| (n.name, n.workgroup)).unwrap_or_default();

    let role = if own.is_some() {
        Role::ThisComputer
    } else if ctx.nets.iter().any(|n| n.gateway == Some(ip)) {
        Role::Router
    } else {
        Role::Device
    };

    Some(Host {
        ip,
        role,
        method: method?,
        rtt,
        vendor: mac.as_ref().and_then(vendor::lookup),
        mac,
        dns_name,
        netbios_name,
        local_name: asked.local_name,
        upnp_name: asked.upnp_name,
        workgroup,
        ports: None,
        os: None,
        nmap_scripts: Vec::new(),
    })
    .map(|mut h| {
        // Names the multicast sweep already found for this address.
        if let Ok(map) = ctx.swept.read()
            && let Some(list) = map.get(&ip)
        {
            for (kind, name) in list {
                h.apply_swept(*kind, name);
            }
        }
        h
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localnet_contains() {
        let n = LocalNet {
            interface: "x".into(),
            addr: Ipv4Addr::new(192, 168, 1, 37),
            prefix_len: 24,
            mac: None,
            gateway: None,
        };
        assert!(n.contains(Ipv4Addr::new(192, 168, 1, 200)));
        assert!(!n.contains(Ipv4Addr::new(192, 168, 2, 1)));
    }

    #[test]
    fn settings_are_clamped() {
        let s = Settings {
            threads: 100_000,
            ping_timeout_ms: 0,
            ping_attempts: 0,
            port_timeout_ms: 999_999,
            ..Settings::default()
        }
        .sanitized();
        assert_eq!((s.threads, s.ping_timeout_ms, s.ping_attempts, s.port_timeout_ms), (MAX_THREADS, 100, 1, 10_000));
    }

    #[test]
    fn port_scan_job_finds_localhost_listener_and_finishes() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let job =
            start_port_scan(vec![Ipv4Addr::LOCALHOST], vec![port, port.wrapping_add(1).max(1)], &Settings::default())
                .unwrap();
        let mut found = false;
        for ev in job.rx.iter() {
            match ev {
                Event::OpenPort(_, p) if p.port == port => found = true,
                Event::Finished => break,
                _ => {}
            }
        }
        assert!(found);
        assert_eq!(job.done(), 2);
    }

    #[test]
    fn shuffle_is_a_permutation() {
        for n in [1usize, 2, 7, 254, 1000, 4096] {
            let sh = Shuffle::new(n, 42 + n as u64);
            let mut seen = vec![false; n];
            for i in 0..n {
                let j = sh.map(i, n);
                assert!(!seen[j], "index {j} visited twice for n={n}");
                seen[j] = true;
            }
        }
    }

    #[test]
    fn polite_speed_limits_workers() {
        let s = Settings { threads: 64, speed: Speed::Polite, ..Settings::default() }.sanitized();
        assert_eq!(s.threads, 8);
        let s = Settings { threads: 64, speed: Speed::Slow, ..Settings::default() }.sanitized();
        assert_eq!(s.threads, 2);
    }

    #[test]
    fn huge_port_scan_is_refused_without_allocating() {
        let hosts: Vec<_> = (0..65_536u32).map(Ipv4Addr::from).collect();
        let ports: Vec<u16> = (1..=65_535).collect();
        assert!(start_port_scan(hosts, ports, &Settings::default()).is_err());
    }

    #[test]
    fn cancel_stops_quickly() {
        // 4096 unroutable addresses would take minutes; cancel must stop it.
        let ips: Vec<_> = (0..4096u32).map(|i| Ipv4Addr::from(0xC000_0200 + (i % 256))).collect();
        let s = Settings {
            threads: 8,
            ping_timeout_ms: 200,
            ping_attempts: 1,
            resolve_dns: false,
            netbios: false,
            ..Settings::default()
        };
        let job = start_discovery(ips, &s, Vec::new());
        std::thread::sleep(Duration::from_millis(300));
        let t = Instant::now();
        job.cancel();
        for ev in job.rx.iter() {
            if matches!(ev, Event::Finished) {
                break;
            }
        }
        assert!(t.elapsed() < Duration::from_secs(5));
        assert!(job.done() < 4096);
    }
}
