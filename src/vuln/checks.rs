//! Proton's own configuration checks ("PIS-xxxx").
//!
//! These find problems that have no CVE number because they are settings,
//! not software bugs: services left without a password, cleartext logins,
//! management interfaces exposed to the network.
//!
//! Every check is **non-destructive**: it only reads what the service sends
//! to anyone who connects, or tries the documented anonymous/guest access
//! (FTP `anonymous`, MQTT without credentials). Nothing is written, changed or
//! exploited.
//!
//! CVSS v4.0 scores were calculated from the vectors below with the FIRST
//! CVSS v4.0 reference algorithm (via the `ae-cvss-calculator` package) and
//! are stored here so the app needs no calculator at run time.

use std::net::Ipv4Addr;

use super::Finding;
use super::score::{self, Cvss, Severity};

/// Definition of one built-in check.
pub struct Check {
    pub id: &'static str,
    pub title: &'static str,
    /// CVSS v4.0 base vector and its score.
    pub vector: &'static str,
    pub score: f32,
    /// Threat component for the priority rating: how easy and how likely
    /// misuse is (no exploit code is needed for most of these).
    pub threat: f32,
    pub description: &'static str,
    pub solution: &'static str,
}

impl Check {
    /// Create a finding of this check for `ip:port`.
    pub fn finding(&'static self, ip: Ipv4Addr, port: u16, service: &str, evidence: impl Into<String>) -> Finding {
        let severity = Severity::from_score(self.score);
        Finding {
            id: self.id.to_string(),
            title: self.title.to_string(),
            ip,
            port,
            service: service.to_string(),
            product: None,
            severity,
            cvss: Some(Cvss { version: "4.0".into(), score: self.score, vector: self.vector.into() }),
            epss: None,
            kev: false,
            ppr: score::ppr(self.score, self.threat),
            description: self.description.to_string(),
            solution: self.solution.to_string(),
            evidence: evidence.into(),
            references: Vec::new(),
            published: None,
            confidence: super::Confidence::Confirmed,
            reviewed: false,
            comment: String::new(),
        }
    }
}

/// Telnet: remote login without encryption.
pub static TELNET: Check = Check {
    id: "PIS-0001",
    title: "Telnet service enabled (cleartext remote login)",
    vector: "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    score: 6.0,
    threat: 5.0,
    description: "The device accepts Telnet connections. Telnet sends user names, passwords and everything typed \
                  without encryption, so anyone on the same network can read them. Telnet is also a favourite \
                  target of IoT botnets such as Mirai, which try default passwords.",
    solution: "Disable Telnet and use SSH instead. If the device cannot run SSH, block port 23 on the network and \
               change any default password.",
};

/// FTP server allows anonymous login.
pub static FTP_ANONYMOUS: Check = Check {
    id: "PIS-0002",
    title: "Anonymous FTP login allowed",
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    score: 6.9,
    threat: 6.0,
    description: "The FTP server lets anyone log in as 'anonymous' without a password. Files it shares can be \
                  read (and possibly uploaded) by any device on the network.",
    solution: "Disable anonymous access in the FTP server settings (vsftpd: anonymous_enable=NO), or remove the \
               FTP service if it is not needed.",
};

/// Redis database without a password.
pub static REDIS_NOAUTH: Check = Check {
    id: "PIS-0003",
    title: "Redis database accessible without authentication",
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    score: 9.3,
    threat: 9.0,
    description: "The Redis server answers commands without a password. Anyone who can reach it can read and \
                  delete all data, and attackers commonly use open Redis servers to write SSH keys or cron jobs \
                  and take over the machine.",
    solution: "Set a password (requirepass / ACL users), bind Redis to 127.0.0.1 unless remote access is needed, \
               and enable protected-mode.",
};

/// VNC remote desktop without a password.
pub static VNC_NOAUTH: Check = Check {
    id: "PIS-0004",
    title: "VNC remote desktop without password",
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    score: 9.3,
    threat: 9.0,
    description: "The VNC server offers the 'None' security type: anyone can see and control the screen without \
                  a password.",
    solution: "Configure a VNC password (or system authentication), and allow VNC only through SSH or a VPN.",
};

/// Docker API open without TLS (full control of the host).
pub static DOCKER_API: Check = Check {
    id: "PIS-0005",
    title: "Docker Engine API exposed without authentication",
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    score: 10.0,
    threat: 9.5,
    description: "The Docker daemon's API is reachable over plain TCP without TLS client authentication. Anyone \
                  who can reach it can start containers with full access to the host, which is equivalent to \
                  root access on that machine.",
    solution: "Stop exposing the Docker socket over TCP (remove -H tcp://… / \"hosts\" in daemon.json), or protect \
               it with TLS client certificates (port 2376).",
};

/// Elasticsearch without authentication.
pub static ELASTIC_NOAUTH: Check = Check {
    id: "PIS-0006",
    title: "Elasticsearch accessible without authentication",
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
    score: 9.3,
    threat: 8.5,
    description: "The Elasticsearch HTTP API answers without credentials. All indexed data can be read, changed \
                  or deleted by anyone on the network; open Elasticsearch servers are a leading cause of data \
                  leaks.",
    solution: "Enable Elasticsearch security (xpack.security.enabled: true) with passwords and TLS, and bind it to \
               a private interface.",
};

/// memcached open to the network.
pub static MEMCACHED_NOAUTH: Check = Check {
    id: "PIS-0007",
    title: "Memcached accessible without authentication",
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    score: 6.9,
    threat: 6.0,
    description: "The memcached server answers commands without authentication. Cached data (often session data) \
                  can be read or replaced, and exposed memcached servers can be abused for traffic amplification.",
    solution: "Bind memcached to 127.0.0.1 (-l 127.0.0.1), disable UDP (-U 0) and enable SASL if remote access is \
               required.",
};

/// MQTT broker allows anonymous clients.
pub static MQTT_ANONYMOUS: Check = Check {
    id: "PIS-0008",
    title: "MQTT broker allows anonymous clients",
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    score: 6.9,
    threat: 6.0,
    description: "The MQTT broker accepted a connection without user name or password. Smart-home messages can be \
                  read, and devices may be controlled by publishing commands.",
    solution: "Disable anonymous access (Mosquitto: allow_anonymous false), add a password file and use TLS \
               (port 8883).",
};

/// Login page served over plain HTTP.
pub static HTTP_CLEARTEXT_LOGIN: Check = Check {
    id: "PIS-0009",
    title: "Login page served over unencrypted HTTP",
    vector: "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    score: 5.9,
    threat: 4.0,
    description: "This web page contains a password field but is served over plain HTTP. Passwords typed into it \
                  travel unencrypted and can be captured by anyone on the same network.",
    solution: "Enable HTTPS on the device and redirect HTTP to HTTPS. If that is not possible, only manage the \
               device from a trusted, wired network.",
};

/// Remote Desktop (RDP) reachable (informational).
pub static RDP_EXPOSED: Check = Check {
    id: "PIS-0010",
    title: "Remote Desktop (RDP) reachable",
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    score: 0.0,
    threat: 0.0,
    description: "Remote Desktop is listening on this device. RDP is a frequent target of password guessing and \
                  has had critical bugs (e.g. BlueKeep, CVE-2019-0708).",
    solution: "Allow RDP only from trusted addresses, require Network Level Authentication, keep Windows updated, \
               and never forward port 3389 from the internet.",
};

/// Windows file sharing (SMB) reachable (informational).
pub static SMB_EXPOSED: Check = Check {
    id: "PIS-0011",
    title: "Windows file sharing (SMB) reachable",
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    score: 0.0,
    threat: 0.0,
    description: "The device shares files with SMB. This is normal inside a home or office network, but SMB has a \
                  long history of critical bugs (e.g. EternalBlue) and must never be reachable from the internet.",
    solution: "Keep the device updated, disable SMBv1, and make sure port 445 is not forwarded by the router.",
};

/// Software version announced to anyone (informational).
pub static VERSION_DISCLOSED: Check = Check {
    id: "PIS-0012",
    title: "Software version detected",
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    score: 0.0,
    threat: 0.0,
    description: "The service announces its software name and version. This is how the scanner looks up known \
                  vulnerabilities, and attackers do the same.",
    solution: "Keep the software updated. Many servers can hide the version (Apache: ServerTokens Prod; nginx: \
               server_tokens off).",
};

/// FTP sends passwords unencrypted.
pub static FTP_CLEARTEXT: Check = Check {
    id: "PIS-0013",
    title: "Unencrypted FTP service",
    vector: "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    score: 2.1,
    threat: 2.0,
    description: "FTP sends user names, passwords and files without encryption.",
    solution: "Use SFTP (over SSH) or FTPS instead, or disable the FTP service.",
};

/// Database port reachable from the network (informational).
pub static DATABASE_EXPOSED: Check = Check {
    id: "PIS-0014",
    title: "Database server reachable from the network",
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    score: 0.0,
    threat: 0.0,
    description: "A database server (MySQL/MariaDB) accepts connections from other machines. Databases usually \
                  only need to be reachable from the application that uses them.",
    solution: "Bind the database to 127.0.0.1 or a private interface, and allow remote users only from the hosts \
               that need them.",
};

// ---- Checks interpreted from Nmap's safe NSE scripts (Nmap engine only) ----

/// From Nmap's smb2-security-mode / smb-security-mode scripts.
pub static SMB_SIGNING: Check = Check {
    id: "PIS-0015",
    title: "SMB signing not required",
    vector: "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N",
    score: 6.0,
    threat: 5.0,
    description: "The file-sharing (SMB) server accepts connections without message signing. An attacker on the \
                  network can intercept and relay SMB logins (NTLM relay) to read or change files as the victim.",
    solution: "Require SMB signing: in Windows Group Policy enable 'Microsoft network server: Digitally sign \
               communications (always)'; in Samba set 'server signing = mandatory'.",
};

/// From Nmap's sslv2 script.
pub static SSLV2: Check = Check {
    id: "PIS-0016",
    title: "Obsolete SSL 2.0 protocol supported",
    vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    score: 6.3,
    threat: 4.0,
    description: "The service still accepts SSL 2.0, a protocol from 1995 with known cryptographic flaws (for \
                  example the DROWN attack). Encrypted traffic may be decrypted by an attacker.",
    solution: "Disable SSLv2 (and SSLv3) in the service's TLS settings and allow only TLS 1.2 and 1.3. On \
               embedded devices, install the latest firmware.",
};

/// From Nmap's ssl-cert script (certificate end date in the past).
pub static CERT_EXPIRED: Check = Check {
    id: "PIS-0017",
    title: "TLS certificate expired",
    vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    score: 2.3,
    threat: 2.0,
    description: "The certificate this service presents has expired. Browsers show a warning, and users who get \
                  used to clicking through such warnings cannot notice a real man-in-the-middle attack.",
    solution: "Renew the certificate (or let the device create a new one) and install it on the service.",
};

/// From Nmap's http-methods script.
pub static HTTP_RISKY_METHODS: Check = Check {
    id: "PIS-0018",
    title: "Web server allows risky HTTP methods",
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    score: 5.3,
    threat: 3.0,
    description: "The web server announces methods such as PUT, DELETE or TRACE. If they are really enabled, files \
                  could be uploaded or deleted, and TRACE can help steal cookies (cross-site tracing).",
    solution: "Allow only the methods the site needs (usually GET, HEAD, POST) in the web server configuration.",
};

/// From Nmap's x11-access script.
pub static X11_OPEN: Check = Check {
    id: "PIS-0019",
    title: "X11 display server accepts connections from anyone",
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    score: 9.3,
    threat: 7.0,
    description: "The graphical display (X11) on this computer lets any device connect. An attacker can capture \
                  the screen and every key typed, and inject keystrokes.",
    solution: "Turn off TCP connections for the X server (the default on modern systems, '-nolisten tcp') and \
               remove any 'xhost +' setting.",
};

/// Every check (used by the tests to verify ids, vectors and scores).
#[cfg(test)]
pub fn all() -> [&'static Check; 19] {
    [
        &TELNET,
        &FTP_ANONYMOUS,
        &REDIS_NOAUTH,
        &VNC_NOAUTH,
        &DOCKER_API,
        &ELASTIC_NOAUTH,
        &MEMCACHED_NOAUTH,
        &MQTT_ANONYMOUS,
        &HTTP_CLEARTEXT_LOGIN,
        &RDP_EXPOSED,
        &SMB_EXPOSED,
        &VERSION_DISCLOSED,
        &FTP_CLEARTEXT,
        &DATABASE_EXPOSED,
        &SMB_SIGNING,
        &SSLV2,
        &CERT_EXPIRED,
        &HTTP_RISKY_METHODS,
        &X11_OPEN,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_are_consistent() {
        let mut ids = std::collections::HashSet::new();
        for c in all() {
            assert!(ids.insert(c.id), "duplicate id {}", c.id);
            assert!(c.vector.starts_with("CVSS:4.0/AV:"));
            assert_eq!(c.vector.split('/').count(), 12, "{} needs all 11 base metrics", c.id);
            assert!((0.0..=10.0).contains(&c.score));
        }
        let f = REDIS_NOAUTH.finding(Ipv4Addr::LOCALHOST, 6379, "Redis", "PONG");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.ppr > 9.0);
    }
}
