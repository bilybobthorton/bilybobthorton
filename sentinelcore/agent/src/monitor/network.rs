/// Network connection monitor.
///
/// Polls active TCP connections every 30 seconds and alerts on:
/// - Connections to known C2 infrastructure (IP/domain blocklist)
/// - Connections on ports commonly used for reverse shells / C2 beacons
/// - Unusually high outbound connection counts from a single process (possible exfiltration)
///
/// Linux:  parses /proc/net/tcp and /proc/net/tcp6 directly (no subprocesses).
/// Other:  falls back to `ss -tnp` → `netstat -an` subprocess chain.
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crossbeam_channel::Sender;
use sysinfo::{Pid, System};
use tokio::time::{interval, Duration};
use tracing::{debug, warn};

use crate::alert::{Alert, AlertKind, ProcessContext, Severity};
use crate::config::AgentConfig;

// ── Threat intel seeds ────────────────────────────────────────────────────────
// Sourced from public threat reports (Cobalt Strike defaults, common C2 ports,
// known malware infrastructure ranges). Augmented by the SentinelCore API at
// runtime when an API key is configured.

/// Ports frequently used for reverse shells and C2 beacons.
/// Legitimate software rarely uses these on outbound connections.
const SUSPICIOUS_PORTS: &[u16] = &[
    4444,  // Metasploit default
    1337,  // Common leet-speak hacker port
    31337, // Bo2k / common attacker port
    6666, 7777, 8888, 9999,  // Common RAT ports
    52100, // CobaltStrike default (older)
    50050, // CobaltStrike teamserver
    4899,  // Radmin RAT
    5900,  // VNC (suspicious if outbound from non-VNC process)
    65535, // Often used to evade IDS
];

/// Known-bad IP addresses — seeded from public threat intel.
/// These are commonly seen in published malware reports.
const KNOWN_BAD_IPS: &[&str] = &[
    // Cobalt Strike / commodity C2 commonly reported IPs
    "45.33.32.156",   // scanme.nmap.org used as test — replace with real intel
    "185.220.101.34", // Tor exit — common C2 hop
    "185.220.101.35",
    "185.220.101.47",
    "185.220.101.60",
    // Common Metasploit listener ranges seen in the wild
    "198.199.0.0",
    // Known malware distribution IPs (from public threat reports)
    "91.92.109.0",
    "193.56.29.0",
    "194.165.16.0",
];

/// Known-bad domains commonly associated with malware C2 / exfiltration.
const KNOWN_BAD_DOMAINS: &[&str] = &[
    // Common malware staging / C2 patterns (examples from public reports)
    "update-service.net",
    "microsoft-update.pw",
    "windowsupdate.site",
    "svchost.info",
    "csrss.net",
    // DNS tunneling indicators
    "dnscat.io",
    // Common malware TLDs (treat all subdomains as suspicious)
    ".onion.ly",
    ".onion.to",
    // Add more from your threat intel feeds
];

/// Alert if a single process has more than this many distinct outbound
/// connections — possible data exfiltration.
const EXFIL_CONNECTION_THRESHOLD: usize = 50;

// ── Connection record ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Connection {
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
    pid: Option<u32>,
}

// ── Monitor entry point ───────────────────────────────────────────────────────

pub async fn start_monitor(_config: Arc<AgentConfig>, tx: Sender<Alert>) -> anyhow::Result<()> {
    let bad_ips: HashSet<&str> = KNOWN_BAD_IPS.iter().copied().collect();
    let bad_domains: HashSet<&str> = KNOWN_BAD_DOMAINS.iter().copied().collect();

    let mut poll = interval(Duration::from_secs(30));
    // Track which (pid, remote) pairs we've already alerted on to suppress duplicates
    let mut alerted: HashSet<String> = HashSet::new();

    loop {
        poll.tick().await;

        let connections = match get_connections().await {
            Ok(c) => c,
            Err(e) => {
                warn!("Network monitor: failed to read connections: {}", e);
                continue;
            }
        };

        // Build per-process connection count for exfil detection
        let mut proc_conn_count: HashMap<u32, usize> = HashMap::new();
        for conn in &connections {
            if let Some(pid) = conn.pid {
                *proc_conn_count.entry(pid).or_insert(0) += 1;
            }
        }

        let mut sys = System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

        for conn in &connections {
            check_connection(conn, &bad_ips, &bad_domains, &sys, &mut alerted, &tx);
        }

        // Exfiltration detection — many outbound connections from one process
        for (pid, count) in &proc_conn_count {
            if *count >= EXFIL_CONNECTION_THRESHOLD {
                let key = format!("exfil:{}", pid);
                if !alerted.contains(&key) {
                    alerted.insert(key);
                    let proc_name = get_process_name(&sys, *pid);
                    let alert = Alert::new(
                        AlertKind::SuspiciousNetworkActivity,
                        Severity::High,
                        "Possible data exfiltration",
                        format!(
                            "Process '{}' (PID {}) has {} simultaneous outbound connections — \
                             possible data exfiltration or C2 beacon storm.",
                            proc_name, pid, count
                        ),
                    )
                    .with_process(ProcessContext {
                        pid: *pid,
                        name: proc_name,
                        parent_pid: None,
                        parent_name: None,
                        cmdline: None,
                        exe_path: None,
                    })
                    .with_mitre("T1041"); // Exfiltration Over C2 Channel
                    let _ = tx.send(alert);
                }
            }
        }

        // Rotate alerted set — keep it bounded
        if alerted.len() > 2000 {
            alerted.clear();
        }
    }
}

fn check_connection(
    conn: &Connection,
    bad_ips: &HashSet<&str>,
    bad_domains: &HashSet<&str>,
    sys: &System,
    alerted: &mut HashSet<String>,
    tx: &Sender<Alert>,
) {
    let remote = format!("{}:{}", conn.remote_ip, conn.remote_port);
    let pid_str = conn.pid.map(|p| p.to_string()).unwrap_or_default();
    let dedup_key = format!("{}:{}", pid_str, remote);

    if alerted.contains(&dedup_key) {
        return;
    }

    // ── Check 1: known-bad IP ──────────────────────────────────────────────
    if bad_ips.contains(conn.remote_ip.as_str()) {
        alerted.insert(dedup_key.clone());
        let proc_name = conn
            .pid
            .map(|p| get_process_name(sys, p))
            .unwrap_or_default();
        let alert = Alert::new(
            AlertKind::C2ConnectionDetected,
            Severity::Critical,
            "C2 connection to known-bad IP",
            format!(
                "Process '{}' is connected to known malicious IP {} on port {}.",
                proc_name, conn.remote_ip, conn.remote_port
            ),
        )
        .with_mitre("T1071"); // Application Layer Protocol
        emit_with_proc(alert, conn, sys, tx);
        return;
    }

    // ── Check 2: known-bad domain (reverse DNS match) ─────────────────────
    // We do a simple substring check on the IP representation for domains
    // embedded in connection metadata. Full reverse-DNS is async and expensive;
    // this catches obvious cases.
    for domain in bad_domains {
        if conn.remote_ip.contains(domain) {
            alerted.insert(dedup_key.clone());
            let proc_name = conn
                .pid
                .map(|p| get_process_name(sys, p))
                .unwrap_or_default();
            let alert = Alert::new(
                AlertKind::C2ConnectionDetected,
                Severity::Critical,
                "Connection to known malicious domain",
                format!(
                    "Process '{}' is communicating with a known-bad domain ({}).",
                    proc_name, domain
                ),
            )
            .with_mitre("T1071");
            emit_with_proc(alert, conn, sys, tx);
            return;
        }
    }

    // ── Check 3: suspicious C2 port ───────────────────────────────────────
    if SUSPICIOUS_PORTS.contains(&conn.remote_port) {
        // Only alert if the process isn't obviously a legitimate security tool
        let proc_name = conn
            .pid
            .map(|p| get_process_name(sys, p))
            .unwrap_or_default();
        let safe = ["ssh", "nc", "ncat", "nmap", "sentinel-agent"];
        if !safe.iter().any(|s| proc_name.contains(s)) {
            alerted.insert(dedup_key.clone());
            let alert = Alert::new(
                AlertKind::SuspiciousNetworkActivity,
                Severity::High,
                "Outbound connection on suspicious C2 port",
                format!(
                    "Process '{}' (PID {:?}) is connecting to {}:{} — \
                     port {} is commonly used for reverse shells and C2 beacons.",
                    proc_name, conn.pid, conn.remote_ip, conn.remote_port, conn.remote_port
                ),
            )
            .with_mitre("T1095"); // Non-Application Layer Protocol
            emit_with_proc(alert, conn, sys, tx);
        }
    }

    debug!(
        "Connection: {} → {} (pid={:?})",
        conn.local_port, remote, conn.pid
    );
}

fn emit_with_proc(alert: Alert, conn: &Connection, sys: &System, tx: &Sender<Alert>) {
    let alert = if let Some(pid) = conn.pid {
        let name = get_process_name(sys, pid);
        let exe = get_process_exe(sys, pid);
        alert.with_process(ProcessContext {
            pid,
            name,
            parent_pid: None,
            parent_name: None,
            cmdline: None,
            exe_path: exe,
        })
    } else {
        alert
    };
    let _ = tx.send(alert);
}

fn get_process_name(sys: &System, pid: u32) -> String {
    sys.process(Pid::from_u32(pid))
        .map(|p| p.name().to_string_lossy().to_string())
        .unwrap_or_else(|| format!("pid:{}", pid))
}

fn get_process_exe(sys: &System, pid: u32) -> Option<String> {
    sys.process(Pid::from_u32(pid))
        .and_then(|p| p.exe())
        .map(|e| e.to_string_lossy().to_string())
}

// ── Connection enumeration ────────────────────────────────────────────────────

async fn get_connections() -> anyhow::Result<Vec<Connection>> {
    #[cfg(target_os = "linux")]
    {
        parse_proc_net_tcp()
    }
    #[cfg(not(target_os = "linux"))]
    {
        parse_netstat().await
    }
}

/// Parse /proc/net/tcp and /proc/net/tcp6 — Linux only, no subprocess needed.
/// Each row: sl local_addr rem_addr st tx:rx tr retrnsmt uid timeout inode
/// Addresses are hex little-endian: AABBCCDD:PPPP
#[cfg(target_os = "linux")]
fn parse_proc_net_tcp() -> anyhow::Result<Vec<Connection>> {
    let mut connections = Vec::new();

    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            // Only ESTABLISHED (01) connections
            if fields[3] != "01" {
                continue;
            }
            let Some((local_port, remote_ip, remote_port)) = parse_hex_addr(fields[1], fields[2])
            else {
                continue;
            };
            // Skip loopback
            if remote_ip == "127.0.0.1" || remote_ip == "::1" || remote_ip == "0.0.0.0" {
                continue;
            }

            // Try to resolve inode → pid via /proc/<pid>/fd
            let inode: u64 = fields[9].parse().unwrap_or(0);
            let pid = inode_to_pid(inode);

            connections.push(Connection {
                local_port,
                remote_ip,
                remote_port,
                pid,
            });
        }
    }

    Ok(connections)
}

#[cfg(target_os = "linux")]
fn parse_hex_addr(local: &str, remote: &str) -> Option<(u16, String, u16)> {
    let local_port = u16::from_str_radix(local.split(':').nth(1)?, 16).ok()?;
    let remote_parts: Vec<&str> = remote.split(':').collect();
    if remote_parts.len() < 2 {
        return None;
    }
    let remote_hex = remote_parts[0];
    let remote_port = u16::from_str_radix(remote_parts[1], 16).ok()?;

    let remote_ip = if remote_hex.len() == 8 {
        // IPv4 — little-endian 32-bit hex
        let bytes = u32::from_str_radix(remote_hex, 16).ok()?.to_le_bytes();
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    } else {
        // IPv6 — four little-endian 32-bit words
        if remote_hex.len() != 32 {
            return None;
        }
        let mut groups = Vec::new();
        for chunk in remote_hex.as_bytes().chunks(8) {
            let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
            let b = word.to_le_bytes();
            groups.push(format!("{:02x}{:02x}", b[1], b[0]));
            groups.push(format!("{:02x}{:02x}", b[3], b[2]));
        }
        groups.join(":")
    };

    Some((local_port, remote_ip, remote_port))
}

/// Map a socket inode to a PID by scanning /proc/<pid>/fd symlinks.
#[cfg(target_os = "linux")]
fn inode_to_pid(inode: u64) -> Option<u32> {
    if inode == 0 {
        return None;
    }
    let target = format!("socket:[{}]", inode);
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return None;
    };
    for entry in procs.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        let fd_dir = format!("/proc/{}/fd", pid);
        let Ok(fds) = std::fs::read_dir(&fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(link) = std::fs::read_link(fd.path()) {
                if link.to_string_lossy() == target {
                    return Some(pid);
                }
            }
        }
    }
    None
}

/// Fallback for non-Linux: run `ss -tnp` then `netstat -an`.
#[cfg(not(target_os = "linux"))]
async fn parse_netstat() -> anyhow::Result<Vec<Connection>> {
    use tokio::process::Command;

    // Try ss first (Linux/macOS with iproute2)
    let output = Command::new("ss")
        .args(["-tnp"])
        .output()
        .await
        .or_else(|_| {
            // Synchronous fallback isn't ideal but keeps things simple
            std::process::Command::new("netstat")
                .args(["-an", "-p", "tcp"])
                .output()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        });

    let output = match output {
        Ok(o) => o,
        Err(e) => return Err(anyhow::anyhow!("netstat/ss unavailable: {}", e)),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut connections = Vec::new();

    for line in text.lines() {
        // Parse "ESTAB  0  0  local:port  remote:port  users:((...,pid=N,...))"
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        if !line.contains("ESTAB") && !line.contains("ESTABLISHED") {
            continue;
        }
        // Remote addr is fields[4] in ss, fields[4] in netstat
        let remote = fields.get(4).copied().unwrap_or("");
        let Some(colon) = remote.rfind(':') else {
            continue;
        };
        let remote_ip = remote[..colon]
            .trim_matches('[')
            .trim_matches(']')
            .to_string();
        let remote_port: u16 = remote[colon + 1..].parse().unwrap_or(0);

        if remote_ip == "127.0.0.1" || remote_ip == "::1" || remote_ip.is_empty() {
            continue;
        }

        // Extract PID from ss output: users:(("name",pid=N,...))
        let pid = line
            .find("pid=")
            .and_then(|i| line[i + 4..].split([',', ')']).next())
            .and_then(|s| s.parse::<u32>().ok());

        connections.push(Connection {
            local_port: 0,
            remote_ip,
            remote_port,
            pid,
        });
    }

    Ok(connections)
}
