use crate::alert::{Alert, AlertKind, FileHashes as AlertHashes, Severity};
use crate::config::AgentConfig;
use crate::scanner::hash::compute_hashes;
use anyhow::Result;
use crossbeam_channel::Sender;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// File extensions that are high-risk and always scanned
const HIGH_RISK_EXTENSIONS: &[&str] = &[
    "exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "jse", "vbe", "hta", "scr", "pif", "com",
    "cpl", "msi", "msp", "jar", "py", "sh", "elf", "so", "dylib", "dmg", "pkg", "deb", "rpm",
];

/// Known-malicious file name patterns
const SUSPICIOUS_FILENAMES: &[&str] = &[
    "mimikatz",
    "meterpreter",
    "cobalt",
    "beacon",
    "payload",
    "empire",
    "metasploit",
    "exploit",
    "shellcode",
    "keylogger",
    "ransomware",
    "cryptominer",
    "xmrig",
    "lazagne",
];

pub async fn start_monitor(config: Arc<AgentConfig>, alert_tx: Sender<Alert>) -> Result<()> {
    info!("Starting filesystem monitor");

    let (tx, rx) = crossbeam_channel::unbounded();
    let mut watcher = RecommendedWatcher::new(
        tx,
        Config::default().with_poll_interval(Duration::from_secs(1)),
    )?;

    for dir in &config.watch_dirs {
        if dir.exists() {
            match watcher.watch(dir, RecursiveMode::Recursive) {
                Ok(_) => info!("Watching: {}", dir.display()),
                Err(e) => warn!("Cannot watch {}: {}", dir.display(), e),
            }
        }
    }

    for event in rx {
        match event {
            Ok(event) => {
                if let Err(e) = handle_event(&event, &config, &alert_tx).await {
                    debug!("Error handling fs event: {}", e);
                }
            }
            Err(e) => warn!("Filesystem watch error: {}", e),
        }
    }

    Ok(())
}

async fn handle_event(event: &Event, config: &AgentConfig, alert_tx: &Sender<Alert>) -> Result<()> {
    match &event.kind {
        EventKind::Create(_) | EventKind::Modify(_) => {
            for path in &event.paths {
                if should_skip(path, config) {
                    continue;
                }
                if let Err(e) = scan_file(path, alert_tx, config).await {
                    debug!("Scan error for {}: {}", path.display(), e);
                }
            }
        }
        _ => {}
    }
    Ok(())
}

async fn scan_file(path: &Path, alert_tx: &Sender<Alert>, config: &AgentConfig) -> Result<()> {
    if !path.is_file() {
        return Ok(());
    }

    let metadata = path.metadata()?;
    let size_mb = metadata.len() / (1024 * 1024);
    if size_mb > config.max_scan_size_mb {
        return Ok(());
    }

    // Check suspicious filenames
    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
        let stem_lower = stem.to_lowercase();
        for pattern in SUSPICIOUS_FILENAMES {
            if stem_lower.contains(pattern) {
                let alert = Alert::new(
                    AlertKind::SuspiciousFileCreated,
                    Severity::High,
                    format!("Suspicious filename: {}", stem),
                    format!(
                        "File '{}' matches known malware naming pattern '{}'",
                        path.display(),
                        pattern
                    ),
                )
                .with_path(path.to_string_lossy());
                let _ = alert_tx.send(alert);
            }
        }
    }

    // Only deep-scan high-risk extensions
    if !is_high_risk(path) {
        return Ok(());
    }

    debug!("Scanning: {}", path.display());

    let hashes = match compute_hashes(path) {
        Ok(h) => h,
        Err(_) => return Ok(()),
    };

    // TODO: check hashes against local DB and VirusTotal
    // For now, flag executables dropped in temp directories
    let path_str = path.to_string_lossy().to_lowercase();
    let is_suspicious_location = [
        "/tmp",
        "/var/tmp",
        "\\temp\\",
        "\\tmp\\",
        "appdata\\local\\temp",
    ]
    .iter()
    .any(|loc| path_str.contains(loc));

    if is_suspicious_location {
        let alert = Alert::new(
            AlertKind::SuspiciousFileCreated,
            Severity::Medium,
            format!(
                "Executable in temp directory: {}",
                path.file_name().unwrap_or_default().to_string_lossy()
            ),
            format!(
                "Executable file created in suspicious location: {}",
                path.display()
            ),
        )
        .with_path(path.to_string_lossy())
        .with_hashes(AlertHashes {
            md5: hashes.md5,
            sha256: hashes.sha256,
        });
        let _ = alert_tx.send(alert);
    }

    Ok(())
}

fn is_high_risk(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|ext| HIGH_RISK_EXTENSIONS.contains(&ext.to_lowercase().as_str()))
        .unwrap_or(false)
}

fn should_skip(path: &Path, config: &AgentConfig) -> bool {
    let path_str = path.to_string_lossy();
    config
        .exclude_dirs
        .iter()
        .any(|excl| path_str.starts_with(&excl.to_string_lossy().as_ref()))
}
