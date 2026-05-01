/// File Integrity Monitor — hashes critical system paths at startup,
/// then alerts on any modifications.
use crate::alert::{Alert, AlertKind, FileHashes as AlertHashes, Severity};
use crate::scanner::hash::compute_hashes;
use crossbeam_channel::Sender;
use dashmap::DashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Critical paths to monitor for integrity
fn critical_paths() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    return vec![
        PathBuf::from("C:\\Windows\\System32\\ntoskrnl.exe"),
        PathBuf::from("C:\\Windows\\System32\\lsass.exe"),
        PathBuf::from("C:\\Windows\\System32\\winlogon.exe"),
        PathBuf::from("C:\\Windows\\System32\\csrss.exe"),
        PathBuf::from("C:\\Windows\\System32\\svchost.exe"),
        PathBuf::from("C:\\Windows\\System32\\services.exe"),
        PathBuf::from("C:\\Windows\\System32\\smss.exe"),
        PathBuf::from("C:\\Windows\\System32\\wininit.exe"),
        PathBuf::from("C:\\Windows\\System32\\userinit.exe"),
        PathBuf::from("C:\\Windows\\System32\\taskhost.exe"),
        PathBuf::from("C:\\Windows\\System32\\explorer.exe"),
        PathBuf::from("C:\\Windows\\System32\\cmd.exe"),
        PathBuf::from("C:\\Windows\\System32\\powershell.exe"),
        PathBuf::from("C:\\Windows\\System32\\reg.exe"),
        PathBuf::from("C:\\Windows\\System32\\net.exe"),
        PathBuf::from("C:\\Windows\\SysWOW64\\cmd.exe"),
        PathBuf::from("C:\\Windows\\SysWOW64\\powershell.exe"),
    ];

    #[cfg(target_os = "macos")]
    return vec![
        PathBuf::from("/bin/sh"),
        PathBuf::from("/bin/bash"),
        PathBuf::from("/bin/zsh"),
        PathBuf::from("/usr/bin/python3"),
        PathBuf::from("/usr/bin/curl"),
        PathBuf::from("/usr/bin/ssh"),
        PathBuf::from("/usr/bin/sudo"),
        PathBuf::from("/sbin/launchd"),
        PathBuf::from("/usr/libexec/xpcproxy"),
        PathBuf::from("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"),
    ];

    #[cfg(target_os = "linux")]
    return vec![
        PathBuf::from("/bin/sh"),
        PathBuf::from("/bin/bash"),
        PathBuf::from("/usr/bin/sudo"),
        PathBuf::from("/usr/bin/ssh"),
        PathBuf::from("/usr/bin/curl"),
        PathBuf::from("/usr/bin/wget"),
        PathBuf::from("/sbin/init"),
        PathBuf::from("/lib/systemd/systemd"),
        PathBuf::from("/etc/passwd"),
        PathBuf::from("/etc/shadow"),
        PathBuf::from("/etc/sudoers"),
        PathBuf::from("/etc/crontab"),
        PathBuf::from("/etc/hosts"),
    ];

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    vec![]
}

pub async fn start_monitor(alert_tx: Sender<Alert>) -> anyhow::Result<()> {
    info!("Starting file integrity monitor");

    let baseline: Arc<DashMap<PathBuf, String>> = Arc::new(DashMap::new());
    let paths = critical_paths();

    // Build baseline
    let mut baselined = 0;
    for path in &paths {
        if path.exists() {
            match compute_hashes(path) {
                Ok(h) => {
                    baseline.insert(path.clone(), h.sha256);
                    baselined += 1;
                }
                Err(e) => warn!("FIM: cannot hash {}: {}", path.display(), e),
            }
        }
    }
    info!("FIM baseline complete: {} files", baselined);

    // Monitor loop
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;

        for path in &paths {
            if !path.exists() {
                if baseline.contains_key(path) {
                    let alert = Alert::new(
                        AlertKind::CriticalFileDeleted,
                        Severity::Critical,
                        format!(
                            "Critical system file deleted: {}",
                            path.file_name().unwrap_or_default().to_string_lossy()
                        ),
                        format!("System file was deleted: {}", path.display()),
                    )
                    .with_path(path.to_string_lossy());
                    let _ = alert_tx.send(alert);
                }
                continue;
            }

            match compute_hashes(path) {
                Ok(h) => {
                    if let Some(baseline_hash) = baseline.get(path) {
                        if *baseline_hash != h.sha256 {
                            let alert = Alert::new(
                                AlertKind::CriticalFileModified,
                                Severity::Critical,
                                format!(
                                    "Critical system file modified: {}",
                                    path.file_name().unwrap_or_default().to_string_lossy()
                                ),
                                format!(
                                    "Hash changed for {}\nBaseline: {}\nCurrent:  {}",
                                    path.display(),
                                    *baseline_hash,
                                    h.sha256
                                ),
                            )
                            .with_path(path.to_string_lossy())
                            .with_hashes(AlertHashes {
                                md5: h.md5,
                                sha256: h.sha256.clone(),
                            })
                            .with_mitre("T1070");
                            let _ = alert_tx.send(alert);
                            // Update baseline so we don't spam
                            drop(baseline_hash);
                            baseline.insert(path.clone(), h.sha256);
                        }
                    } else {
                        // New file appeared
                        baseline.insert(path.clone(), h.sha256);
                    }
                }
                Err(e) => warn!("FIM hash error for {}: {}", path.display(), e),
            }
        }
    }
}
