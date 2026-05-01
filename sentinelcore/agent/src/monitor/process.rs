use crate::alert::{Alert, AlertKind, ProcessContext, Severity};
use crate::config::AgentConfig;
use crate::monitor::lolbas::check_process;
use crossbeam_channel::Sender;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{ProcessRefreshKind, RefreshKind, System};
use tracing::{debug, info};

/// Parent-child process combinations that are always suspicious
const SUSPICIOUS_CHAINS: &[(&str, &str)] = &[
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "powershell.exe"),
    ("winword.exe", "wscript.exe"),
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    ("explorer.exe", "powershell.exe"),
    ("svchost.exe", "cmd.exe"),
    ("svchost.exe", "powershell.exe"),
    ("lsass.exe", "cmd.exe"),
    ("chrome.exe", "cmd.exe"),
    ("firefox.exe", "cmd.exe"),
    ("iexplore.exe", "powershell.exe"),
];

pub async fn start_monitor(
    config: Arc<AgentConfig>,
    alert_tx: Sender<Alert>,
) -> anyhow::Result<()> {
    info!("Starting process monitor");
    let seen_pids: Arc<DashMap<u32, String>> = Arc::new(DashMap::new());

    loop {
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_all();

        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let name = process.name().to_string();

            // Only process newly spawned processes
            if seen_pids.contains_key(&pid_u32) {
                continue;
            }
            seen_pids.insert(pid_u32, name.clone());

            let cmdline = process
                .cmd()
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(" ");

            let exe_path = process.exe().map(|p| p.to_string_lossy().to_string());

            let parent_pid = process.parent().map(|p| p.as_u32());
            let parent_name = parent_pid.and_then(|ppid| {
                sys.process(sysinfo::Pid::from_u32(ppid))
                    .map(|p| p.name().to_string())
            });

            let ctx = ProcessContext {
                pid: pid_u32,
                name: name.clone(),
                parent_pid,
                parent_name: parent_name.clone(),
                cmdline: Some(cmdline.clone()),
                exe_path,
            };

            // Check LOLBAS abuse
            if let Some((entry, matched_args)) = check_process(&name, &cmdline) {
                let alert = Alert::new(
                    AlertKind::LolbasAbuse,
                    Severity::High,
                    format!("LOLBAS abuse detected: {}", name),
                    format!(
                        "{} executed with suspicious arguments [{}]. MITRE: {}",
                        entry.name,
                        matched_args.join(", "),
                        entry.mitre
                    ),
                )
                .with_process(ctx.clone())
                .with_mitre(entry.mitre);
                let _ = alert_tx.send(alert);
            }

            // Check suspicious parent-child chains
            if let Some(ref parent) = parent_name {
                let parent_lower = parent.to_lowercase();
                let child_lower = name.to_lowercase();

                for (sus_parent, sus_child) in SUSPICIOUS_CHAINS {
                    if parent_lower == *sus_parent && child_lower == *sus_child {
                        let alert = Alert::new(
                            AlertKind::SuspiciousProcessChain,
                            Severity::High,
                            format!("Suspicious process chain: {} → {}", parent, name),
                            format!(
                                "{} spawned {} — common malware / macro execution pattern",
                                parent, name
                            ),
                        )
                        .with_process(ctx.clone())
                        .with_mitre("T1059");
                        let _ = alert_tx.send(alert);
                    }
                }
            }

            debug!("New process: [{}] {} | cmd: {}", pid_u32, name, cmdline);
        }

        // Clean up dead processes
        seen_pids.retain(|pid, _| sys.process(sysinfo::Pid::from_u32(*pid)).is_some());

        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
