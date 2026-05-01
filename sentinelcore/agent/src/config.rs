use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// SentinelCore API base URL
    pub api_url: String,
    /// API key for authentication
    pub api_key: Option<String>,
    /// Directories to monitor (defaults to system-wide)
    pub watch_dirs: Vec<PathBuf>,
    /// Directories to never scan (performance + false positives)
    pub exclude_dirs: Vec<PathBuf>,
    /// File extensions to scan (empty = all)
    pub scan_extensions: Vec<String>,
    /// Enable real-time file monitoring
    pub monitor_filesystem: bool,
    /// Enable process monitoring
    pub monitor_processes: bool,
    /// Enable file integrity monitoring
    pub monitor_fim: bool,
    /// Max file size to scan in MB
    pub max_scan_size_mb: u64,
    /// Report alerts to API (false = local log only)
    pub report_to_api: bool,
    /// Automatically quarantine malicious files
    pub auto_quarantine: bool,
    /// Quarantine directory
    pub quarantine_dir: PathBuf,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            api_url: "http://localhost:8000".to_string(),
            api_key: None,
            watch_dirs: default_watch_dirs(),
            exclude_dirs: default_exclude_dirs(),
            scan_extensions: vec![],
            monitor_filesystem: true,
            monitor_processes: true,
            monitor_fim: true,
            max_scan_size_mb: 100,
            report_to_api: true,
            auto_quarantine: false,
            quarantine_dir: default_quarantine_dir(),
        }
    }
}

#[allow(dead_code)]
impl AgentConfig {
    pub fn load(path: &PathBuf) -> Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            Ok(serde_json::from_str(&content)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

fn default_watch_dirs() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    return vec![
        PathBuf::from("C:\\Users"),
        PathBuf::from("C:\\Windows\\Temp"),
        PathBuf::from("C:\\Temp"),
        PathBuf::from("C:\\ProgramData"),
    ];

    #[cfg(target_os = "macos")]
    return vec![
        PathBuf::from("/Users"),
        PathBuf::from("/tmp"),
        PathBuf::from("/private/tmp"),
        PathBuf::from("/Applications"),
    ];

    #[cfg(target_os = "linux")]
    return vec![
        PathBuf::from("/home"),
        PathBuf::from("/tmp"),
        PathBuf::from("/var/tmp"),
        PathBuf::from("/usr/local/bin"),
    ];

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    vec![PathBuf::from("/")]
}

fn default_exclude_dirs() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    return vec![
        PathBuf::from("C:\\Windows\\WinSxS"),
        PathBuf::from("C:\\Windows\\SoftwareDistribution"),
    ];

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    return vec![
        PathBuf::from("/proc"),
        PathBuf::from("/sys"),
        PathBuf::from("/dev"),
    ];

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    vec![]
}

fn default_quarantine_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("/var/lib"))
        .join("sentinelcore")
        .join("quarantine")
}
