use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    // File events
    MaliciousFileDetected,
    SuspiciousFileCreated,
    SystemFileModified,
    HighEntropyFile,
    // Process events
    LolbasAbuse,
    SuspiciousProcessChain,
    SuspiciousChildProcess,
    // FIM
    CriticalFileModified,
    CriticalFileDeleted,
    // Threat intel
    KnownMaliciousHash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub kind: AlertKind,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub path: Option<String>,
    pub process: Option<ProcessContext>,
    pub hashes: Option<FileHashes>,
    pub timestamp: DateTime<Utc>,
    pub hostname: String,
    pub mitre_technique: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessContext {
    pub pid: u32,
    pub name: String,
    pub parent_pid: Option<u32>,
    pub parent_name: Option<String>,
    pub cmdline: Option<String>,
    pub exe_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHashes {
    pub md5: String,
    pub sha256: String,
}

impl Alert {
    pub fn new(
        kind: AlertKind,
        severity: Severity,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            kind,
            severity,
            title: title.into(),
            description: description.into(),
            path: None,
            process: None,
            hashes: None,
            timestamp: Utc::now(),
            hostname: hostname(),
            mitre_technique: None,
        }
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn with_process(mut self, ctx: ProcessContext) -> Self {
        self.process = Some(ctx);
        self
    }

    pub fn with_hashes(mut self, hashes: FileHashes) -> Self {
        self.hashes = Some(hashes);
        self
    }

    pub fn with_mitre(mut self, technique: impl Into<String>) -> Self {
        self.mitre_technique = Some(technique.into());
        self
    }
}

fn hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string())
}
