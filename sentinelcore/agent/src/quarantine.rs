/// Quarantine engine — isolates malicious files safely.
/// Files are encrypted and moved to a locked quarantine vault.
/// Metadata is preserved so files can be restored if false positive.
use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::info;

#[derive(Debug, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub original_path: String,
    pub quarantine_path: String,
    pub sha256: String,
    pub md5: String,
    pub file_size: u64,
    pub quarantined_at: String,
    pub reason: String,
    pub alert_id: String,
}

pub struct QuarantineVault {
    vault_dir: PathBuf,
}

impl QuarantineVault {
    pub fn new(vault_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&vault_dir)
            .with_context(|| format!("Cannot create quarantine dir: {}", vault_dir.display()))?;

        // Restrict permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&vault_dir, std::fs::Permissions::from_mode(0o700))?;
        }

        Ok(Self { vault_dir })
    }

    /// Move a file into quarantine. Returns the quarantine record.
    #[allow(dead_code)]
    pub fn quarantine(
        &self,
        path: &Path,
        sha256: &str,
        md5: &str,
        reason: &str,
        alert_id: &str,
    ) -> Result<QuarantineRecord> {
        let file_size = path.metadata()?.len();
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let quarantine_name = format!("{}_{}_{}", timestamp, &sha256[..8], filename);
        let dest = self.vault_dir.join(&quarantine_name);

        // XOR-obfuscate the file bytes so it can't be accidentally executed
        let data = std::fs::read(path)?;
        let obfuscated: Vec<u8> = data.iter().map(|&b| b ^ 0xAA).collect();
        std::fs::write(&dest, &obfuscated)?;

        // Remove original
        std::fs::remove_file(path)
            .with_context(|| format!("Cannot remove original: {}", path.display()))?;

        let record = QuarantineRecord {
            original_path: path.to_string_lossy().to_string(),
            quarantine_path: dest.to_string_lossy().to_string(),
            sha256: sha256.to_string(),
            md5: md5.to_string(),
            file_size,
            quarantined_at: Utc::now().to_rfc3339(),
            reason: reason.to_string(),
            alert_id: alert_id.to_string(),
        };

        // Save metadata record
        let record_path = dest.with_extension("json");
        std::fs::write(&record_path, serde_json::to_string_pretty(&record)?)?;

        info!("Quarantined: {} → {}", path.display(), dest.display());

        Ok(record)
    }

    /// Restore a quarantined file to its original location.
    pub fn restore(&self, record: &QuarantineRecord) -> Result<()> {
        let quarantine_path = PathBuf::from(&record.quarantine_path);
        let original_path = PathBuf::from(&record.original_path);

        if !quarantine_path.exists() {
            anyhow::bail!("Quarantine file not found: {}", quarantine_path.display());
        }

        if let Some(parent) = original_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Reverse XOR obfuscation
        let data = std::fs::read(&quarantine_path)?;
        let restored: Vec<u8> = data.iter().map(|&b| b ^ 0xAA).collect();
        std::fs::write(&original_path, &restored)?;

        // Clean up quarantine files
        let _ = std::fs::remove_file(&quarantine_path);
        let record_path = quarantine_path.with_extension("json");
        let _ = std::fs::remove_file(&record_path);

        info!(
            "Restored: {} → {}",
            quarantine_path.display(),
            original_path.display()
        );
        Ok(())
    }

    /// List all quarantined files.
    pub fn list(&self) -> Vec<QuarantineRecord> {
        let Ok(entries) = std::fs::read_dir(&self.vault_dir) else {
            return vec![];
        };

        entries
            .flatten()
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
            .filter_map(|e| {
                std::fs::read_to_string(e.path())
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok())
            })
            .collect()
    }
}
