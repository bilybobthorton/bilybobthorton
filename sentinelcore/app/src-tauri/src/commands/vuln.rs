use crate::commands::auth::get_token;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tauri::Emitter;

const API_BASE: &str = "https://api.redgaurd.com";
const CHUNK_SIZE: usize = 20; // NVD scan limit per request

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Clone)]
pub struct SoftwareItem {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CveItem {
    pub cve_id: String,
    pub description: String,
    pub severity: String,
    pub cvss_score: f64,
    pub published: String,
    pub references: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VulnResult {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub cves: Vec<CveItem>,
    pub highest_severity: String,
    pub cve_count: i32,
}

// ── Registry reading (Windows-only) ──────────────────────────────────────────

#[cfg(target_os = "windows")]
fn read_installed_software() -> Vec<SoftwareItem> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let uninstall_paths = [
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
    ];

    let mut items: Vec<SoftwareItem> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Software we skip — system components unlikely to have actionable CVEs in NVD
    let skip_prefixes = [
        "Microsoft Visual C++",
        "Microsoft Visual Studio",
        "Windows SDK",
        "Update for",
        "Security Update",
        "Hotfix",
        "KB",
    ];

    for (hive, path) in &uninstall_paths {
        let Ok(hklm) = RegKey::predef(*hive).open_subkey_with_flags(path, KEY_READ) else {
            continue;
        };
        for subkey_name in hklm.enum_keys().flatten() {
            let Ok(subkey) = hklm.open_subkey_with_flags(&subkey_name, KEY_READ) else {
                continue;
            };
            let name: String = subkey.get_value("DisplayName").unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            // Skip system noise
            if skip_prefixes.iter().any(|p| name.starts_with(p)) {
                continue;
            }
            // Deduplicate by name
            if seen.contains(&name) {
                continue;
            }
            seen.insert(name.clone());

            let version: Option<String> = subkey.get_value("DisplayVersion").ok();
            let publisher: Option<String> = subkey.get_value("Publisher").ok();

            items.push(SoftwareItem {
                name,
                version,
                publisher,
            });
        }
    }

    // Sort by name
    items.sort_by(|a, b| a.name.cmp(&b.name));
    items
}

#[cfg(not(target_os = "windows"))]
fn read_installed_software() -> Vec<SoftwareItem> {
    // On non-Windows, return common packages as a stub
    vec![
        SoftwareItem { name: "openssl".into(), version: Some("1.1.1".into()), publisher: None },
        SoftwareItem { name: "curl".into(), version: None, publisher: None },
    ]
}

// ── API call ──────────────────────────────────────────────────────────────────

fn scan_chunk(items: &[SoftwareItem], token: &str) -> Result<Vec<VulnResult>, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120)) // NVD can be slow
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let resp = client
        .post(format!("{API_BASE}/api/v1/vuln/scan"))
        .bearer_auth(token)
        .json(items)
        .send()
        .map_err(|e| format!("Request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().unwrap_or_default();
        return Err(format!("API error {status}: {body}"));
    }

    resp.json::<Vec<VulnResult>>().map_err(|e| format!("Parse error: {e}"))
}

// ── Commands ──────────────────────────────────────────────────────────────────

/// Returns all installed software items (for display before scanning).
#[tauri::command]
pub fn get_installed_software() -> Vec<SoftwareItem> {
    read_installed_software()
}

/// Scans installed software against NVD CVE database.
/// Sends software in chunks of 20 (API limit) and merges results.
#[tauri::command]
pub fn scan_vulnerabilities(window: tauri::Window) -> Result<Vec<VulnResult>, String> {
    let token = get_token()?;
    let software = read_installed_software();
    let total = software.len();

    let _ = window.emit(
        "vuln-progress",
        serde_json::json!({ "checked": 0, "total": total, "done": false }),
    );

    let mut all_results: Vec<VulnResult> = Vec::new();
    let chunks: Vec<&[SoftwareItem]> = software.chunks(CHUNK_SIZE).collect();

    for (i, chunk) in chunks.iter().enumerate() {
        match scan_chunk(chunk, &token) {
            Ok(mut results) => all_results.append(&mut results),
            Err(e) => {
                // Log error but keep going — don't fail the whole scan for one chunk
                eprintln!("Chunk {} error: {}", i, e);
            }
        }

        let checked = ((i + 1) * CHUNK_SIZE).min(total);
        let _ = window.emit(
            "vuln-progress",
            serde_json::json!({ "checked": checked, "total": total, "done": false }),
        );
    }

    // Sort: critical first
    let order = |s: &str| match s {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "LOW" => 3,
        _ => 4,
    };
    all_results.sort_by_key(|r| order(&r.highest_severity));

    let _ = window.emit(
        "vuln-progress",
        serde_json::json!({ "checked": total, "total": total, "done": true }),
    );

    Ok(all_results)
}
