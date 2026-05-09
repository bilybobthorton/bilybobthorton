use crate::commands::auth::get_token;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;
use tauri::Emitter;
use walkdir::WalkDir;

const API_BASE: &str = "https://api.redgaurd.com";

const KNOWN_BAD_HASHES: &str = include_str!("../../../../engine/signatures/malware_hashes.txt");

static SCAN_RUNNING: OnceLock<AtomicBool> = OnceLock::new();

fn scan_flag() -> &'static AtomicBool {
    SCAN_RUNNING.get_or_init(|| AtomicBool::new(false))
}

const SCAN_EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "drv", "bat", "cmd", "ps1", "vbs", "js", "msi", "scr", "cpl", "pif",
];

// Extensions that are executables and worth full-analysis upload
const PE_EXTENSIONS: &[&str] = &["exe", "dll", "sys", "drv", "scr", "cpl"];

// Suspicious import strings indicative of malware behaviour
const SUSPICIOUS_IMPORTS: &[&str] = &[
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "SetWindowsHookEx",
    "GetAsyncKeyState",
    "NtUnmapViewOfSection",
    "RtlDecompressBuffer",
    "NtWriteVirtualMemory",
    "ZwAllocateVirtualMemory",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "OutputDebugString",
];

// ── Heuristics ────────────────────────────────────────────────────────────────

fn byte_entropy(data: &[u8]) -> f64 {
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Returns a 0-10 suspicion score using only in-process analysis.
fn quick_pe_score(data: &[u8]) -> u8 {
    if data.len() < 64 || &data[0..2] != b"MZ" {
        return 0;
    }
    let mut score = 0u8;

    // High entropy → packed / encrypted payload
    let entropy = byte_entropy(data);
    if entropy > 7.2 {
        score += 4;
    } else if entropy > 6.8 {
        score += 2;
    } else if entropy > 6.4 {
        score += 1;
    }

    // Suspicious API imports (case-sensitive, they appear as ASCII strings in PE)
    let content = String::from_utf8_lossy(data);
    for imp in SUSPICIOUS_IMPORTS {
        if content.contains(imp) {
            score += 1;
        }
    }

    // PE section name anomalies — look for typical packer section names
    let packer_sections: &[&[u8]] = &[b".packed", b"UPX0", b"UPX1", b".themida", b".enigma"];
    for name in packer_sections {
        if data.windows(name.len()).any(|w| w == *name) {
            score += 3;
        }
    }

    score.min(10)
}

// ── Scan directories ──────────────────────────────────────────────────────────

/// Returns dirs to scan. `full` adds system dirs that take longer.
fn scan_dirs(full: bool) -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        let profile = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users".into());
        let mut dirs = vec![
            format!("{profile}\\Downloads"),
            format!("{profile}\\AppData\\Local\\Temp"),
            format!("{profile}\\AppData\\Roaming"),
            "C:\\ProgramData".into(),
            "C:\\Temp".into(),
            "C:\\Windows\\Temp".into(),
        ];
        if full {
            dirs.push("C:\\Program Files".into());
            dirs.push("C:\\Program Files (x86)".into());
            dirs.push("C:\\Windows\\System32".into());
            dirs.push("C:\\Windows\\SysWOW64".into());
        }
        dirs
    }
    #[cfg(not(target_os = "windows"))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home".into());
        let mut dirs = vec![
            format!("{home}/Downloads"),
            "/tmp".into(),
            "/var/tmp".into(),
            "/usr/local/bin".into(),
        ];
        if full {
            dirs.push("/usr/bin".into());
            dirs.push("/usr/lib".into());
        }
        dirs
    }
}

// ── Shared types ──────────────────────────────────────────────────────────────

#[derive(Serialize, Clone)]
pub struct ScanProgress {
    pub scanned: u64,
    pub threats: u64,
    pub current_file: String,
    pub done: bool,
    pub phase: String, // "scanning" | "uploading" | "done"
}

#[derive(Serialize, Clone)]
pub struct SystemThreat {
    pub path: String,
    pub sha256: String,
    pub source: String,          // "local-blocklist" | "heuristic" | "cloud-hash" | "cloud-full"
    pub threat_level: String,    // CLEAN / SUSPICIOUS / MALICIOUS
    pub score: f64,
    pub detail: String,          // human-readable reason
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatStats {
    pub total_alerts: i32,
    pub critical: i32,
    pub high: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Alert {
    pub id: i32,
    pub severity: String,
    pub message: String,
    pub file_path: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub threat_level: String,
    pub score: f64,
    pub status: String,
}

// ── API helpers ───────────────────────────────────────────────────────────────

fn is_known_bad(hash: &str) -> bool {
    KNOWN_BAD_HASHES
        .lines()
        .any(|line| line.trim().eq_ignore_ascii_case(hash))
}

fn make_client(timeout_secs: u64) -> Option<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .ok()
}

/// Returns threat_level string, or None on error.
fn api_hash_lookup(hash: &str, token: &str, client: &reqwest::blocking::Client) -> Option<String> {
    let resp = client
        .post(format!("{API_BASE}/api/v1/scan/hash"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "hash": hash }))
        .send()
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let val = resp.json::<serde_json::Value>().ok()?;
    Some(
        val.get("threat_level")
            .and_then(|v| v.as_str())
            .unwrap_or("CLEAN")
            .to_string(),
    )
}

/// Uploads a file for full analysis (ML + YARA + VT + OTX). Returns (threat_level, score).
fn api_full_scan(
    path: &std::path::Path,
    data: Vec<u8>,
    token: &str,
    client: &reqwest::blocking::Client,
) -> Option<(String, f64)> {
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_string();

    let part = reqwest::blocking::multipart::Part::bytes(data)
        .file_name(filename)
        .mime_str("application/octet-stream")
        .ok()?;
    let form = reqwest::blocking::multipart::Form::new().part("file", part);

    let resp = client
        .post(format!("{API_BASE}/api/v1/scan/file"))
        .bearer_auth(token)
        .multipart(form)
        .send()
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let upload: serde_json::Value = resp.json().ok()?;
    let job_id = upload
        .get("id")
        .or_else(|| upload.get("job_id"))
        .and_then(|v| v.as_str())?
        .to_string();

    // Poll up to 30×2s = 60s
    let poll_client = make_client(15)?;
    for _ in 0..30 {
        std::thread::sleep(Duration::from_secs(2));
        let pr = poll_client
            .get(format!("{API_BASE}/api/v1/scan/{job_id}"))
            .bearer_auth(token)
            .send()
            .ok()?;
        if !pr.status().is_success() {
            continue;
        }
        let result: serde_json::Value = pr.json().ok()?;
        let status = result
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("pending");
        if status == "pending" || status == "running" {
            continue;
        }
        let level = result
            .get("threat_level")
            .and_then(|v| v.as_str())
            .unwrap_or("CLEAN")
            .to_string();
        let score = result
            .get("ml_score")
            .or_else(|| result.get("score"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        return Some((level, score));
    }
    None
}

fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// ── Commands ──────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn cancel_scan() {
    scan_flag().store(false, Ordering::Relaxed);
}

/// scan_mode: "quick" (default) or "full"
#[tauri::command]
pub fn scan_system(window: tauri::Window, scan_mode: Option<String>) -> Result<Vec<SystemThreat>, String> {
    if scan_flag().swap(true, Ordering::Relaxed) {
        return Err("Scan already running".into());
    }

    let full = scan_mode.as_deref() == Some("full");
    let token = get_token().unwrap_or_default();
    let has_token = !token.is_empty();

    let client = make_client(30);
    let mut scanned: u64 = 0;
    let mut threats: Vec<SystemThreat> = Vec::new();
    let mut hash_api_calls: u32 = 0;
    let mut full_api_calls: u32 = 0;

    // Caps — full scan gets more budget
    let max_hash_calls: u32 = if full { 500 } else { 150 };
    let max_full_calls: u32 = if full { 30 } else { 15 };

    'outer: for dir in scan_dirs(full) {
        if !scan_flag().load(Ordering::Relaxed) {
            break;
        }
        // Emit directory-level progress so the user sees activity immediately
        let _ = window.emit(
            "scan-progress",
            ScanProgress {
                scanned,
                threats: threats.len() as u64,
                current_file: format!("Searching {dir}…"),
                done: false,
                phase: "scanning".into(),
            },
        );

        let walker = WalkDir::new(&dir)
            .follow_links(false)
            .same_file_system(true)
            .into_iter();

        for entry in walker.filter_map(|e| e.ok()) {
            if !scan_flag().load(Ordering::Relaxed) {
                break 'outer;
            }
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            if !SCAN_EXTENSIONS.contains(&ext.as_str()) {
                continue;
            }
            let file_size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            // Skip empty or very large files (>100 MB)
            if file_size == 0 || file_size > 100 * 1024 * 1024 {
                continue;
            }

            scanned += 1;
            let path_str = path.to_string_lossy().to_string();

            // Emit progress on every file so the counter updates in real-time
            let _ = window.emit(
                "scan-progress",
                ScanProgress {
                    scanned,
                    threats: threats.len() as u64,
                    current_file: path_str.clone(),
                    done: false,
                    phase: "scanning".into(),
                },
            );

            // Read file data (needed for hash + heuristics)
            let Ok(data) = std::fs::read(path) else {
                continue;
            };

            let hash = sha256_bytes(&data);

            // ── Layer 1: local blocklist (instant) ────────────────────────
            if is_known_bad(&hash) {
                threats.push(SystemThreat {
                    path: path_str,
                    sha256: hash,
                    source: "local-blocklist".into(),
                    threat_level: "MALICIOUS".into(),
                    score: 1.0,
                    detail: "Matched known malware hash database".into(),
                });
                continue;
            }

            // ── Layer 2: local PE heuristics ──────────────────────────────
            let is_pe = PE_EXTENSIONS.contains(&ext.as_str());
            let heuristic_score = if is_pe { quick_pe_score(&data) } else { 0 };

            // Flag purely on local heuristics (no API needed)
            if heuristic_score >= 7 {
                let detail = if byte_entropy(&data) > 7.2 {
                    "Extremely high entropy (packed/encrypted) with suspicious API imports"
                } else {
                    "Multiple suspicious API patterns detected"
                };
                threats.push(SystemThreat {
                    path: path_str.clone(),
                    sha256: hash.clone(),
                    source: "heuristic".into(),
                    threat_level: "SUSPICIOUS".into(),
                    score: heuristic_score as f64 / 10.0,
                    detail: detail.into(),
                });
                // Still try to verify via API
            }

            // ── Layer 3: cloud full analysis for suspicious PE files ───────
            if has_token
                && is_pe
                && heuristic_score >= 3
                && full_api_calls < max_full_calls
                && client.is_some()
                && file_size < 25 * 1024 * 1024  // cap upload at 25 MB
            {
                let _ = window.emit(
                    "scan-progress",
                    ScanProgress {
                        scanned,
                        threats: threats.len() as u64,
                        current_file: format!("Analyzing: {path_str}"),
                        done: false,
                        phase: "uploading".into(),
                    },
                );
                full_api_calls += 1;
                if let Some((level, score)) = api_full_scan(path, data.clone(), &token, client.as_ref().unwrap()) {
                    if level == "MALICIOUS" || level == "SUSPICIOUS" {
                        // Remove the heuristic entry if present (replace with confirmed)
                        threats.retain(|t| t.path != path_str);
                        threats.push(SystemThreat {
                            path: path_str,
                            sha256: hash,
                            source: "cloud-full".into(),
                            threat_level: level,
                            score,
                            detail: "Full cloud analysis: ML + YARA + threat intelligence".into(),
                        });
                    } else if heuristic_score >= 7 {
                        // Cloud says clean — remove heuristic flag
                        threats.retain(|t| t.path != path_str);
                    }
                }
                continue;
            }

            // ── Layer 4: cloud hash lookup for everything else ────────────
            if has_token && hash_api_calls < max_hash_calls && client.is_some() {
                hash_api_calls += 1;
                if let Some(level) = api_hash_lookup(&hash, &token, client.as_ref().unwrap()) {
                    if level == "MALICIOUS" {
                        threats.retain(|t| t.path != path_str);
                        threats.push(SystemThreat {
                            path: path_str,
                            sha256: hash,
                            source: "cloud-hash".into(),
                            threat_level: level,
                            score: 0.95,
                            detail: "Hash matched threat intelligence database".into(),
                        });
                    }
                }
            }
        }
    }

    scan_flag().store(false, Ordering::Relaxed);

    let _ = window.emit(
        "scan-progress",
        ScanProgress {
            scanned,
            threats: threats.len() as u64,
            current_file: String::new(),
            done: true,
            phase: "done".into(),
        },
    );

    Ok(threats)
}

#[tauri::command]
pub fn scan_file(path: String) -> Result<ScanResult, String> {
    let token = get_token()?;
    let file_bytes =
        std::fs::read(&path).map_err(|e| format!("Failed to read file '{path}': {e}"))?;
    let filename = std::path::Path::new(&path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

    let part = reqwest::blocking::multipart::Part::bytes(file_bytes)
        .file_name(filename)
        .mime_str("application/octet-stream")
        .map_err(|e| format!("Failed to set MIME type: {e}"))?;
    let form = reqwest::blocking::multipart::Form::new().part("file", part);

    let resp = client
        .post(format!("{API_BASE}/api/v1/scan/file"))
        .bearer_auth(&token)
        .multipart(form)
        .send()
        .map_err(|e| format!("Upload failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let text = resp.text().unwrap_or_default();
        return Err(format!("Scan upload failed ({status}): {text}"));
    }

    let upload_result: serde_json::Value = resp
        .json()
        .map_err(|e| format!("Failed to parse upload response: {e}"))?;

    let job_id = upload_result
        .get("id")
        .and_then(|v| v.as_str())
        .or_else(|| upload_result.get("job_id").and_then(|v| v.as_str()))
        .ok_or_else(|| "Upload response missing job id".to_string())?
        .to_string();

    for _ in 0..30u32 {
        std::thread::sleep(Duration::from_secs(2));
        let poll_resp = client
            .get(format!("{API_BASE}/api/v1/scan/{job_id}"))
            .bearer_auth(&token)
            .send()
            .map_err(|e| format!("Poll request failed: {e}"))?;
        if !poll_resp.status().is_success() {
            continue;
        }
        let result: serde_json::Value = poll_resp
            .json()
            .map_err(|e| format!("Failed to parse poll response: {e}"))?;
        let status = result
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("pending")
            .to_string();
        if status == "pending" || status == "running" {
            continue;
        }
        let threat_level = result
            .get("threat_level")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let score = result
            .get("ml_score")
            .or_else(|| result.get("score"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        return Ok(ScanResult {
            threat_level,
            score,
            status,
        });
    }
    Err("Scan timed out after 60 seconds".into())
}

#[tauri::command]
pub fn get_threat_stats() -> Result<ThreatStats, String> {
    let token = get_token()?;
    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(format!("{API_BASE}/api/v1/agent/stats"))
        .bearer_auth(&token)
        .send()
        .map_err(|e| format!("Network error: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("Failed to fetch threat stats ({})", resp.status().as_u16()));
    }
    let raw: serde_json::Value = resp
        .json()
        .map_err(|e| format!("Failed to parse stats: {e}"))?;
    Ok(ThreatStats {
        total_alerts: raw.get("total_alerts").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
        critical: raw.get("critical").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
        high: raw.get("high").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
    })
}

#[tauri::command]
pub fn get_alerts(limit: i32) -> Result<Vec<Alert>, String> {
    let token = get_token()?;
    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(format!("{API_BASE}/api/v1/agent/alerts"))
        .query(&[("limit", limit.to_string())])
        .bearer_auth(&token)
        .send()
        .map_err(|e| format!("Network error: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("Failed to fetch alerts ({})", resp.status().as_u16()));
    }
    let raw: serde_json::Value = resp
        .json()
        .map_err(|e| format!("Failed to parse alerts: {e}"))?;
    let arr = if let Some(alerts) = raw.get("alerts").and_then(|v| v.as_array()) {
        alerts.clone()
    } else if let Some(arr) = raw.as_array() {
        arr.clone()
    } else {
        return Ok(vec![]);
    };
    Ok(arr
        .iter()
        .filter_map(|v| {
            Some(Alert {
                id: v.get("id").and_then(|x| x.as_i64())? as i32,
                severity: v.get("severity").and_then(|x| x.as_str()).unwrap_or("medium").to_string(),
                message: v.get("message").and_then(|x| x.as_str()).unwrap_or("Unknown alert").to_string(),
                file_path: v.get("file_path").and_then(|x| x.as_str()).map(String::from),
                created_at: v.get("created_at").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            })
        })
        .collect())
}
