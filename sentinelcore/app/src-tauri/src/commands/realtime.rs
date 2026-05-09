/// Real-time protection engine for RedGuard.
///
/// Watches high-risk directories for new/modified executable files.
/// Each file goes through a 4-layer analysis pipeline:
///   1. Local SHA256 blocklist          (instant, no network)
///   2. Local PE heuristics             (in-process, no network)
///   3. Cloud full scan (ML+YARA+VT)    (API, triggered on suspicious PE)
///   4. Cloud hash lookup               (API, fallback)
///
/// MALICIOUS (score ≥ 0.85) → auto-quarantine + system notification + UI alert
/// SUSPICIOUS (score ≥ 0.50) → flag only + notification + UI alert
use crate::commands::auth::get_token;
use chrono::Utc;
use dashmap::DashSet;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex, OnceLock,
};
use std::time::Duration;
use tauri::{AppHandle, Emitter};

// ── Constants ─────────────────────────────────────────────────────────────────

const API_BASE: &str = "https://api.redgaurd.com";
const XOR_KEY: u8 = 0x52; // 'R' — prevents accidental execution of quarantined files
const QUARANTINE_THRESHOLD: f64 = 0.85; // auto-quarantine above this
const FLAG_THRESHOLD: f64 = 0.50; // show alert above this
const MAX_FILE_SIZE: u64 = 25 * 1024 * 1024; // 25 MB — skip larger files
const DEBOUNCE_MS: u64 = 800; // wait for file writes to complete
const KNOWN_BAD: &str = include_str!("../../../../engine/signatures/malware_hashes.txt");

const WATCH_EXTS: &[&str] = &[
    "exe", "dll", "sys", "drv", "bat", "cmd", "ps1", "vbs", "js", "msi", "scr", "cpl", "pif",
    "hta", "wsf", "lnk", "jar", "reg",
];

const PE_EXTS: &[&str] = &["exe", "dll", "sys", "drv", "scr", "cpl"];

const SUSPICIOUS_APIS: &[&str] = &[
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "SetWindowsHookEx", "GetAsyncKeyState", "NtUnmapViewOfSection",
    "RtlDecompressBuffer", "NtWriteVirtualMemory", "ZwAllocateVirtualMemory",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
];

const PACKER_SIGS: &[&[u8]] = &[b"UPX0", b"UPX1", b".themida", b".enigma", b".packed", b"ASPack"];

// ── Global state ──────────────────────────────────────────────────────────────

struct RtState {
    quarantine: Mutex<Vec<QuarantineEntry>>,
}

static STATE: OnceLock<Arc<RtState>> = OnceLock::new();
static ENABLED: OnceLock<Arc<AtomicBool>> = OnceLock::new();
static FILES_ANALYZED: OnceLock<Arc<AtomicU64>> = OnceLock::new();
static THREATS_BLOCKED: OnceLock<Arc<AtomicU64>> = OnceLock::new();
static THREATS_FLAGGED: OnceLock<Arc<AtomicU64>> = OnceLock::new();
// Hash cache — avoids re-analyzing files we've seen in this session
static SEEN_HASHES: OnceLock<Arc<DashSet<String>>> = OnceLock::new();
// Watcher handle kept alive in a Mutex so it's not dropped
static WATCHER_HANDLE: OnceLock<Mutex<Option<RecommendedWatcher>>> = OnceLock::new();

fn rt_state() -> Arc<RtState> {
    STATE.get_or_init(|| Arc::new(RtState { quarantine: Mutex::new(Vec::new()) })).clone()
}
fn enabled() -> Arc<AtomicBool> {
    ENABLED.get_or_init(|| Arc::new(AtomicBool::new(false))).clone()
}
fn files_analyzed() -> Arc<AtomicU64> {
    FILES_ANALYZED.get_or_init(|| Arc::new(AtomicU64::new(0))).clone()
}
fn threats_blocked() -> Arc<AtomicU64> {
    THREATS_BLOCKED.get_or_init(|| Arc::new(AtomicU64::new(0))).clone()
}
fn threats_flagged() -> Arc<AtomicU64> {
    THREATS_FLAGGED.get_or_init(|| Arc::new(AtomicU64::new(0))).clone()
}
fn seen_hashes() -> Arc<DashSet<String>> {
    SEEN_HASHES.get_or_init(|| Arc::new(DashSet::new())).clone()
}

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub quarantine_path: String,
    pub filename: String,
    pub sha256: String,
    pub threat_level: String,
    pub score: f64,
    pub timestamp: String,
    pub restored: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct ProtectionAlert {
    pub filename: String,
    pub path: String,
    pub threat_level: String,
    pub score: f64,
    pub action: String, // "quarantined" | "flagged"
    pub detail: String,
    pub timestamp: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct ProtectionStatus {
    pub enabled: bool,
    pub files_analyzed: u64,
    pub threats_blocked: u64,
    pub threats_flagged: u64,
}

// ── Quarantine directory ──────────────────────────────────────────────────────

fn quarantine_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA").unwrap_or_else(|_| "C:\\ProgramData".into());
        PathBuf::from(appdata).join("RedGuard").join("quarantine")
    }
    #[cfg(not(target_os = "windows"))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(home).join(".redguard").join("quarantine")
    }
}

// ── Heuristics (no network) ───────────────────────────────────────────────────

fn byte_entropy(data: &[u8]) -> f64 {
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let len = data.len() as f64;
    freq.iter().filter(|&&c| c > 0).map(|&c| { let p = c as f64 / len; -p * p.log2() }).sum()
}

fn quick_pe_score(data: &[u8]) -> u8 {
    if data.len() < 64 || &data[0..2] != b"MZ" { return 0; }
    let mut score = 0u8;
    let entropy = byte_entropy(data);
    if entropy > 7.2 { score += 4; } else if entropy > 6.8 { score += 2; } else if entropy > 6.4 { score += 1; }
    let content = String::from_utf8_lossy(data);
    for api in SUSPICIOUS_APIS { if content.contains(api) { score = score.saturating_add(1); } }
    for sig in PACKER_SIGS { if data.windows(sig.len()).any(|w| w == *sig) { score = score.saturating_add(3); } }
    score.min(10)
}

fn is_known_bad(hash: &str) -> bool {
    KNOWN_BAD.lines().any(|l| l.trim().eq_ignore_ascii_case(hash))
}

fn sha256_of(data: &[u8]) -> String {
    let mut h = Sha256::new(); h.update(data); format!("{:x}", h.finalize())
}

// ── Network helpers ───────────────────────────────────────────────────────────

fn make_client() -> Option<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder().timeout(Duration::from_secs(30)).build().ok()
}

fn cloud_hash_lookup(hash: &str, token: &str, client: &reqwest::blocking::Client) -> Option<String> {
    let resp = client
        .post(format!("{API_BASE}/api/v1/scan/hash"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "hash": hash }))
        .send().ok()?;
    if !resp.status().is_success() { return None; }
    resp.json::<serde_json::Value>().ok()?
        .get("threat_level").and_then(|v| v.as_str()).map(String::from)
}

fn cloud_full_scan(
    path: &Path,
    data: Vec<u8>,
    token: &str,
    client: &reqwest::blocking::Client,
) -> Option<(String, f64, String)> {
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string();
    let part = reqwest::blocking::multipart::Part::bytes(data)
        .file_name(filename)
        .mime_str("application/octet-stream").ok()?;
    let form = reqwest::blocking::multipart::Form::new().part("file", part);
    let resp = client.post(format!("{API_BASE}/api/v1/scan/file")).bearer_auth(token).multipart(form).send().ok()?;
    if !resp.status().is_success() { return None; }
    let upload: serde_json::Value = resp.json().ok()?;
    let job_id = upload.get("id").or_else(|| upload.get("job_id")).and_then(|v| v.as_str())?.to_string();
    let poll_client = make_client()?;
    for _ in 0..20 {
        std::thread::sleep(Duration::from_secs(3));
        let pr = poll_client.get(format!("{API_BASE}/api/v1/scan/{job_id}")).bearer_auth(token).send().ok()?;
        if !pr.status().is_success() { continue; }
        let result: serde_json::Value = pr.json().ok()?;
        let status = result.get("status").and_then(|v| v.as_str()).unwrap_or("pending");
        if status == "pending" || status == "running" { continue; }
        let level = result.get("threat_level").and_then(|v| v.as_str()).unwrap_or("CLEAN").to_string();
        let score = result.get("ml_score").or_else(|| result.get("score")).and_then(|v| v.as_f64()).unwrap_or(0.0);
        let detail = result.get("heuristics")
            .and_then(|h| h.get("hits")).and_then(|h| h.as_array())
            .and_then(|arr| arr.first()).and_then(|h| h.get("rule_id")).and_then(|v| v.as_str())
            .unwrap_or("ML + YARA + threat intelligence").to_string();
        return Some((level, score, detail));
    }
    None
}

// ── Quarantine ────────────────────────────────────────────────────────────────

fn quarantine_file(path: &Path, hash: &str, level: &str, score: f64) -> Option<QuarantineEntry> {
    let dir = quarantine_dir();
    std::fs::create_dir_all(&dir).ok()?;
    let id = uuid::Uuid::new_v4().to_string();
    let filename = path.file_name()?.to_string_lossy().to_string();
    let data = std::fs::read(path).ok()?;
    // XOR-encrypt so the file cannot accidentally execute
    let encrypted: Vec<u8> = data.iter().map(|&b| b ^ XOR_KEY).collect();
    let qpath = dir.join(format!("{id}.rg"));
    std::fs::write(&qpath, &encrypted).ok()?;
    // Remove original; best-effort if the file is locked
    let _ = std::fs::remove_file(path);
    let entry = QuarantineEntry {
        id,
        original_path: path.to_string_lossy().to_string(),
        quarantine_path: qpath.to_string_lossy().to_string(),
        filename,
        sha256: hash.to_string(),
        threat_level: level.to_string(),
        score,
        timestamp: Utc::now().to_rfc3339(),
        restored: false,
    };
    Some(entry)
}

// ── Core analysis routine ─────────────────────────────────────────────────────

/// Analyze a single file through all 4 layers. Called from the background watcher.
fn analyze_file_realtime(path: &Path, app: &AppHandle) {
    // Basic guards
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    if !WATCH_EXTS.contains(&ext.as_str()) { return; }

    let Ok(meta) = std::fs::metadata(path) else { return };
    let size = meta.len();
    if size == 0 || size > MAX_FILE_SIZE { return; }

    // Wait for file write to settle
    std::thread::sleep(Duration::from_millis(DEBOUNCE_MS));

    // Re-check size hasn't changed (file still being written)
    if let Ok(m2) = std::fs::metadata(path) { if m2.len() != size { return; } }

    let Ok(data) = std::fs::read(path) else { return };
    let hash = sha256_of(&data);

    // Dedup — skip if analyzed this session
    if !seen_hashes().insert(hash.clone()) { return; }

    files_analyzed().fetch_add(1, Ordering::Relaxed);

    let token = get_token().unwrap_or_default();
    let has_token = !token.is_empty();
    let client = make_client();
    let path_str = path.to_string_lossy().to_string();
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown").to_string();
    let is_pe = PE_EXTS.contains(&ext.as_str());

    let mut threat_level = "CLEAN".to_string();
    let mut score = 0.0f64;
    let mut detail = String::new();
    let mut source = "clean";

    // ── Layer 1: local blocklist ───────────────────────────────────────────
    if is_known_bad(&hash) {
        threat_level = "MALICIOUS".to_string();
        score = 1.0;
        detail = "Matched known malware hash database".to_string();
        source = "local-blocklist";
    }

    // ── Layer 2: local PE heuristics ──────────────────────────────────────
    if threat_level == "CLEAN" && is_pe {
        let hs = quick_pe_score(&data);
        if hs >= 7 {
            threat_level = "SUSPICIOUS".to_string();
            score = hs as f64 / 10.0;
            detail = format!("High-entropy packer/injector patterns detected (score {hs}/10)");
            source = "heuristic";
        } else if hs >= 4 {
            score = hs as f64 / 10.0;
        }
    }

    // ── Layer 3: cloud full scan for suspicious PE ─────────────────────────
    if has_token && is_pe && score >= 0.3 && client.is_some() {
        if let Some((lvl, sc, det)) = cloud_full_scan(path, data.clone(), &token, client.as_ref().unwrap()) {
            threat_level = lvl;
            score = sc;
            detail = det;
            source = "cloud-full";
        }
    }
    // ── Layer 4: cloud hash lookup ─────────────────────────────────────────
    else if has_token && threat_level == "CLEAN" && client.is_some() {
        if let Some(lvl) = cloud_hash_lookup(&hash, &token, client.as_ref().unwrap()) {
            if lvl != "CLEAN" {
                threat_level = lvl.clone();
                score = if lvl == "MALICIOUS" { 0.95 } else { 0.65 };
                detail = "Matched threat intelligence database".to_string();
                source = "cloud-hash";
            }
        }
    }

    let _ = source; // used implicitly via threat_level

    // ── Act on result ──────────────────────────────────────────────────────
    if score < FLAG_THRESHOLD { return; } // clean or very low confidence — ignore

    let action;
    if score >= QUARANTINE_THRESHOLD || threat_level == "MALICIOUS" {
        // Auto-quarantine
        let state = rt_state();
        if let Some(entry) = quarantine_file(path, &hash, &threat_level, score) {
            if let Ok(mut q) = state.quarantine.lock() {
                q.push(entry);
            }
        }
        threats_blocked().fetch_add(1, Ordering::Relaxed);
        action = "quarantined";

        // System notification
        use tauri_plugin_notification::NotificationExt;
        let _ = app.notification()
            .builder()
            .title("RedGuard blocked a threat")
            .body(format!("Quarantined: {} ({:.0}% confidence)", filename, score * 100.0))
            .show();
    } else {
        // Flag but don't remove
        threats_flagged().fetch_add(1, Ordering::Relaxed);
        action = "flagged";

        use tauri_plugin_notification::NotificationExt;
        let _ = app.notification()
            .builder()
            .title("RedGuard: suspicious file detected")
            .body(format!("Review: {} ({:.0}% suspicious)", filename, score * 100.0))
            .show();
    }

    // Emit event to React UI
    let alert = ProtectionAlert {
        filename,
        path: path_str,
        threat_level,
        score,
        action: action.to_string(),
        detail: if detail.is_empty() { "Suspicious file activity detected".to_string() } else { detail },
        timestamp: Utc::now().to_rfc3339(),
    };
    let _ = app.emit("protection-alert", &alert);
}

// ── Watched directories ───────────────────────────────────────────────────────

fn watch_dirs() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let profile = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Public".into());
        let appdata = std::env::var("APPDATA").unwrap_or_else(|_| format!("{profile}\\AppData\\Roaming"));
        let local = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| format!("{profile}\\AppData\\Local"));
        let temp = std::env::var("TEMP").unwrap_or_else(|_| format!("{local}\\Temp"));
        vec![
            PathBuf::from(format!("{profile}\\Downloads")),
            PathBuf::from(format!("{profile}\\Desktop")),
            PathBuf::from(format!("{profile}\\Documents")),
            PathBuf::from(&temp),
            PathBuf::from("C:\\Windows\\Temp"),
            PathBuf::from(&appdata),
            PathBuf::from("C:\\ProgramData"),
            PathBuf::from(format!("{local}\\Temp")),
        ]
    }
    #[cfg(not(target_os = "windows"))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());
        vec![
            PathBuf::from(format!("{home}/Downloads")),
            PathBuf::from(format!("{home}/Desktop")),
            PathBuf::from("/tmp"),
            PathBuf::from("/var/tmp"),
        ]
    }
}

// ── Background watcher startup ────────────────────────────────────────────────

pub fn start_watcher(app: AppHandle) {
    let app_clone = app.clone();
    let enabled_flag = enabled();

    std::thread::spawn(move || {
        let (tx, rx) = std::sync::mpsc::channel();

        let mut watcher = match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("[RedGuard RT] Failed to create watcher: {e}");
                return;
            }
        };

        for dir in watch_dirs() {
            if dir.exists() {
                if let Err(e) = watcher.watch(&dir, RecursiveMode::Recursive) {
                    eprintln!("[RedGuard RT] Cannot watch {}: {e}", dir.display());
                }
            }
        }

        // Store watcher to keep it alive
        if let Some(handle) = WATCHER_HANDLE.get() {
            if let Ok(mut guard) = handle.lock() {
                *guard = Some(watcher);
            }
        }

        loop {
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(event) => {
                    if !enabled_flag.load(Ordering::Relaxed) { continue; }
                    match event.kind {
                        EventKind::Create(_) | EventKind::Modify(notify::event::ModifyKind::Data(_)) => {
                            for path in &event.paths {
                                if path.is_file() {
                                    let p = path.clone();
                                    let app_ref = app_clone.clone();
                                    // Analyze in a separate thread so watcher loop doesn't block
                                    std::thread::spawn(move || {
                                        analyze_file_realtime(&p, &app_ref);
                                    });
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(_) => break,
            }
        }
    });
}

// ── Tauri commands ────────────────────────────────────────────────────────────

#[tauri::command]
pub fn enable_realtime_protection() -> ProtectionStatus {
    enabled().store(true, Ordering::Relaxed);
    get_protection_status()
}

#[tauri::command]
pub fn disable_realtime_protection() -> ProtectionStatus {
    enabled().store(false, Ordering::Relaxed);
    get_protection_status()
}

#[tauri::command]
pub fn get_protection_status() -> ProtectionStatus {
    ProtectionStatus {
        enabled: enabled().load(Ordering::Relaxed),
        files_analyzed: files_analyzed().load(Ordering::Relaxed),
        threats_blocked: threats_blocked().load(Ordering::Relaxed),
        threats_flagged: threats_flagged().load(Ordering::Relaxed),
    }
}

#[tauri::command]
pub fn get_quarantine() -> Vec<QuarantineEntry> {
    rt_state().quarantine.lock().map(|q| q.clone()).unwrap_or_default()
}

#[tauri::command]
pub fn restore_quarantine_file(id: String) -> Result<(), String> {
    let state = rt_state();
    let mut q = state.quarantine.lock().map_err(|e| e.to_string())?;
    let entry = q.iter_mut().find(|e| e.id == id).ok_or("Entry not found")?;
    if entry.restored { return Err("Already restored".into()); }
    let encrypted = std::fs::read(&entry.quarantine_path).map_err(|e| e.to_string())?;
    let decrypted: Vec<u8> = encrypted.iter().map(|&b| b ^ XOR_KEY).collect();
    std::fs::write(&entry.original_path, &decrypted).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&entry.quarantine_path);
    entry.restored = true;
    Ok(())
}

#[tauri::command]
pub fn delete_quarantine_file(id: String) -> Result<(), String> {
    let state = rt_state();
    let mut q = state.quarantine.lock().map_err(|e| e.to_string())?;
    let idx = q.iter().position(|e| e.id == id).ok_or("Entry not found")?;
    let entry = &q[idx];
    let _ = std::fs::remove_file(&entry.quarantine_path);
    q.remove(idx);
    Ok(())
}

/// Initialize the watcher handle storage (call once at app startup).
pub fn init_watcher_storage() {
    let _ = WATCHER_HANDLE.set(Mutex::new(None));
}
