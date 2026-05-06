use crate::commands::auth::get_token;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const API_BASE: &str = "https://api.redgaurd.com";
/// Maximum poll iterations before giving up waiting for scan result.
const MAX_POLL_ITERATIONS: u32 = 30;
/// Seconds between poll requests.
const POLL_INTERVAL_SECS: u64 = 2;

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
        let status = resp.status().as_u16();
        return Err(format!("Failed to fetch threat stats ({status})"));
    }

    let raw: serde_json::Value = resp
        .json()
        .map_err(|e| format!("Failed to parse stats: {e}"))?;

    let total_alerts = raw
        .get("total_alerts")
        .and_then(|v| v.as_i64())
        .unwrap_or(0) as i32;

    let critical = raw
        .get("critical")
        .and_then(|v| v.as_i64())
        .unwrap_or(0) as i32;

    let high = raw.get("high").and_then(|v| v.as_i64()).unwrap_or(0) as i32;

    Ok(ThreatStats {
        total_alerts,
        critical,
        high,
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
        let status = resp.status().as_u16();
        return Err(format!("Failed to fetch alerts ({status})"));
    }

    let raw: serde_json::Value = resp
        .json()
        .map_err(|e| format!("Failed to parse alerts: {e}"))?;

    // API may return { alerts: [...] } or a bare array.
    let arr = if let Some(alerts) = raw.get("alerts").and_then(|v| v.as_array()) {
        alerts.clone()
    } else if let Some(arr) = raw.as_array() {
        arr.clone()
    } else {
        return Ok(vec![]);
    };

    let alerts: Vec<Alert> = arr
        .iter()
        .filter_map(|v| {
            let id = v.get("id").and_then(|x| x.as_i64())? as i32;
            let severity = v
                .get("severity")
                .and_then(|x| x.as_str())
                .unwrap_or("medium")
                .to_string();
            let message = v
                .get("message")
                .and_then(|x| x.as_str())
                .unwrap_or("Unknown alert")
                .to_string();
            let file_path = v
                .get("file_path")
                .and_then(|x| x.as_str())
                .map(String::from);
            let created_at = v
                .get("created_at")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            Some(Alert {
                id,
                severity,
                message,
                file_path,
                created_at,
            })
        })
        .collect();

    Ok(alerts)
}

#[tauri::command]
pub fn scan_file(path: String) -> Result<ScanResult, String> {
    let token = get_token()?;

    // Read file bytes.
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

    // Build multipart form.
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

    // Poll until complete.
    for _ in 0..MAX_POLL_ITERATIONS {
        std::thread::sleep(Duration::from_secs(POLL_INTERVAL_SECS));

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

    Err(format!(
        "Scan timed out after {} seconds",
        MAX_POLL_ITERATIONS * POLL_INTERVAL_SECS as u32
    ))
}
