use crate::commands::auth::get_token;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

const API_BASE: &str = "https://api.redgaurd.com";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VpnDevice {
    pub id: i32,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VpnStatus {
    pub connected: bool,
    pub server: Option<String>,
}

/// Global VPN connection state.
static VPN_STATUS: Mutex<VpnStatus> = Mutex::new(VpnStatus {
    connected: false,
    server: None,
});

fn get_appdata_dir() -> Result<std::path::PathBuf, String> {
    let appdata = std::env::var("APPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            // Fallback for non-Windows (dev/testing on macOS/Linux)
            dirs_next_fallback()
        });
    let dir = appdata.join("RedGuard");
    std::fs::create_dir_all(&dir).map_err(|e| format!("Failed to create RedGuard dir: {e}"))?;
    Ok(dir)
}

/// Minimal fallback when APPDATA is not available (macOS / Linux dev environment).
fn dirs_next_fallback() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    std::path::PathBuf::from(home).join(".redguard")
}

#[tauri::command]
pub fn get_vpn_keys() -> Result<Vec<VpnDevice>, String> {
    let token = get_token()?;
    let client = reqwest::blocking::Client::new();

    let resp = client
        .get(format!("{API_BASE}/api/v1/vpn/keys"))
        .bearer_auth(&token)
        .send()
        .map_err(|e| format!("Network error: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        return Err(format!("Failed to fetch VPN keys ({status})"));
    }

    let raw: serde_json::Value = resp
        .json()
        .map_err(|e| format!("Failed to parse VPN keys: {e}"))?;

    // API may return { keys: [...] } or a bare array.
    let arr = if let Some(keys) = raw.get("keys").and_then(|v| v.as_array()) {
        keys.clone()
    } else if let Some(arr) = raw.as_array() {
        arr.clone()
    } else {
        return Ok(vec![]);
    };

    let devices: Vec<VpnDevice> = arr
        .iter()
        .filter_map(|v| {
            let id = v.get("id").and_then(|x| x.as_i64())? as i32;
            let name = v
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("Device")
                .to_string();
            Some(VpnDevice { id, name })
        })
        .collect();

    Ok(devices)
}

#[tauri::command]
pub fn connect_vpn(device_id: i32) -> Result<(), String> {
    let token = get_token()?;
    let client = reqwest::blocking::Client::new();

    // Download WireGuard config.
    let resp = client
        .get(format!("{API_BASE}/api/v1/vpn/keys/{device_id}/config"))
        .bearer_auth(&token)
        .send()
        .map_err(|e| format!("Network error: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        return Err(format!("Failed to download VPN config ({status})"));
    }

    let conf_text = resp
        .text()
        .map_err(|e| format!("Failed to read config body: {e}"))?;

    // Save config file.
    let dir = get_appdata_dir()?;
    let conf_path = dir.join("vpn.conf");
    std::fs::write(&conf_path, &conf_text)
        .map_err(|e| format!("Failed to write vpn.conf: {e}"))?;

    // Install tunnel via WireGuard CLI (Windows).
    #[cfg(target_os = "windows")]
    {
        let conf_str = conf_path.to_string_lossy();
        let output = std::process::Command::new("wireguard.exe")
            .args(["/installtunnel", &conf_str])
            .output()
            .map_err(|e| format!("Failed to run wireguard.exe: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("wireguard.exe failed: {stderr}"));
        }
    }

    // On non-Windows (dev / macOS): skip actual WireGuard invocation.
    #[cfg(not(target_os = "windows"))]
    {
        eprintln!("[vpn] Non-Windows: skipping wireguard.exe, config saved to {conf_path:?}");
    }

    // Update global state.
    let mut status = VPN_STATUS
        .lock()
        .map_err(|e| format!("VPN state lock poisoned: {e}"))?;
    status.connected = true;
    status.server = Some("US East — New York".to_string());

    Ok(())
}

#[tauri::command]
pub fn disconnect_vpn() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("wireguard.exe")
            .args(["/uninstalltunnel", "redguard"])
            .output()
            .map_err(|e| format!("Failed to run wireguard.exe: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("wireguard.exe failed: {stderr}"));
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        eprintln!("[vpn] Non-Windows: skipping wireguard.exe uninstall");
    }

    let mut status = VPN_STATUS
        .lock()
        .map_err(|e| format!("VPN state lock poisoned: {e}"))?;
    status.connected = false;
    status.server = None;

    Ok(())
}

#[tauri::command]
pub fn get_vpn_status() -> Result<VpnStatus, String> {
    let status = VPN_STATUS
        .lock()
        .map_err(|e| format!("VPN state lock poisoned: {e}"))?;
    Ok(status.clone())
}
