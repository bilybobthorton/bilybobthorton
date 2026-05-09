use crate::commands::auth::get_token;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::Duration;

const API_BASE: &str = "https://api.redgaurd.com";
const TUNNEL_NAME: &str = "redguard";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VpnDevice {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VpnStatus {
    pub connected: bool,
    pub server: Option<String>,
}

static VPN_STATUS: Mutex<VpnStatus> = Mutex::new(VpnStatus {
    connected: false,
    server: None,
});

fn get_appdata_dir() -> Result<std::path::PathBuf, String> {
    let appdata = std::env::var("APPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            std::path::PathBuf::from(home).join(".redguard")
        });
    let dir = appdata.join("RedGuard");
    std::fs::create_dir_all(&dir).map_err(|e| format!("Failed to create RedGuard dir: {e}"))?;
    Ok(dir)
}

fn build_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))
}

/// Returns the ID of the user's first VPN device, creating one if none exist.
fn get_or_create_device(
    client: &reqwest::blocking::Client,
    token: &str,
) -> Result<String, String> {
    let resp = client
        .get(format!("{API_BASE}/api/v1/vpn/keys"))
        .bearer_auth(token)
        .send()
        .map_err(|e| format!("Network error: {e}"))?;

    if resp.status().is_success() {
        let raw: serde_json::Value =
            resp.json().map_err(|e| format!("Parse error: {e}"))?;
        let arr = raw
            .get("keys")
            .and_then(|v| v.as_array())
            .or_else(|| raw.as_array())
            .cloned()
            .unwrap_or_default();
        if let Some(first) = arr.first() {
            if let Some(id) = first.get("id").and_then(|v| v.as_str()) {
                return Ok(id.to_string());
            }
        }
    }

    // No device exists — create one automatically.
    let create_resp = client
        .post(format!("{API_BASE}/api/v1/vpn/keys"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "name": "Desktop" }))
        .send()
        .map_err(|e| format!("Network error creating device: {e}"))?;

    if !create_resp.status().is_success() {
        let status = create_resp.status().as_u16();
        let body = create_resp.text().unwrap_or_default();
        return Err(format!("Failed to create VPN device ({status}): {body}"));
    }

    let raw: serde_json::Value = create_resp
        .json()
        .map_err(|e| format!("Parse error: {e}"))?;
    raw.get("id")
        .and_then(|v| v.as_str())
        .map(|id| id.to_string())
        .ok_or_else(|| "Missing device ID in create response".to_string())
}

#[tauri::command]
pub fn get_vpn_keys() -> Result<Vec<VpnDevice>, String> {
    let token = get_token()?;
    let client = build_client()?;

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
            let id = v.get("id").and_then(|x| x.as_str())?.to_string();
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

/// Connect to VPN — fully automatic. Auto-provisions a device if none exists,
/// downloads the WireGuard config, installs and activates the tunnel.
#[tauri::command]
pub fn connect_vpn() -> Result<(), String> {
    let token = get_token()?;
    let client = build_client()?;

    // 1. Get or create a VPN device.
    let device_id = get_or_create_device(&client, &token)?;

    // 2. Download WireGuard config.
    let resp = client
        .get(format!("{API_BASE}/api/v1/vpn/keys/{device_id}/config"))
        .bearer_auth(&token)
        .send()
        .map_err(|e| format!("Network error downloading config: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        return Err(format!("Failed to download VPN config ({status})"));
    }

    let conf_text = resp
        .text()
        .map_err(|e| format!("Failed to read config body: {e}"))?;

    // 3. Write config to %APPDATA%\RedGuard\redguard.conf
    let dir = get_appdata_dir()?;
    let conf_path = dir.join(format!("{TUNNEL_NAME}.conf"));
    std::fs::write(&conf_path, &conf_text)
        .map_err(|e| format!("Failed to write vpn.conf: {e}"))?;

    // 4. Install and activate tunnel (Windows only).
    #[cfg(target_os = "windows")]
    {
        // Remove any stale tunnel first — ignore errors.
        let _ = std::process::Command::new("wireguard.exe")
            .args(["/uninstalltunnel", TUNNEL_NAME])
            .output();

        // Install tunnel service.
        let conf_str = conf_path.to_string_lossy().to_string();
        let install = std::process::Command::new("wireguard.exe")
            .args(["/installtunnel", &conf_str])
            .output()
            .map_err(|e| format!("wireguard.exe not found — is WireGuard installed? {e}"))?;

        if !install.status.success() {
            let err = String::from_utf8_lossy(&install.stderr);
            return Err(format!("wireguard.exe /installtunnel failed: {err}"));
        }

        // Activate tunnel.
        let activate = std::process::Command::new("wireguard.exe")
            .args(["/tunnelon", TUNNEL_NAME])
            .output()
            .map_err(|e| format!("Failed to activate tunnel: {e}"))?;

        if !activate.status.success() {
            let err = String::from_utf8_lossy(&activate.stderr);
            return Err(format!("wireguard.exe /tunnelon failed: {err}"));
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        eprintln!("[vpn] Non-Windows: config saved to {conf_path:?}, skipping wireguard.exe");
    }

    // 5. Update status.
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
        // Deactivate tunnel.
        let _ = std::process::Command::new("wireguard.exe")
            .args(["/tunneloff", TUNNEL_NAME])
            .output();

        // Uninstall service.
        let output = std::process::Command::new("wireguard.exe")
            .args(["/uninstalltunnel", TUNNEL_NAME])
            .output()
            .map_err(|e| format!("Failed to run wireguard.exe: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("wireguard.exe /uninstalltunnel failed: {stderr}"));
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
