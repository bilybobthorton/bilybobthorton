use crate::commands::auth::get_token;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::Duration;
use tauri::Emitter;
use tokio::sync::mpsc::UnboundedSender;

const API_BASE: &str = "https://api.redgaurd.com";
const TUNNEL_NAME: &str = "redguard";

#[cfg(target_os = "windows")]
const WG_INSTALLER_URL: &str =
    "https://download.wireguard.com/windows-client/wireguard-installer.exe";

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

#[derive(Debug, Serialize, Deserialize, Clone)]
struct VpnPhase {
    phase: String,
    message: String,
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

fn send_phase(tx: &UnboundedSender<VpnPhase>, phase: &str, message: &str) {
    let _ = tx.send(VpnPhase {
        phase: phase.to_string(),
        message: message.to_string(),
    });
}

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
        let raw: serde_json::Value = resp.json().map_err(|e| format!("Parse error: {e}"))?;
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

    let raw: serde_json::Value = create_resp.json().map_err(|e| format!("Parse error: {e}"))?;
    raw.get("id")
        .and_then(|v| v.as_str())
        .map(|id| id.to_string())
        .ok_or_else(|| "Missing device ID in create response".to_string())
}

/// Check known install locations for wireguard.exe.
#[cfg(target_os = "windows")]
fn find_wireguard_exe() -> Option<std::path::PathBuf> {
    [
        r"C:\Program Files\WireGuard\wireguard.exe",
        r"C:\Program Files (x86)\WireGuard\wireguard.exe",
    ]
    .iter()
    .map(std::path::PathBuf::from)
    .find(|p| p.exists())
}

/// If WireGuard is not installed, download and silently install it.
/// Sends phase events so the UI can show progress.
#[cfg(target_os = "windows")]
fn ensure_wireguard(phase_tx: &UnboundedSender<VpnPhase>) -> Result<std::path::PathBuf, String> {
    if let Some(path) = find_wireguard_exe() {
        return Ok(path);
    }

    send_phase(phase_tx, "installing", "Downloading VPN components…");

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let mut resp = client
        .get(WG_INSTALLER_URL)
        .send()
        .map_err(|e| format!("Failed to download VPN components: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!(
            "VPN component download failed ({})",
            resp.status().as_u16()
        ));
    }

    let installer_path = std::env::temp_dir().join("redguard-vpn-setup.exe");
    {
        let mut file = std::fs::File::create(&installer_path)
            .map_err(|e| format!("Temp file error: {e}"))?;
        std::io::copy(&mut resp, &mut file)
            .map_err(|e| format!("Download write error: {e}"))?;
    }

    send_phase(
        phase_tx,
        "installing",
        "Installing VPN components (one-time)…",
    );

    // /S = silent NSIS install, no UI shown to user.
    let exit = std::process::Command::new(&installer_path)
        .arg("/S")
        .status()
        .map_err(|e| format!("Failed to launch VPN installer: {e}"))?;

    let _ = std::fs::remove_file(&installer_path);

    if !exit.success() {
        return Err(format!(
            "VPN component installation failed (code {:?}) — try running as administrator",
            exit.code()
        ));
    }

    // Wait up to 15 s for the binary to appear after install.
    for _ in 0..30 {
        if let Some(path) = find_wireguard_exe() {
            return Ok(path);
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    Err("VPN components installed but driver not ready — please restart the app".to_string())
}

/// All blocking connect work: provision device, download config, install WireGuard if needed,
/// activate tunnel. Sends VpnPhase updates through the channel so the async side can
/// forward them to the webview without racing.
fn connect_vpn_blocking(token: String, phase_tx: &UnboundedSender<VpnPhase>) -> Result<(), String> {
    let client = build_client()?;

    send_phase(phase_tx, "configuring", "Preparing your secure connection…");
    let device_id = get_or_create_device(&client, &token)?;

    send_phase(phase_tx, "configuring", "Downloading VPN configuration…");
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

    let dir = get_appdata_dir()?;
    let conf_path = dir.join(format!("{TUNNEL_NAME}.conf"));
    std::fs::write(&conf_path, &conf_text)
        .map_err(|e| format!("Failed to write vpn.conf: {e}"))?;

    #[cfg(target_os = "windows")]
    {
        let wg_exe = ensure_wireguard(phase_tx)?;

        send_phase(phase_tx, "connecting", "Activating secure tunnel…");

        // Remove stale tunnel if it exists.
        let _ = std::process::Command::new(&wg_exe)
            .args(["/uninstalltunnel", TUNNEL_NAME])
            .output();

        let conf_str = conf_path.to_string_lossy().to_string();
        let install = std::process::Command::new(&wg_exe)
            .args(["/installtunnel", &conf_str])
            .output()
            .map_err(|e| format!("Failed to register tunnel service: {e}"))?;

        if !install.status.success() {
            let err = String::from_utf8_lossy(&install.stderr);
            return Err(format!("Tunnel service registration failed: {err}"));
        }

        let activate = std::process::Command::new(&wg_exe)
            .args(["/tunnelon", TUNNEL_NAME])
            .output()
            .map_err(|e| format!("Failed to activate tunnel: {e}"))?;

        if !activate.status.success() {
            let err = String::from_utf8_lossy(&activate.stderr);
            return Err(format!("Tunnel activation failed: {err}"));
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        eprintln!("[vpn] Non-Windows: config saved to {conf_path:?}, skipping tunnel activation");
    }

    Ok(())
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

    Ok(arr
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
        .collect())
}

/// Connect to VPN fully automatically — no user action beyond clicking Connect.
/// Silently installs WireGuard if it is not already present.
#[tauri::command]
pub async fn connect_vpn(window: tauri::Window) -> Result<(), String> {
    let token = get_token()?;
    let (phase_tx, mut phase_rx) = tokio::sync::mpsc::unbounded_channel::<VpnPhase>();
    let (result_tx, result_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();

    // Run all blocking work on a dedicated OS thread so the async runtime stays unblocked.
    std::thread::spawn(move || {
        let result = connect_vpn_blocking(token, &phase_tx);
        drop(phase_tx); // close channel so the async recv loop exits
        let _ = result_tx.send(result);
    });

    // Forward phase updates to the webview.
    while let Some(phase) = phase_rx.recv().await {
        window.emit("vpn-phase", &phase).ok();
    }

    let result = result_rx.await.map_err(|e| format!("Channel error: {e}"))?;

    if result.is_ok() {
        let mut status = VPN_STATUS
            .lock()
            .map_err(|e| format!("VPN state lock poisoned: {e}"))?;
        status.connected = true;
        status.server = Some("US East — New York".to_string());
    }

    result
}

#[tauri::command]
pub fn disconnect_vpn() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let wg_exe = find_wireguard_exe().unwrap_or_else(|| {
            std::path::PathBuf::from(r"C:\Program Files\WireGuard\wireguard.exe")
        });

        let _ = std::process::Command::new(&wg_exe)
            .args(["/tunneloff", TUNNEL_NAME])
            .output();

        let output = std::process::Command::new(&wg_exe)
            .args(["/uninstalltunnel", TUNNEL_NAME])
            .output()
            .map_err(|e| format!("Failed to run VPN client: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Tunnel removal failed: {stderr}"));
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        eprintln!("[vpn] Non-Windows: skipping tunnel removal");
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
