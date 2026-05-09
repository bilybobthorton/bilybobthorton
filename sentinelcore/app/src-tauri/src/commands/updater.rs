use serde::{Deserialize, Serialize};

const API_BASE: &str = "https://api.redgaurd.com";

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub version: String,
    pub release_notes: String,
    pub download_url: String,
}

/// Check the API for a newer version. Returns Some(UpdateInfo) if an update is available.
#[tauri::command]
pub async fn check_for_update(current_version: String) -> Option<UpdateInfo> {
    let url = format!("{}/api/v1/version", API_BASE);
    let resp = match reqwest::get(&url).await {
        Ok(r) => r,
        Err(_) => return None,
    };
    let info: UpdateInfo = match resp.json().await {
        Ok(i) => i,
        Err(_) => return None,
    };
    if is_newer(&info.version, &current_version) {
        Some(info)
    } else {
        None
    }
}

/// Open a URL in the system default browser.
#[tauri::command]
pub async fn open_browser_url(app: tauri::AppHandle, url: String) {
    use tauri_plugin_shell::ShellExt;
    let _ = app.shell().open(&url, None);
}

/// Compare semver strings — returns true if `remote` is newer than `local`.
fn is_newer(remote: &str, local: &str) -> bool {
    let parse = |s: &str| -> (u32, u32, u32) {
        let parts: Vec<u32> = s
            .trim_start_matches('v')
            .split('.')
            .filter_map(|p| p.parse().ok())
            .collect();
        (
            parts.first().copied().unwrap_or(0),
            parts.get(1).copied().unwrap_or(0),
            parts.get(2).copied().unwrap_or(0),
        )
    };
    parse(remote) > parse(local)
}
