use serde::{Deserialize, Serialize};
use std::sync::Mutex;

const API_BASE: &str = "https://api.redgaurd.com";

/// Global token store — set on login, cleared on logout.
pub static TOKEN: Mutex<Option<String>> = Mutex::new(None);

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LoginResponse {
    pub access_token: String,
    pub tier: String,
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubscriptionInfo {
    pub tier: String,
    pub is_active: bool,
}

// Internal helper — used by other command modules.
pub fn get_token() -> Result<String, String> {
    TOKEN
        .lock()
        .map_err(|e| format!("Token lock poisoned: {e}"))?
        .clone()
        .ok_or_else(|| "Not authenticated".to_string())
}

#[tauri::command]
pub fn login(email: String, password: String) -> Result<LoginResponse, String> {
    let client = reqwest::blocking::Client::new();

    let body = serde_json::json!({
        "email": email,
        "password": password,
    });

    let resp = client
        .post(format!("{API_BASE}/api/v1/auth/login"))
        .json(&body)
        .send()
        .map_err(|e| format!("Network error: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let text = resp.text().unwrap_or_default();
        return Err(format!("Login failed ({status}): {text}"));
    }

    // The API may return either a flat object or nest token inside "data".
    // Parse raw JSON so we can handle both shapes.
    let raw: serde_json::Value = resp
        .json()
        .map_err(|e| format!("Failed to parse response: {e}"))?;

    let access_token = raw
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Response missing access_token".to_string())?
        .to_string();

    let tier = raw
        .get("tier")
        .and_then(|v| v.as_str())
        .unwrap_or("free")
        .to_string();

    let resp_email = raw
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or(&email)
        .to_string();

    // Persist token in global state.
    *TOKEN
        .lock()
        .map_err(|e| format!("Token lock poisoned: {e}"))? = Some(access_token.clone());

    Ok(LoginResponse {
        access_token,
        tier,
        email: resp_email,
    })
}

/// Called by the frontend on startup to restore a persisted session into Rust memory.
#[tauri::command]
pub fn set_token(token: String) -> Result<(), String> {
    *TOKEN
        .lock()
        .map_err(|e| format!("Token lock poisoned: {e}"))? = Some(token);
    Ok(())
}

#[tauri::command]
pub fn logout() -> Result<(), String> {
    *TOKEN
        .lock()
        .map_err(|e| format!("Token lock poisoned: {e}"))? = None;
    Ok(())
}

#[tauri::command]
pub fn get_subscription() -> Result<SubscriptionInfo, String> {
    let token = get_token()?;
    let client = reqwest::blocking::Client::new();

    let resp = client
        .get(format!("{API_BASE}/api/v1/shopify/subscription"))
        .bearer_auth(&token)
        .send()
        .map_err(|e| format!("Network error: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        return Err(format!("Failed to fetch subscription ({status})"));
    }

    let raw: serde_json::Value = resp
        .json()
        .map_err(|e| format!("Failed to parse subscription: {e}"))?;

    let tier = raw
        .get("tier")
        .and_then(|v| v.as_str())
        .unwrap_or("free")
        .to_string();

    let is_active = raw
        .get("is_active")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    Ok(SubscriptionInfo { tier, is_active })
}
