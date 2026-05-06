use tauri::{AppHandle, Manager};

#[tauri::command]
pub fn update_tray_status(app: AppHandle, protected: bool) -> Result<(), String> {
    if let Some(tray) = app.tray_by_id("main") {
        let tooltip = if protected {
            "RedGuard — Protected"
        } else {
            "RedGuard — At Risk"
        };
        tray.set_tooltip(Some(tooltip))
            .map_err(|e| format!("Failed to update tray tooltip: {e}"))?;
    }
    Ok(())
}

#[tauri::command]
pub fn show_window(app: AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        window.show().map_err(|e| format!("Failed to show window: {e}"))?;
        window.set_focus().map_err(|e| format!("Failed to focus window: {e}"))?;
    }
    Ok(())
}

#[tauri::command]
pub fn hide_window(app: AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        window.hide().map_err(|e| format!("Failed to hide window: {e}"))?;
    }
    Ok(())
}
