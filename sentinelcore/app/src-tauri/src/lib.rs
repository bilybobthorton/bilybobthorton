mod commands;

use tauri::{
    menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager,
};

pub fn run() {
    tauri::Builder::default()
        // Plugins
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        // System tray
        .setup(|app| {
            build_tray(app)?;
            Ok(())
        })
        // Register all Tauri commands
        .invoke_handler(tauri::generate_handler![
            // auth
            commands::auth::login,
            commands::auth::logout,
            commands::auth::get_subscription,
            // vpn
            commands::vpn::get_vpn_keys,
            commands::vpn::connect_vpn,
            commands::vpn::disconnect_vpn,
            commands::vpn::get_vpn_status,
            // scanner
            commands::scanner::get_threat_stats,
            commands::scanner::get_alerts,
            commands::scanner::scan_file,
            // tray / window
            commands::tray::update_tray_status,
            commands::tray::show_window,
            commands::tray::hide_window,
        ])
        .run(tauri::generate_context!())
        .expect("error while running RedGuard application");
}

fn build_tray(app: &mut tauri::App) -> tauri::Result<()> {
    let open_item = MenuItem::with_id(app, "open", "Open RedGuard", true, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;

    let vpn_item = CheckMenuItem::with_id(app, "vpn", "Enable VPN", true, false, None::<&str>)?;
    let protection_item =
        CheckMenuItem::with_id(app, "protect", "Enable Protection", true, true, None::<&str>)?;

    let sep2 = PredefinedMenuItem::separator(app)?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

    let menu = Menu::with_items(
        app,
        &[
            &open_item,
            &sep1,
            &vpn_item,
            &protection_item,
            &sep2,
            &quit_item,
        ],
    )?;

    TrayIconBuilder::with_id("main")
        .tooltip("RedGuard — Protected")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => {
                show_main_window(app);
            }
            "quit" => {
                app.exit(0);
            }
            "vpn" | "protect" => {
                // Toggle state is handled automatically by CheckMenuItem;
                // a real implementation would wire into VPN/protection commands here.
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        })
        .build(app)?;

    Ok(())
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}
