#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::fs;
use std::sync::Mutex;
use serde::{Deserialize, Serialize};
use tauri::State;

const CONFIG_PATH: &str = "client_config.json";

#[derive(Serialize, Deserialize, Clone)]
struct ClientConfig {
    relays: Vec<String>,
    interface_name: String,
    address: String,
    dns_servers: Vec<String>,
}

struct AppState {
    status: Mutex<String>,
}

#[tauri::command]
fn load_config() -> Result<ClientConfig, String> {
    let data = fs::read_to_string(CONFIG_PATH).map_err(|e| e.to_string())?;
    serde_json::from_str(&data).map_err(|e| e.to_string())
}

#[tauri::command]
fn save_config(config: ClientConfig) -> Result<(), String> {
    let data = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    fs::write(CONFIG_PATH, data).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_status(state: State<AppState>) -> String {
    state.status.lock().unwrap().clone()
}

#[tauri::command]
fn connect(state: State<AppState>) {
    let mut status = state.status.lock().unwrap();
    *status = "connected".to_string();
}

#[tauri::command]
fn disconnect(state: State<AppState>) {
    let mut status = state.status.lock().unwrap();
    *status = "disconnected".to_string();
}

fn main() {
    tauri::Builder::default()
        .manage(AppState {
            status: Mutex::new("disconnected".to_string()),
        })
        .invoke_handler(tauri::generate_handler![
            load_config,
            save_config,
            get_status,
            connect,
            disconnect
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
