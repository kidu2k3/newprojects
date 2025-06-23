# Tauri Client UI

This directory contains the Tauri-based user interface for the client app.

## Features (Planned)
- View and update client configuration (relays, interface, DNS, etc.)
- Display relay status and connection state
- Connect/disconnect actions
- Cross-platform (Linux, Windows, macOS)

## Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install)
- [Node.js](https://nodejs.org/)
- [Tauri CLI](https://tauri.app/v1/guides/getting-started/prerequisites/)

### Installation (All OS)

```bash
cd client/ui-tauri
npm install
```

### Running the UI

#### Linux/macOS

```bash
npm run dev
```

#### Windows

```powershell
npm run dev
```

### Building for Production

```bash
npm run build
```

### Notes

- The UI expects Tauri backend commands (Rust or Python) to provide real client status and metrics.
- You must implement Tauri commands (e.g., load_config, save_config, get_status, connect, disconnect) in src-tauri/ to connect the UI to the backend.
- See [Tauri Command Docs](https://tauri.app/v1/guides/features/command/) for backend integration.

## Next Steps

- Implement Tauri backend commands for config, status, and relay management.
- Integrate with client/config.py and relay status endpoints.
- Add metrics and real-time status updates to the UI.
