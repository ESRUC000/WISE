# WISE — Wi-Fi Inspection and Security Evaluator

WISE is a Windows desktop app that assesses the Wi-Fi network currently connected to the computer. Each assessment is scored out of 100 and stored in the signed-in account's history so you can compare rescans and remove saved records.

## Score

- **Security: 50 points.** Authentication contributes up to 35 points and modern AES/CCMP/GCMP cipher use contributes 15.
- **Performance: 30 points.** Signal strength, ping latency, packet loss, DNS resolution time, and optional measured download speed contribute to this category. Run the active tests from the overview; speed testing is opt-in.
- **Configuration: 20 points.** User-confirmed Wi-Fi and router administrator passphrases, SSID hygiene, and channel selection contribute to this category. WISE cannot inspect passwords or router settings.

The score breakdown appears in the dashboard. By default, rescanning the same SSID updates its most recent history row while comparing against its prior score. Enable **Keep each scan** beside the Scan button to retain every scan as a separate history entry. Use Scan history to filter, compare, export, and delete assessments.

## Scan history and privacy

WISE requires a user account. Usernames are unique without regard to letter case, and passwords are stored as salted PBKDF2-SHA256 hashes, never as plain text. Scans belong to the signed-in account and are stored by the API server, not on each desktop client. Session tokens are stored as hashes in the server database, survive server restarts, expire after 30 days, and are revoked on logout. An expired session returns the user to the login screen.

## Run the app

1. Use Windows with Python 3.10 or newer and connect to Wi-Fi.
2. In PowerShell, install the existing scanning dependency:

   ```powershell
   py -m pip install -r requirements.txt
   ```

3. Start the API server in one PowerShell window:

   ```powershell
   py server.py
   ```

The server listens on port 8000 by default. In another PowerShell window, point the desktop app at it and launch the interface:

   ```powershell
   $env:WISE_SERVER = "http://localhost:8000"
   py app.py
   ```

WISE reads the connected interface and nearby access points through the Windows WLAN service. Nearby scanning requests a fresh adapter scan, waits for Windows to complete it, then samples the results several times and uses the most complete result. Windows may require location access to expose nearby Wi-Fi details; allow WISE under **Settings > Privacy & security > Location** if Windows blocks a scan. Authentication text from Windows supports WPA3 and enterprise networks without PyWiFi or comtypes. The desktop app sends account and scan operations to `server.py`; start that server before registering or logging in.

The overview also checks nearby SSIDs for common default names and flags a possible rogue access point only when the same visible SSID is advertised with materially weaker security. These are heuristics, not proof of an attack. Device discovery is a separate, user-triggered ARP scan limited to the active IPv4 subnet and at most 1,024 addresses. On Windows, install Npcap and run the app with administrator privileges for ARP discovery. Performance tests, including internet speed testing, are also user-triggered.

The Scan history page plots saved score trends with Matplotlib, filters by SSID, compares two selected assessments, and exports CSV. The Reports page exports a PDF with score changes, recommendations, identity findings, and the latest saved device inventory. Device discovery snapshots are kept per account and show the gateway and devices first seen in the latest scan.

The overview provides a Quick test for ping and DNS only and a separate Speed test button; speed tests transfer data to an external test service. Performance recommendations are included in scoring, the dashboard recommendation panel, and PDF reports. Router/Wi-Fi confirmations are restored from the previous scan of the same SSID.

Desktop clients remember `WISE_SERVER` in the current user's application settings. Session tokens stay in memory only and are cleared when WISE closes, so users must sign in each time the app opens. The sign-in screen also lets packaged-app users set the API URL directly. Account settings supports password changes and permanent account deletion.

## Accounts and shared scan history

WISE requires a login before you can use the dashboard. Usernames are unique without regard to letter case. Passwords are stored as salted PBKDF2-SHA256 hashes; WISE never stores the original password. Every scan is associated with the account that created it, and history operations are restricted to that account.

The API server uses SQLite on its host by default. For shared multi-device accounts and scan history, configure the server to use PostgreSQL, then point each desktop app at the reachable API server. Set `DATABASE_URL` only on the API server and `WISE_SERVER` on each client. For example, on the server:

```powershell
$env:DATABASE_URL = "postgresql://wise_app:YOUR_PASSWORD@your-db-host:5432/wise"
py -m pip install -r requirements.txt
py server.py
```

On each desktop, configure the API URL and launch WISE:

```powershell
$env:WISE_SERVER = "https://your-wise-api-host"
py app.py
```

Use SSL-enabled connections for both PostgreSQL and the public API, and keep credentials out of source control. The API server creates its database tables on startup. Configure `TLS_CERT` and `TLS_KEY` to enable the API server's built-in HTTPS. If the server uses SQLite, accounts and scans stay on that server machine; every client must connect to the same API server to share them. API request bodies are limited to 1 MiB.

## Optional console report

Run `py scan_report.py` for a console-only nearby-network report. This troubleshooting tool performs a live radio scan; the desktop app does not need it.

## Checks

Run the offline project checks with `py -m unittest discover -s tests -v`. The optional nearby-network scan itself requires a working Wi-Fi adapter and is not run by the offline checks.

## Build a Windows executable

The build script creates both `dist\WISE.exe` (windowed release) and `dist\WISE-Debug.exe` (console-enabled troubleshooting build).

On Windows, run `.\build_exe.ps1` from PowerShell. The script installs the app/build dependencies and creates `dist\WISE.exe` as a single-file, windowed executable. Users can run the executable directly; no Python installation is needed. Configure `WISE_SERVER` for the API server; scan history is stored in the server's configured database.

The current windowed executable is also checked in at [`release/WISE.exe`](release/WISE.exe). It is built from this repository's `app.py` using `build_exe.ps1`; see [`release/README.md`](release/README.md) for its checksum and details. Rebuild it after changing the source so the checked-in executable stays current.
