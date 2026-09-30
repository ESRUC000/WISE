# WISE — Wi-Fi Inspection and Security Evaluator

WISE is a Windows desktop app that assesses the Wi-Fi network currently connected to the computer. Each assessment is scored out of 100 and stored in the signed-in account's history so you can compare rescans and remove saved records.

## Score

- **Security protocol: 60 points.** WPA3 earns 60, WPA2 earns 48, WPA earns 24, WEP earns 8, and open or unknown authentication earns 0.
- **Company SSID and password: 20 points.** You earn these points only when you confirm that this is not a company-managed SSID and that you use a strong, unique Wi-Fi password. WISE cannot inspect your organization’s policy or reveal/check the Wi-Fi password.
- **Other safeguards: 20 points.** Up to 10 points are based on Windows-reported signal strength, and up to 10 points are awarded for a modern AES/CCMP/GCMP cipher.

The score breakdown appears in the dashboard. A scan is saved automatically; subsequent assessments of the same SSID show whether the score improved, decreased, or stayed the same. Use the history tab to review or delete one assessment or all history.

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

WISE reads the connected interface with Windows `netsh wlan show interfaces`. The desktop app sends account and scan operations to `server.py`; start that server before registering or logging in.

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
