# WISE — Wi-Fi Insight & Security Explorer

WISE is a Windows desktop app that assesses the Wi-Fi network currently connected to the computer. Each assessment is scored out of 100 and stored in a local SQLite history so you can compare rescans and remove saved records.

## Score

- **Security protocol: 60 points.** WPA3 earns 60, WPA2 earns 48, WPA earns 24, WEP earns 8, and open or unknown authentication earns 0.
- **Company SSID and password: 20 points.** You earn these points only when you confirm that this is not a company-managed SSID and that you use a strong, unique Wi-Fi password. WISE cannot inspect your organization’s policy or reveal/check the Wi-Fi password.
- **Other safeguards: 20 points.** Up to 10 points are based on Windows-reported signal strength, and up to 10 points are awarded for a modern AES/CCMP/GCMP cipher.

The score breakdown appears in the dashboard. A scan is saved automatically; subsequent assessments of the same SSID show whether the score improved, decreased, or stayed the same. Use the history tab to review or delete one assessment or all history.

## Scan history and privacy

The repository includes an empty SQLite database template at `data/wise_scans.db`. On first launch, WISE copies that template to a local runtime database, then stores scan history on the computer running the app. The runtime database is ignored by Git; only the empty template is shared. Scan history is not sent to GitHub. It can contain Wi-Fi network names and scan details, so do not upload or share a runtime database. Source mode keeps its runtime database as `wise_scans.db` beside the app; the packaged executable uses `%LOCALAPPDATA%\\WISE\\wise_scans.db`.

## Run the app

1. Use Windows with Python 3.10 or newer and connect to Wi-Fi.
2. In PowerShell, install the existing scanning dependency:

   ```powershell
   py -m pip install -r requirements.txt
   ```

3. Launch the interface:

   ```powershell
   py app.py
   ```

WISE reads the connected interface with Windows `netsh wlan show interfaces`. On first launch, it copies the empty template database to the runtime location. `database.py` exposes functions to save, list, retrieve, and delete assessments.

## Build a Windows executable

On Windows, run `.\build_exe.ps1` from PowerShell. The script installs the app/build dependencies and creates `dist\WISE.exe` as a single-file, windowed executable. Users can run the executable directly; no Python installation is needed. Their scan history is stored in `%LOCALAPPDATA%\WISE\wise_scans.db`.
