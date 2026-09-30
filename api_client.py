"""Client for the WISE API service."""

import json
import os
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def _settings_path():
    root = Path(os.environ.get("APPDATA") or os.environ.get("LOCALAPPDATA") or Path.home() / ".config")
    return root / "WISE" / "client-settings.json"


def _load_settings():
    try:
        return json.loads(_settings_path().read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}


SERVER_URL = os.environ.get("WISE_SERVER", "").strip().rstrip("/") or \
    str(_load_settings().get("server_url", "http://localhost:8000")).rstrip("/")
_token = None
_UNSET = object()


class SessionExpired(RuntimeError):
    pass


def _keyring():
    try:
        import keyring
        return keyring
    except ImportError:
        return None


def _store_token(token):
    global _token
    _token = token
    # Sessions are intentionally kept in memory only. Requiring credentials at
    # each launch avoids silently signing the user back in.
    _clear_saved_token()


def _clear_saved_token():
    keyring = _keyring()
    if keyring is not None:
        try:
            keyring.delete_password("WISE API session", SERVER_URL)
        except Exception:
            pass


# Remove credentials saved by older versions that automatically restored them.
_clear_saved_token()


def configure_server_url(url):
    global SERVER_URL, _token
    url = str(url).strip().rstrip("/")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Enter a valid API URL beginning with http:// or https://, without embedded credentials.")
    SERVER_URL = url
    _token = None
    _clear_saved_token()
    config_path = _settings_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps({"server_url": SERVER_URL}), encoding="utf-8")
    return SERVER_URL


def _call(method, path, data=None, token=_UNSET):
    headers = {"Content-Type": "application/json"}
    auth_token = _token if token is _UNSET else token
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    request = urllib.request.Request(
        SERVER_URL + path, method=method, headers=headers,
        data=json.dumps(data).encode() if data is not None else None)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        try:
            data = json.load(error)
        except (ValueError, UnicodeDecodeError):
            data = {"error": f"Server returned HTTP {error.code} with a non-JSON response."}
        if not isinstance(data, dict):
            data = {"error": f"Server returned HTTP {error.code}."}
        return error.code, data
    except OSError as error:
        raise RuntimeError(f"Cannot reach the WISE server: {error}") from error


def _ok(result):
    code, data = result
    if code >= 400:
        message = data.get("error", "Server error")
        if code == 401:
            raise SessionExpired(message)
        raise (ValueError if code in (400, 429) else RuntimeError)(message)
    return data


def initialize_database():
    pass


def register_user(username, password):
    data = _ok(_call("POST", "/register", {"username": username, "password": password}))
    _store_token(data["token"])
    return data["user"]


def authenticate_user(username, password):
    code, data = _call("POST", "/login", {"username": username, "password": password})
    if code == 401:
        return None
    data = _ok((code, data))
    _store_token(data["token"])
    return data["user"]


def restore_session():
    """Automatic session restoration is disabled; require an explicit login."""
    return None


def _revoke_session(token):
    try:
        _call("DELETE", "/logout", token=token)
    except Exception:
        pass


def logout():
    global _token
    token, _token = _token, None
    _clear_saved_token()
    if token:
        threading.Thread(target=_revoke_session, args=(token,), daemon=True).start()


def change_password(current_password, new_password):
    return _ok(_call("POST", "/password", {
        "current_password": current_password, "new_password": new_password,
    }))


def delete_account(password):
    global _token
    result = _ok(_call("DELETE", "/account", {"password": password}))
    _token = None
    _clear_saved_token()
    return result


def save_scan(connection_info, score_info, update_id=None, user_id=None, separate=False):
    return _ok(_call("POST", "/scans", {
        "connection": connection_info, "score": score_info, "update_id": update_id,
        "separate": separate,
    }))


def list_scans(user_id=None):
    return _ok(_call("GET", "/scans"))


def get_scan(scan_id, user_id=None):
    return _ok(_call("GET", f"/scans/{scan_id}"))


def delete_scan(scan_id, user_id=None):
    return _ok(_call("DELETE", f"/scans/{scan_id}"))["deleted"]


def delete_all_scans(user_id=None):
    return _ok(_call("DELETE", "/scans"))["deleted"]


def save_device_snapshot(snapshot, user_id=None):
    return _ok(_call("POST", "/devices", {"snapshot": snapshot}))


def latest_device_snapshot(user_id=None):
    return _ok(_call("GET", "/devices/latest"))
