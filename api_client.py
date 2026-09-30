"""Drop-in replacement for database.py: talks to the WISE server."""
import json, os, threading, urllib.error, urllib.request

SERVER_URL = os.environ.get("WISE_SERVER", "http://localhost:8000").rstrip("/")
_token = None
_UNSET = object()


class SessionExpired(RuntimeError):
    pass


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
    global _token
    data = _ok(_call("POST", "/register", {"username": username, "password": password}))
    _token = data["token"]
    return data["user"]


def authenticate_user(username, password):
    global _token
    code, data = _call("POST", "/login", {"username": username, "password": password})
    if code == 401:
        return None
    data = _ok((code, data))
    _token = data["token"]
    return data["user"]


def _revoke_session(token):
    try:
        _call("DELETE", "/logout", token=token)
    except Exception:
        pass


def logout():
    global _token
    token, _token = _token, None
    if token:
        threading.Thread(target=_revoke_session, args=(token,), daemon=True).start()


def save_scan(connection_info, score_info, update_id=None, user_id=None):
    return _ok(_call("POST", "/scans", {"connection": connection_info, "score": score_info, "update_id": update_id}))

def list_scans(user_id=None):
    return _ok(_call("GET", "/scans"))

def get_scan(scan_id, user_id=None):
    return _ok(_call("GET", f"/scans/{scan_id}"))

def delete_scan(scan_id, user_id=None):
    return _ok(_call("DELETE", f"/scans/{scan_id}"))["deleted"]

def delete_all_scans(user_id=None):
    return _ok(_call("DELETE", "/scans"))["deleted"]