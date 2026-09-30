"""WISE API server. Run on the machine that holds the database."""
import json, os, secrets, ssl, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import database

database.initialize_database()
FAILS = {}      # (client address, username) -> (failed_count, locked_until)
MAX_REQUEST_BYTES = 1024 * 1024


class RequestTooLarge(Exception):
    pass


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError as error:
            raise ValueError("Invalid Content-Length header.") from error
        if length < 0:
            raise ValueError("Invalid Content-Length header.")
        if length > MAX_REQUEST_BYTES:
            raise RequestTooLarge()
        raw_body = self.rfile.read(length)
        if len(raw_body) != length:
            raise ValueError("Request body ended before Content-Length bytes were received.")
        try:
            data = json.loads(raw_body or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ValueError("Request body must contain valid JSON.") from error
        if not isinstance(data, dict):
            raise ValueError("Request JSON must be an object.")
        return data

    def _handle(self):
        try:
            self._route()
        except RequestTooLarge:
            self.close_connection = True
            self._send(413, {"error": "Request body exceeds the 1 MiB limit."})
        except ValueError as error:          # bad input, duplicate username, etc.
            self._send(400, {"error": str(error)})
        except Exception as error:
            print("Server error:", error)
            self._send(500, {"error": "Server error"})

    do_GET = do_POST = do_DELETE = _handle

    def _route(self):
        path, method = self.path.split("?")[0].rstrip("/"), self.command

        if method == "POST" and path in ("/register", "/login"):
            data = self._body()
            name, password = str(data.get("username", "")), str(data.get("password", ""))
            if path == "/register":
                user = database.register_user(name, password)
            else:
                key = (self.client_address[0], name.strip().casefold())
                count, locked_until = FAILS.get(key, (0, 0))
                if time.time() < locked_until:
                    return self._send(429, {"error": "Too many attempts. Try again in a minute."})
                user = database.authenticate_user(name, password)
                if user is None:
                    FAILS[key] = (count + 1, time.time() + 60 if count + 1 >= 5 else 0)
                    return self._send(401, {"error": "Username or password is incorrect."})
                FAILS.pop(key, None)
            token = secrets.token_urlsafe(32)
            database.create_session(token, user["id"])
            return self._send(200, {"token": token, "user": user})

        token = self.headers.get("Authorization", "").removeprefix("Bearer ")
        uid = database.get_session_user_id(token)
        if uid is None:
            return self._send(401, {"error": "Session expired. Please log in again."})
        if method == "DELETE" and path == "/logout":
            database.delete_session(token)
            return self._send(200, {"logged_out": True})
        parts = path.strip("/").split("/")
        if parts[0] != "scans":
            return self._send(404, {"error": "Not found"})

        if method == "GET":
            return self._send(200, database.list_scans(uid) if len(parts) == 1
                              else database.get_scan(int(parts[1]), uid))
        if method == "POST":
            data = self._body()
            required_score_fields = {"total", "protocol", "company_and_password", "other"}
            if not isinstance(data.get("connection"), dict):
                raise ValueError("Request must include a connection object.")
            if not isinstance(data.get("score"), dict) or not required_score_fields.issubset(data["score"]):
                raise ValueError("Request must include a complete score object.")
            return self._send(200, database.save_scan(
                data["connection"], data["score"], data.get("update_id"), uid))
        if method == "DELETE":
            done = (database.delete_all_scans(uid) if len(parts) == 1
                    else database.delete_scan(int(parts[1]), uid))
            return self._send(200, {"deleted": done})


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", 8000))), Handler)
    if os.environ.get("TLS_CERT"):   # optional built-in HTTPS
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(os.environ["TLS_CERT"], os.environ["TLS_KEY"])
        server.socket = context.wrap_socket(server.socket, server_side=True)
    print("WISE server running...")
    server.serve_forever()