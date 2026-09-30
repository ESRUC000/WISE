import sqlite3
import tempfile
import unittest
import io
import json
from urllib.error import HTTPError
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import checknetwork
import conn_network
import database
import analyzer
import api_client
from channel_recommender import recommend_channel
from fil_scanner import scan as scan_nearby
from pywifi import const
from security_score import compare_scores, score_connection


class ScoringTests(unittest.TestCase):
    def test_wpa3_maximum_score_and_company_answers(self):
        score = score_connection(
            {"authentication": "WPA3-Personal", "cipher": "CCMP", "signal_percent": 95},
            company_network=False,
            password_policy_ok=True,
        )
        self.assertEqual((score["protocol"], score["company_and_password"], score["other"], score["total"]),
                         (60, 20, 20, 100))

    def test_open_network_receives_no_protocol_points(self):
        score = score_connection({"authentication": "Open", "cipher": "None", "signal_percent": 0})
        self.assertEqual((score["protocol"], score["total"]), (0, 0))

    def test_score_comparison(self):
        result = compare_scores({"total": 40}, {"total": 55})
        self.assertEqual(result["change"], 15)
        self.assertIn("Improved", result["label"])


class ChannelTests(unittest.TestCase):
    def test_unknown_channel_is_safe_for_every_band(self):
        from channel_check import get_channel_status

        for band in ("2.4 GHz", "5 GHz", "6 GHz"):
            with self.subTest(band=band):
                self.assertEqual(get_channel_status(band, "Unknown"), "Unknown")

    def test_no_2_4_ghz_measurements_do_not_claim_low_congestion(self):
        result = recommend_channel([])
        self.assertIsNone(result["recommended_channel"])
        self.assertEqual(result["status"], "No 2.4 GHz data")

    def test_recommendation_chooses_lowest_interference(self):
        result = recommend_channel([
            {"band": "2.4 GHz", "channel": 1, "quality": 90},
            {"band": "2.4 GHz", "channel": 6, "quality": 20},
        ])
        self.assertEqual(result["recommended_channel"], 11)


class NetworkParsingTests(unittest.TestCase):
    def test_connected_interface_fields_are_normalized(self):
        output = """There is 1 interface on the system:

    Name                   : Wi-Fi
    State                  : connected
    SSID                   : Example Wi-Fi
    BSSID                  : 01:23:45:67:89:ab
    Network type           : Infrastructure
    Radio type             : 802.11ax
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Channel                : 11
    Receive rate (Mbps)    : 72
    Transmit rate (Mbps)   : 72
    Signal                 : 95%
    RSSI                   : -48 dBm
    Profile                : Example Wi-Fi
"""
        completed = SimpleNamespace(returncode=0, stdout=output, stderr="")
        with patch("conn_network.subprocess.run", return_value=completed):
            info = conn_network.connected_wifi()
        self.assertEqual(info["interface"], "Wi-Fi")
        self.assertEqual(info["state"], "connected")
        self.assertEqual(info["ssid"], "Example Wi-Fi")
        self.assertEqual(info["signal_percent"], 95)
        self.assertEqual(info["channel"], 11)
        self.assertEqual(info["receive_rate_mbps"], 72)
        self.assertEqual(info["transmit_rate_mbps"], 72)
        self.assertEqual(info["rssi"], -48)

    def test_disconnected_machine_returns_actionable_error(self):
        completed = SimpleNamespace(returncode=0, stdout="There is 1 interface on the system:\n", stderr="")
        with patch("conn_network.subprocess.run", return_value=completed):
            with self.assertRaisesRegex(RuntimeError, "No connected Wi-Fi"):
                conn_network.connected_wifi()

    def test_no_adapter_is_a_runtime_error_not_an_import_error(self):
        with patch("checknetwork.PyWiFi") as wifi_factory:
            wifi_factory.return_value.interfaces.return_value = []
            with self.assertRaisesRegex(RuntimeError, "No wireless adapter"):
                checknetwork.scan_network(wait_seconds=0)

    def test_adapter_scan_returns_results_after_requesting_a_scan(self):
        interface = SimpleNamespace(scan=Mock(), scan_results=lambda: ["ap"])
        with patch("checknetwork.PyWiFi") as wifi_factory, patch("checknetwork.time.sleep"):
            wifi_factory.return_value.interfaces.return_value = [interface]
            self.assertEqual(checknetwork.scan_network(), ["ap"])
        interface.scan.assert_called_once_with()

    def test_nearby_scan_normalizes_and_deduplicates_access_points(self):
        one = SimpleNamespace(ssid=" Lab ", akm=[const.AKM_TYPE_WPA2PSK], freq=2412000,
                              bssid="AA:BB", signal=-55)
        duplicate = SimpleNamespace(ssid="Lab", akm=[const.AKM_TYPE_WPA2PSK], freq=2412000,
                                    bssid="aa:bb", signal=-70)
        with patch("fil_scanner.checknetwork.scan_network", return_value=[one, duplicate]):
            results = scan_nearby()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ssid"], "Lab")
        self.assertEqual(results[0]["band"], "2.4 GHz")
        self.assertEqual(results[0]["quality"], 90)

    def test_analyzer_wires_security_channel_and_performance_recommendations(self):
        network = {
            "ssid": "Lab", "bssid": "aa:bb", "signal": -55, "quality": 90,
            "encryption": "WPA2", "frequency": 2412, "band": "2.4 GHz", "channel": 1,
        }
        with patch("analyzer.scan", return_value=[network]):
            networks, environment = analyzer.analyze()
        self.assertEqual(environment["status"], "Low Congestion")
        self.assertIn("security_status", networks[0])
        self.assertIn("performance_recommendations", networks[0])
        self.assertIn("channel_advice", networks[0])
        self.assertIn("band_recommendations", networks[0])


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        workspace = Path(__file__).resolve().parents[1]
        self.temp_dir = tempfile.TemporaryDirectory(dir=workspace)
        self.original_path = database.DATABASE_PATH
        database.DATABASE_PATH = Path(self.temp_dir.name) / "wise_scans.db"
        database.initialize_database()

    def tearDown(self):
        database.DATABASE_PATH = self.original_path
        self.temp_dir.cleanup()

    @staticmethod
    def _score(total):
        return {"total": total, "protocol": 48, "company_and_password": 0, "other": total - 48}

    def test_accounts_have_unique_case_insensitive_usernames_and_hashed_passwords(self):
        user = database.register_user("Alice", "correct horse battery")
        self.assertEqual(database.authenticate_user("ALICE", "correct horse battery"), user)
        self.assertIsNone(database.authenticate_user("Alice", "wrong password"))
        with closing(sqlite3.connect(database.DATABASE_PATH)) as connection:
            password_hash = connection.execute(
                "SELECT password_hash FROM users WHERE id = ?", (user["id"],)
            ).fetchone()[0]
        self.assertNotEqual(password_hash, "correct horse battery")
        self.assertTrue(password_hash.startswith("pbkdf2_sha256$"))
        with self.assertRaisesRegex(ValueError, "already registered"):
            database.register_user("aLiCe", "another secure password")

    def test_scan_history_is_scoped_to_its_account(self):
        first_user = database.register_user("first.user", "first secure password")
        second_user = database.register_user("second.user", "second secure password")
        connection_info = {"ssid": "Shared network", "authentication": "WPA2-Personal"}

        first_scan = database.save_scan(connection_info, self._score(60), user_id=first_user["id"])
        second_scan = database.save_scan(connection_info, self._score(70), user_id=second_user["id"])

        self.assertIsNone(second_scan["previous"])
        self.assertEqual([row["id"] for row in database.list_scans(first_user["id"])], [first_scan["id"]])
        self.assertEqual([row["id"] for row in database.list_scans(second_user["id"])], [second_scan["id"]])
        self.assertIsNone(database.get_scan(first_scan["id"], second_user["id"]))
        self.assertFalse(database.delete_scan(first_scan["id"], second_user["id"]))
        self.assertEqual(database.delete_all_scans(second_user["id"]), 1)
        self.assertEqual(len(database.list_scans(first_user["id"])), 1)

    def test_sessions_persist_as_hashes_and_can_be_revoked(self):
        user = database.register_user("session.user", "session password long")
        token = "opaque-session-token"
        database.create_session(token, user["id"])
        self.assertEqual(database.get_session_user_id(token), user["id"])
        with closing(sqlite3.connect(database.DATABASE_PATH)) as connection:
            token_hash = connection.execute("SELECT token_hash FROM sessions").fetchone()[0]
        self.assertNotEqual(token_hash, token)

        database.delete_session(token)
        self.assertIsNone(database.get_session_user_id(token))
        database.create_session("expired-session-token", user["id"], ttl_seconds=-1)
        self.assertIsNone(database.get_session_user_id("expired-session-token"))

    def test_postgres_unique_violation_is_recognized(self):
        class UniqueViolation(Exception):
            sqlstate = "23505"

        self.assertTrue(database._is_username_conflict(UniqueViolation()))

    def test_save_update_read_and_delete_history(self):
        connection_info = {"ssid": "Office Wi-Fi", "authentication": "WPA2-Personal"}
        first = database.save_scan(connection_info, self._score(60))
        second = database.save_scan(connection_info, self._score(70), update_id=None)
        self.assertEqual(second["previous"]["score"], 60)
        self.assertEqual(len(database.list_scans()), 2)

        connection_info["environment"] = {
            "recommended_channel": 6,
            "status": "Low Congestion",
            "channel_scores": {1: 150, 6: 20, 11: 90},
        }
        updated = database.save_scan(connection_info, self._score(75), update_id=second["id"])
        self.assertTrue(updated["updated"])
        record = database.get_scan(second["id"])
        self.assertEqual(record["score"], 75)
        self.assertEqual(record["environment"]["recommended_channel"], 6)
        self.assertEqual(len(database.list_scans()), 2)

        self.assertTrue(database.delete_scan(first["id"]))
        self.assertEqual(database.delete_all_scans(), 1)
        self.assertEqual(database.list_scans(), [])

    def test_hidden_networks_are_grouped_by_bssid(self):
        first = database.save_scan({"ssid": "<Hidden>", "bssid": "aa:bb"}, self._score(10))
        second = database.save_scan({"ssid": "<Hidden>", "bssid": "cc:dd"}, self._score(20))
        self.assertIsNone(first["previous"])
        self.assertIsNone(second["previous"])

    def test_old_schema_is_upgraded_and_remains_openable(self):
        legacy_path = Path(self.temp_dir.name) / "legacy.db"
        database.DATABASE_PATH = legacy_path
        connection = sqlite3.connect(legacy_path)
        connection.execute(
            "CREATE TABLE scans (id INTEGER PRIMARY KEY, scanned_at TEXT NOT NULL, "
            "ssid TEXT NOT NULL, score INTEGER NOT NULL)"
        )
        connection.execute(
            "INSERT INTO scans (id, scanned_at, ssid, score) VALUES (1, ?, ?, ?)",
            ("2026-01-01T00:00:00+00:00", "Office Wi-Fi", 60),
        )
        connection.commit()
        connection.close()

        database.initialize_database()
        record = database.get_scan(1)
        self.assertEqual(record["network_key"], "ssid:office wi-fi")
        self.assertEqual(record["score_details"]["total"], 60)
        self.assertEqual(len(record["score_details"]["breakdown"]), 3)


class ApiClientTests(unittest.TestCase):
    def test_non_json_http_error_returns_actionable_response(self):
        error = HTTPError("http://wise", 502, "Bad Gateway", {}, io.BytesIO(b"<html>proxy error</html>"))
        with patch("api_client.urllib.request.urlopen", side_effect=error):
            status, data = api_client._call("GET", "/scans")
        self.assertEqual(status, 502)
        self.assertIn("non-JSON", data["error"])
        error.close()

    def test_logout_clears_token_without_waiting_for_server(self):
        api_client._token = "active-token"
        with patch("api_client.threading.Thread") as thread_factory:
            api_client.logout()
        self.assertIsNone(api_client._token)
        thread_factory.return_value.start.assert_called_once_with()

    def test_unauthorized_response_is_a_session_expiry(self):
        with self.assertRaises(api_client.SessionExpired):
            api_client._ok((401, {"error": "Session expired"}))


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.original_path = database.DATABASE_PATH
        self.temp_dir = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1])
        database.DATABASE_PATH = Path(self.temp_dir.name) / "wise_scans.db"
        database.initialize_database()
        import server
        self.server = server
        self.server.FAILS.clear()

    def tearDown(self):
        self.server.FAILS.clear()
        database.DATABASE_PATH = self.original_path
        self.temp_dir.cleanup()

    def _handler(self, path, body, client_ip="192.0.2.1"):
        handler = object.__new__(self.server.Handler)
        encoded_body = json.dumps(body).encode("utf-8")
        handler.headers = {"Content-Length": str(len(encoded_body)), "Authorization": "Bearer test-token"}
        handler.rfile = io.BytesIO(encoded_body)
        handler.wfile = io.BytesIO()
        handler.close_connection = False
        handler.command = "POST"
        handler.path = path
        handler.client_address = (client_ip, 12345)
        handler._send = Mock()
        return handler

    def test_oversized_request_body_is_rejected(self):
        handler = self._handler("/login", {})
        handler.headers["Content-Length"] = str(self.server.MAX_REQUEST_BYTES + 1)
        handler._handle()
        self.assertEqual(handler._send.call_args.args[0], 413)

    def test_scan_without_connection_or_score_returns_bad_request(self):
        handler = self._handler("/scans", {"score": {"total": 10}})
        with patch.object(self.server.database, "get_session_user_id", return_value=5):
            handler._handle()
        self.assertEqual(handler._send.call_args.args[0], 400)

    def test_failed_login_lockouts_are_scoped_to_client_and_username(self):
        with patch.object(self.server.database, "authenticate_user", return_value=None):
            for client_ip in ("192.0.2.1", "192.0.2.2"):
                handler = self._handler("/login", {"username": "target", "password": "wrong"}, client_ip)
                handler.headers.pop("Authorization")
                with patch.object(self.server.database, "create_session"):
                    handler._handle()
        self.assertIn(("192.0.2.1", "target"), self.server.FAILS)
        self.assertIn(("192.0.2.2", "target"), self.server.FAILS)


if __name__ == "__main__":
    unittest.main()
