import sqlite3
import tempfile
import unittest
import io
import json
import socket
import sys
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
import guest_storage
from channel_recommender import recommend_channel
from fil_scanner import scan as scan_nearby
from security_score import compare_scores, score_connection
from network_audit import analyze_networks


class ScoringTests(unittest.TestCase):
    def test_radio_link_rate_adds_performance_points(self):
        base = {"ssid": "Home", "authentication": "WPA2", "cipher": "CCMP", "signal_percent": 80}
        without_rate = score_connection(base)
        with_rate = score_connection({**base, "receive_rate_mbps": 300, "transmit_rate_mbps": 300})
        self.assertEqual(with_rate["performance"] - without_rate["performance"], 4)

    def test_wpa3_maximum_50_30_20_score(self):
        score = score_connection(
            {"ssid": "Home Secure", "authentication": "WPA3-Personal", "cipher": "CCMP",
             "signal_percent": 95, "receive_rate_mbps": 300, "transmit_rate_mbps": 300,
             "analysis": {"channel_status": "Recommended"}},
            password_policy_ok=True,
            router_admin_password_ok=True,
            performance_metrics={
                "ping": {"latency_ms": 18, "packet_loss_percent": 0},
                "dns": {"resolution_ms": 25},
                "speed": {"download_mbps": 150},
            },
        )
        self.assertEqual((score["security"], score["performance"], score["configuration"], score["total"]),
                         (50, 30, 20, 100))

    def test_suspected_rogue_ap_reduces_security_score(self):
        connection = {
            "ssid": "Home Secure", "authentication": "WPA3-Personal", "cipher": "CCMP",
            "signal_percent": 95, "rogue_ap_suspected": True,
        }
        score = score_connection(connection)
        self.assertEqual(score["rogue_ap_penalty"], 15)
        self.assertEqual(score["security"], 35)

    def test_open_network_receives_no_protocol_points(self):
        score = score_connection({"authentication": "Open", "cipher": "None", "signal_percent": 0})
        self.assertEqual(score["security"], 0)

    def test_score_comparison(self):
        result = compare_scores({"total": 40}, {"total": 55})
        self.assertEqual(result["change"], 15)
        self.assertIn("Improved", result["label"])


class ChannelTests(unittest.TestCase):
    def test_connected_channel_status_uses_netsh_channel_without_nearby_data(self):
        from app import WiseApp

        self.assertEqual(WiseApp._connected_channel_status({"channel": 6}), "Recommended")
        self.assertEqual(WiseApp._connected_channel_status({"channel": 36}), "Good")
        self.assertEqual(WiseApp._connected_channel_status({"channel": 200}), "Excellent")
        self.assertEqual(WiseApp._connected_channel_status({"channel": 20}), "Unknown")

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

    def test_connected_ap_is_excluded_from_channel_congestion(self):
        result = recommend_channel([
            {"ssid": "Home", "bssid": "own", "band": "2.4 GHz", "channel": 1, "quality": 100},
            {"ssid": "Other", "bssid": "peer", "band": "2.4 GHz", "channel": 6, "quality": 40},
        ], connected_bssid="own")
        self.assertEqual(result["channel_scores"][1], 0)
        self.assertEqual(result["recommended_channel"], 1)

    def test_channel_advice_compares_actual_congestion_and_is_connected_only(self):
        from recommendations import get_channel_recommendation

        environment = {"recommended_channel": 6, "channel_scores": {1: 250, 6: 40, 11: 100}}
        network = {"channel": 1, "channel_status": "Recommended"}
        advice = get_channel_recommendation(network, environment, is_connected=True)
        self.assertIn("channel 6", advice[0])
        self.assertEqual(get_channel_recommendation(network, environment, is_connected=False), [])


class NetworkAuditTests(unittest.TestCase):
    def test_flags_weak_duplicate_ssid_as_possible_rogue_ap(self):
        networks = [
            {"ssid": "Office", "bssid": "00:00:00:00:00:01", "security_status": "Secure"},
            {"ssid": "Office", "bssid": "00:00:00:00:00:02", "security_status": "Unsecured"},
        ]
        analyze_networks(networks)
        self.assertTrue(networks[1]["rogue_ap_suspected"])

    def test_identifies_default_and_hidden_ssid_hygiene(self):
        networks = [
            {"ssid": "NETGEAR-Setup", "bssid": "00:00:00:00:00:01", "security_status": "Secure"},
            {"ssid": "<Hidden>", "bssid": "00:00:00:00:00:02", "security_status": "Secure"},
        ]
        analyze_networks(networks)
        self.assertTrue(networks[0]["ssid_hygiene"]["default_name"])
        self.assertTrue(networks[1]["ssid_hygiene"]["hidden"])
        self.assertTrue(networks[0]["configuration_recommendations"])


class PerformanceTests(unittest.TestCase):
    def test_quick_performance_check_skips_speed_test(self):
        from performance_tests import measure_performance

        with patch("performance_tests.measure_ping", return_value={"latency_ms": 20}), \
             patch("performance_tests.measure_dns", return_value={"resolution_ms": 30}), \
             patch("performance_tests.measure_speed") as speed_test:
            result = measure_performance(include_speed_test=False)
        speed_test.assert_not_called()
        self.assertIsNone(result["speed"])

    def test_ping_reports_latency_and_packet_loss(self):
        result = SimpleNamespace(stdout="Reply time=10ms\nReply time=30ms\n", returncode=0)
        with patch("performance_tests.subprocess.run", return_value=result):
            from performance_tests import measure_ping
            measured = measure_ping(count=4)
        self.assertEqual(measured["latency_ms"], 20)
        self.assertEqual(measured["packet_loss_percent"], 50)

    def test_performance_recommendations_explain_slow_measurements(self):
        from performance_tests import get_performance_recommendations

        recommendations = get_performance_recommendations({
            "ping": {"latency_ms": 180, "packet_loss_percent": 10},
            "dns": {"resolution_ms": 260},
            "speed": {"download_mbps": 10},
        })
        self.assertEqual(len(recommendations), 4)

    def test_speed_test_failure_keeps_ping_and_dns_measurements(self):
        from performance_tests import measure_performance

        with patch("performance_tests.measure_ping", return_value={"latency_ms": 20, "packet_loss_percent": 0}), \
             patch("performance_tests.measure_dns", return_value={"resolution_ms": 30}), \
             patch("performance_tests.measure_speed", side_effect=RuntimeError("offline")):
            result = measure_performance(include_speed_test=True)
        self.assertEqual(result["ping"]["latency_ms"], 20)
        self.assertEqual(result["dns"]["resolution_ms"], 30)
        self.assertIn("offline", result["speed"]["error"])


class DeviceDiscoveryTests(unittest.TestCase):
    def _fake_modules(self, netmask):
        scapy = __import__("types").ModuleType("scapy")
        scapy_all = __import__("types").ModuleType("scapy.all")
        scapy_all.conf = SimpleNamespace(route=SimpleNamespace(
            route=lambda _destination: ("Wi-Fi", "192.168.4.20", "192.168.4.1")
        ))
        psutil = __import__("types").ModuleType("psutil")
        psutil.net_if_addrs = lambda: {"Wi-Fi": [SimpleNamespace(
            family=socket.AF_INET, address="192.168.4.20", netmask=netmask
        )]}
        return {"scapy": scapy, "scapy.all": scapy_all, "psutil": psutil}

    def test_discovery_is_limited_to_connected_subnet(self):
        from device_discovery import _connected_ipv4_network

        with patch.dict(sys.modules, self._fake_modules("255.255.255.0")):
            _interface, local_interface, network, gateway_ip = _connected_ipv4_network()
        self.assertEqual(str(local_interface.ip), "192.168.4.20")
        self.assertEqual(str(network), "192.168.4.0/24")
        self.assertEqual(gateway_ip, "192.168.4.1")

    def test_discovery_rejects_subnets_larger_than_limit(self):
        from device_discovery import _connected_ipv4_network

        with patch.dict(sys.modules, self._fake_modules("255.255.0.0")):
            with self.assertRaisesRegex(RuntimeError, "limited to"):
                _connected_ipv4_network()


class ReportingTests(unittest.TestCase):
    def test_reportlab_exports_a_pdf(self):
        from reporting import export_pdf

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assessment.pdf"
            export_pdf(
                str(path),
                                {"ssid": "Test Wi-Fi", "authentication": "WPA2", "cipher": "CCMP", "signal_percent": 85,
                                 "channel": 6, "channel_status": "Recommended", "radio_type": "802.11ax",
                                 "receive_rate_mbps": 300, "transmit_rate_mbps": 240,
                                 "performance_metrics": {"ping": {"latency_ms": 20, "packet_loss_percent": 0},
                                                                                    "dns": {"resolution_ms": 30}},
                                 "performance_recommendations": ["Measured latency is low."],
                                 "channel_advice": ["Keep the current channel."],
                                 "nearby_networks": []},
                {"total": 80, "breakdown": [
                    {"category": "Security", "earned": 45, "possible": 50, "note": "WPA2 with CCMP"}
                ]},
                                [{"ssid": "Test Wi-Fi", "bssid": "aa:bb", "rogue_ap_suspected": True,
                                    "ssid_hygiene": {"findings": ["Possible rogue AP"]}}],
                                score_change="Improved by 5 points",
                                device_snapshot={"scanned_at": "now", "subnet": "192.168.1.0/24", "gateway_ip": "192.168.1.1",
                                                                 "devices": [{"ip": "192.168.1.1", "mac": "aa:bb", "is_gateway": True,
                                                                                            "is_new": False, "is_local": False}]},
            )
            self.assertTrue(path.read_bytes().startswith(b"%PDF-"))


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

    def test_netsh_scan_failure_is_actionable(self):
        failure = SimpleNamespace(returncode=1, stdout="", stderr="WLAN AutoConfig is unavailable")
        with patch("checknetwork.subprocess.run", return_value=failure):
            with self.assertRaisesRegex(RuntimeError, "WLAN AutoConfig"):
                checknetwork.scan_network()

    def test_adapter_scan_returns_results_after_requesting_a_scan(self):
        second = SimpleNamespace(returncode=0, stdout="SSID 1 : Lab\n Authentication : WPA2-Personal\n BSSID 1 : aa:bb\n Signal : 90%\n Channel : 6\n", stderr="")
        with patch("checknetwork.request_wlan_scan"), \
             patch("checknetwork.subprocess.run", side_effect=(second, second, second)) as run, \
             patch("checknetwork.time.sleep") as sleep:
            networks = checknetwork.scan_network()
        self.assertEqual(len(networks), 1)
        self.assertEqual(networks[0]["ssid"], "Lab")
        self.assertEqual(run.call_count, 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [5.0, 1.0, 1.0])

    def test_scan_ignores_first_cached_read_and_waits_before_fresh_read(self):
        fresh = SimpleNamespace(returncode=0, stdout="SSID 1 : Fresh\n BSSID 1 : cc:dd\n Channel : 36\n", stderr="")
        with patch("checknetwork.request_wlan_scan"), \
             patch("checknetwork.subprocess.run", side_effect=(fresh, fresh, fresh)), \
             patch("checknetwork.time.sleep") as sleep:
            networks = checknetwork.scan_network(wait_seconds=1)
        self.assertEqual([network["ssid"] for network in networks], ["Fresh"])
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [5.0, 1.0, 1.0])

    def test_netsh_parser_detects_wpa3_enterprise_and_multiple_bssids(self):
        output = """SSID 1 : Example
    Authentication : WPA3-Personal
    Encryption : CCMP
    BSSID 1 : aa:bb:cc:dd:ee:01
        Signal : 88%
        Radio type : 802.11ax
        Channel : 36
    BSSID 2 : aa:bb:cc:dd:ee:02
        Signal : 45%
        Radio type : 802.11ac
        Channel : 11
SSID 2 : Enterprise
    Authentication : WPA2-Enterprise
    Encryption : CCMP
    BSSID 1 : aa:bb:cc:dd:ee:03
        Signal : 60%
        Channel : 6
"""
        networks = checknetwork.parse_nearby_networks(output)
        self.assertEqual([network["authentication"] for network in networks],
                         ["WPA3-Personal", "WPA3-Personal", "WPA2-Enterprise"])
        self.assertEqual([network["band"] for network in networks], ["5 GHz", "2.4 GHz", "2.4 GHz"])

    def test_nearby_scan_normalizes_and_deduplicates_access_points(self):
        one = {
            "ssid": " Lab ", "authentication": "WPA2-Personal", "frequency": 2412,
            "bssid": "AA:BB", "signal_percent": 90,
        }
        duplicate = {
            "ssid": "Lab", "authentication": "WPA2-Personal", "frequency": 2412,
            "bssid": "aa:bb", "signal_percent": 70,
        }
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

    def test_password_change_and_account_delete_require_current_password(self):
        user = database.register_user("lifecycle.user", "original password")
        with self.assertRaisesRegex(ValueError, "Current password"):
            database.change_user_password(user["id"], "wrong password", "new password")
        database.change_user_password(user["id"], "original password", "new password")
        self.assertIsNone(database.authenticate_user("lifecycle.user", "original password"))
        self.assertEqual(database.authenticate_user("lifecycle.user", "new password"), user)
        with self.assertRaisesRegex(ValueError, "Password is incorrect"):
            database.delete_user(user["id"], "wrong password")
        self.assertTrue(database.delete_user(user["id"], "new password"))
        self.assertIsNone(database.get_user(user["id"]))

    def test_device_snapshots_mark_first_seen_macs(self):
        user = database.register_user("device.user", "device password")
        database.save_device_snapshot(user["id"], {
            "interface": "Wi-Fi", "subnet": "192.168.1.0/24", "gateway_ip": "192.168.1.1",
            "devices": [{"ip": "192.168.1.2", "mac": "aa:bb", "is_gateway": False}],
        })
        saved = database.save_device_snapshot(user["id"], {
            "interface": "Wi-Fi", "subnet": "192.168.1.0/24", "gateway_ip": "192.168.1.1",
            "devices": [{"ip": "192.168.1.1", "mac": "cc:dd", "is_gateway": True},
                        {"ip": "192.168.1.2", "mac": "AA:BB", "is_gateway": False}],
        })
        self.assertFalse(database.latest_device_snapshot(user["id"])["devices"][1]["is_new"])
        self.assertTrue(saved["devices"][0]["is_new"])
        self.assertFalse(saved["devices"][1]["is_new"])
        latest = database.latest_device_snapshot(user["id"])
        self.assertEqual(latest["gateway_ip"], "192.168.1.1")

    def test_postgres_unique_violation_is_recognized(self):
        class UniqueViolation(Exception):
            sqlstate = "23505"

        self.assertTrue(database._is_username_conflict(UniqueViolation()))

    def test_save_update_read_and_delete_history(self):
        connection_info = {"ssid": "Office Wi-Fi", "authentication": "WPA2-Personal"}
        first = database.save_scan(connection_info, self._score(60))
        second = database.save_scan(connection_info, self._score(70), update_id=None)
        self.assertEqual(second["previous"]["score"], 60)
        self.assertEqual(len(database.list_scans()), 1)

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
        self.assertEqual(len(database.list_scans()), 1)

        self.assertTrue(database.delete_scan(first["id"]))
        self.assertEqual(database.delete_all_scans(), 0)
        self.assertEqual(database.list_scans(), [])

    def test_same_network_updates_by_default_and_can_be_saved_individually(self):
        info = {"ssid": "Repeat Wi-Fi", "authentication": "WPA2-Personal"}
        first = database.save_scan(info, self._score(60))
        updated = database.save_scan(info, self._score(70))
        self.assertTrue(updated["updated"])
        self.assertEqual(updated["id"], first["id"])
        self.assertEqual(updated["previous"]["score"], 60)
        self.assertEqual(len(database.list_scans()), 1)

        separate = database.save_scan(info, self._score(80), separate=True)
        self.assertNotEqual(separate["id"], first["id"])
        self.assertEqual(separate["previous"]["score"], 70)
        self.assertEqual(len(database.list_scans()), 2)

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


class GuestStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_path = guest_storage.DATABASE_PATH
        guest_storage.DATABASE_PATH = Path(self.temp_dir.name) / "guest_scans.db"
        guest_storage.initialize_database()

    def tearDown(self):
        guest_storage.DATABASE_PATH = self.original_path
        self.temp_dir.cleanup()

    @staticmethod
    def _score(total):
        return {"total": total, "protocol": 40, "company_and_password": 10, "other": total - 50}

    def test_guest_scan_history_persists_and_can_be_managed(self):
        connection = {"ssid": "Guest Wi-Fi", "authentication": "WPA2-Personal"}
        saved = guest_storage.save_scan(connection, self._score(70))
        updated = guest_storage.save_scan(connection, self._score(80))

        self.assertEqual(updated["id"], saved["id"])
        self.assertEqual(updated["previous"]["score"], 70)
        record = guest_storage.get_scan(saved["id"])
        self.assertEqual(record["score"], 80)
        self.assertEqual(record["connection"], connection)
        self.assertEqual(len(guest_storage.list_scans()), 1)
        self.assertTrue(guest_storage.delete_scan(saved["id"]))
        self.assertEqual(guest_storage.delete_all_scans(), 0)

    def test_guest_device_snapshots_persist_locally(self):
        snapshot = {
            "interface": "Wi-Fi", "subnet": "192.168.1.0/24", "gateway_ip": "192.168.1.1",
            "devices": [{"ip": "192.168.1.2", "mac": "aa:bb", "is_gateway": False}],
        }
        guest_storage.save_device_snapshot(snapshot)
        latest = guest_storage.latest_device_snapshot()
        self.assertEqual(latest["subnet"], snapshot["subnet"])
        self.assertEqual(latest["devices"][0]["mac"], "aa:bb")
        self.assertFalse(latest["devices"][0]["is_new"])


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

    def test_session_token_is_memory_only_and_not_restored_through_keyring(self):
        credentials = {}
        keyring = SimpleNamespace(
            set_password=lambda service, endpoint, token: credentials.update({(service, endpoint): token}),
            get_password=lambda service, endpoint: credentials.get((service, endpoint)),
            delete_password=lambda service, endpoint: credentials.pop((service, endpoint), None),
        )
        with patch.object(api_client, "_keyring", return_value=keyring):
            api_client._store_token("remembered-token")
            self.assertNotIn(("WISE API session", api_client.SERVER_URL), credentials)
            api_client._token = None
            with patch.object(api_client, "_call") as call:
                self.assertIsNone(api_client.restore_session())
                call.assert_not_called()


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

    def test_session_route_restores_signed_in_user(self):
        handler = self._handler("/session", {})
        handler.command = "GET"
        with patch.object(self.server.database, "get_session_user_id", return_value=17), \
             patch.object(self.server.database, "get_user", return_value={"id": 17, "username": "restored"}):
            handler._handle()
        self.assertEqual(handler._send.call_args.args, (200, {"user": {"id": 17, "username": "restored"}}))

    def test_password_and_account_routes(self):
        user = database.register_user("route.user", "old password")
        token = "route-session"
        database.create_session(token, user["id"])
        with patch.object(self.server.database, "get_session_user_id", return_value=user["id"]):
            handler = self._handler("/password", {
                "current_password": "old password", "new_password": "new password",
            })
            handler._handle()
            self.assertEqual(handler._send.call_args.args[0], 200)
            self.assertEqual(database.authenticate_user("route.user", "new password"), user)

            delete_handler = self._handler("/account", {"password": "new password"})
            delete_handler.command = "DELETE"
            delete_handler._handle()
            self.assertEqual(delete_handler._send.call_args.args[0], 200)
        self.assertIsNone(database.get_user(user["id"]))

    def test_device_snapshot_routes_are_account_scoped(self):
        user = database.register_user("route.device", "device password")
        snapshot = {"interface": "Wi-Fi", "subnet": "192.168.0.0/24", "gateway_ip": "192.168.0.1",
                    "devices": [{"ip": "192.168.0.1", "mac": "aa:bb", "is_gateway": True}]}
        with patch.object(self.server.database, "get_session_user_id", return_value=user["id"]):
            save_handler = self._handler("/devices", {"snapshot": snapshot})
            save_handler._handle()
            self.assertEqual(save_handler._send.call_args.args[0], 200)

            get_handler = self._handler("/devices/latest", {})
            get_handler.command = "GET"
            get_handler._handle()
            self.assertEqual(get_handler._send.call_args.args[1]["gateway_ip"], "192.168.0.1")


if __name__ == "__main__":
    unittest.main()
