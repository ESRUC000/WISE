import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import checknetwork
import conn_network
import database
import analyzer
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


if __name__ == "__main__":
    unittest.main()
