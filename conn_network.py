"""Read the Windows Wi-Fi connection currently in use."""

import re
import subprocess


def _number(value):
    match = re.search(r"-?\d+", str(value or ""))
    return int(match.group()) if match else None


def connected_wifi():
    """Return connection details from ``netsh`` or raise a helpful error."""
    result = subprocess.run(
        ["netsh", "wlan", "show", "interfaces"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(detail or "Windows could not read Wi-Fi interface details.")

    interfaces = []
    current = {}
    for line in result.stdout.splitlines():
        match = re.match(r"\s*([^:]+?)\s*:\s*(.*?)\s*$", line)
        if not match:
            continue
        key, value = match.groups()
        key = key.strip().casefold()
        if key == "name" and current:
            interfaces.append(current)
            current = {}
        current[key] = value.strip()
    if current:
        interfaces.append(current)

    connected = next(
        (item for item in interfaces if item.get("state", "").casefold() == "connected"),
        None,
    )
    if connected is None:
        raise RuntimeError("No connected Wi-Fi network was found. Connect to Wi-Fi and scan again.")

    channel = _number(connected.get("channel"))
    signal = _number(connected.get("signal"))

    return {
        "ssid": connected.get("ssid") or "<Hidden>",
        "interface": connected.get("name", "Unknown"),
        "state": connected.get("state", "Unknown"),
        "profile": connected.get("profile", "Unknown"),
        "bssid": connected.get("bssid", "Unknown"),
        "authentication": connected.get("authentication", "Unknown"),
        "cipher": connected.get("cipher", "Unknown"),
        "signal_percent": signal,
        "channel": channel,
        "radio_type": connected.get("radio type", "Unknown"),
        "receive_rate_mbps": _number(connected.get("receive rate (Mbps)")),
        "transmit_rate_mbps": _number(connected.get("transmit rate (Mbps)")),
        "network_type": connected.get("network type", "Unknown"),
    }
