"""Thin, lazy PyWiFi adapter for scanning nearby access points."""

import time

from pywifi import PyWiFi


def scan_network(wait_seconds=3):
    """Scan nearby networks without touching Wi-Fi hardware at import time."""
    try:
        interfaces = PyWiFi().interfaces()
    except Exception as error:
        raise RuntimeError(f"Could not enumerate wireless adapters: {error}") from error

    if not interfaces:
        raise RuntimeError("No wireless adapter is available for nearby-network scanning.")

    interface = interfaces[0]
    try:
        interface.scan()
        time.sleep(max(0, wait_seconds))
        return interface.scan_results() or []
    except Exception as error:
        raise RuntimeError(f"Nearby Wi-Fi scanning failed: {error}") from error



