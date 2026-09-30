"""Nearby Wi-Fi scanner using the Windows WLAN service and netsh output."""

import ctypes
import ctypes.wintypes
import re
import subprocess
import time


_FIELD = re.compile(r"^\s*([^:]+?)\s*:\s*(.*?)\s*$")
_SSID_KEY = re.compile(r"^ssid\s+\d+$", re.IGNORECASE)
_BSSID_KEY = re.compile(r"^bssid\s+\d+$", re.IGNORECASE)


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.wintypes.DWORD), ("Data2", ctypes.wintypes.WORD),
                ("Data3", ctypes.wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


class _WlanInterfaceInfo(ctypes.Structure):
    _fields_ = [("InterfaceGuid", _GUID), ("strInterfaceDescription", ctypes.wintypes.WCHAR * 256),
                ("isState", ctypes.wintypes.DWORD)]


class _WlanInterfaceInfoList(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", ctypes.wintypes.DWORD), ("dwIndex", ctypes.wintypes.DWORD),
                ("InterfaceInfo", _WlanInterfaceInfo * 1)]


def request_wlan_scan():
    """Ask the Windows WLAN service to scan instead of reading only its cache."""
    try:
        wlanapi = ctypes.WinDLL("wlanapi.dll")
    except (AttributeError, OSError) as error:
        raise RuntimeError(f"Could not access the Windows WLAN scan API: {error}") from error

    handle = ctypes.wintypes.HANDLE()
    negotiated_version = ctypes.wintypes.DWORD()
    open_handle = wlanapi.WlanOpenHandle
    open_handle.argtypes = [ctypes.wintypes.DWORD, ctypes.c_void_p,
                            ctypes.POINTER(ctypes.wintypes.DWORD),
                            ctypes.POINTER(ctypes.wintypes.HANDLE)]
    open_handle.restype = ctypes.wintypes.DWORD
    result = open_handle(2, None, ctypes.byref(negotiated_version), ctypes.byref(handle))
    if result:
        raise RuntimeError(f"Windows could not open its Wi-Fi scan service (error {result}).")

    interface_list = ctypes.POINTER(_WlanInterfaceInfoList)()
    enum_interfaces = wlanapi.WlanEnumInterfaces
    enum_interfaces.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p,
                                ctypes.POINTER(ctypes.POINTER(_WlanInterfaceInfoList))]
    enum_interfaces.restype = ctypes.wintypes.DWORD
    scan = wlanapi.WlanScan
    scan.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(_GUID), ctypes.c_void_p,
                     ctypes.c_void_p, ctypes.c_void_p]
    scan.restype = ctypes.wintypes.DWORD
    free_memory = wlanapi.WlanFreeMemory
    free_memory.argtypes = [ctypes.c_void_p]
    close_handle = wlanapi.WlanCloseHandle
    close_handle.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p]
    close_handle.restype = ctypes.wintypes.DWORD

    try:
        result = enum_interfaces(handle, None, ctypes.byref(interface_list))
        if result:
            raise RuntimeError(f"Windows could not list Wi-Fi adapters (error {result}).")
        if not interface_list or interface_list.contents.dwNumberOfItems == 0:
            raise RuntimeError("Windows did not report an available Wi-Fi adapter.")

        info_list_address = ctypes.addressof(interface_list.contents)
        info_offset = _WlanInterfaceInfoList.InterfaceInfo.offset
        for index in range(interface_list.contents.dwNumberOfItems):
            info_address = info_list_address + info_offset + index * ctypes.sizeof(_WlanInterfaceInfo)
            interface = ctypes.cast(info_address, ctypes.POINTER(_WlanInterfaceInfo)).contents
            if interface.isState == 0:  # wlan_interface_state_not_ready
                continue
            result = scan(handle, ctypes.byref(interface.InterfaceGuid), None, None, None)
            if result == 5:
                raise RuntimeError(
                    "Windows blocked the fresh Wi-Fi scan. Allow WISE to access location in "
                    "Settings > Privacy & security > Location, then scan again."
                )
            if result:
                raise RuntimeError(f"Windows could not start a fresh Wi-Fi scan (error {result}).")
            return
        raise RuntimeError("Windows did not report a ready Wi-Fi adapter to scan.")
    finally:
        if interface_list:
            free_memory(interface_list)
        close_handle(handle, None)


def _number(value):
    match = re.search(r"\d+", str(value or ""))
    return int(match.group()) if match else None


def _channel_band_frequency(channel):
    if channel is None:
        return "Unknown", None
    if 1 <= channel <= 14:
        return "2.4 GHz", 2484 if channel == 14 else 2407 + channel * 5
    if 32 <= channel <= 177:
        return "5 GHz", 5000 + channel * 5
    if 178 <= channel <= 233:
        return "6 GHz", 5950 + channel * 5
    return "Unknown", None


def parse_nearby_networks(output):
    """Parse netsh's SSID/BSSID blocks into normalized network dictionaries."""
    networks = []
    ssid_fields = {}
    current = None

    def finish(record):
        if not record:
            return
        ssid = str(record.get("ssid") or "").strip() or "<Hidden>"
        channel = record.get("channel")
        band, frequency = _channel_band_frequency(channel)
        networks.append({
            "ssid": ssid,
            "bssid": str(record.get("bssid", "")).strip().casefold().rstrip(":"),
            "authentication": record.get("authentication", "Unknown"),
            "encryption": record.get("authentication", "Unknown"),
            "cipher": record.get("encryption", "Unknown"),
            "network_type": record.get("network type", "Unknown"),
            "radio_type": record.get("radio type", "Unknown"),
            "signal_percent": record.get("signal_percent"),
            "quality": record.get("signal_percent") or 0,
            "signal": None,
            "rssi": None,
            "channel": channel if channel is not None else "Unknown",
            "band": band,
            "frequency": frequency,
        })

    for line in output.splitlines():
        match = _FIELD.match(line)
        if not match:
            continue
        key, value = match.groups()
        key = key.strip().casefold()

        if _SSID_KEY.fullmatch(key):
            finish(current)
            current = None
            ssid_fields = {"ssid": value.strip()}
            continue
        if _BSSID_KEY.fullmatch(key):
            finish(current)
            current = {**ssid_fields, "bssid": value.strip()}
            continue

        target = current if current is not None else ssid_fields
        if key in ("network type", "authentication", "encryption", "radio type"):
            target[key] = value.strip()
        elif key == "channel":
            target["channel"] = _number(value)
        elif key == "signal":
            target["signal_percent"] = _number(value)

    finish(current)
    if not networks and ssid_fields.get("ssid"):
        finish(ssid_fields)
    return networks


def _run_netsh():
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
        )
    except OSError as error:
        raise RuntimeError(f"Could not run Windows netsh Wi-Fi scan: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(detail or "Windows could not scan nearby Wi-Fi networks.")
    return result.stdout


def scan_network(wait_seconds=3.5):
    """Return the richest of several fresh WLAN snapshots.

    Windows can update its visible-network list in stages. Taking several
    snapshots after the initial wait avoids showing only the connected AP
    when the first refreshed result is incomplete.
    """
    request_wlan_scan()
    last_error = None
    time.sleep(max(5.0, wait_seconds))
    best = []
    for attempt in range(3):
        try:
            networks = parse_nearby_networks(_run_netsh())
            if len(networks) >= len(best):
                best = networks
        except RuntimeError as error:
            last_error = error
        if attempt < 2:
            time.sleep(1.0)
    if not best and last_error:
        raise last_error
    return best
