import checknetwork


def get_encryption(akm):
    value = str(akm or "").strip().upper()
    if "OPEN" in value or value in ("NONE", "NO AUTHENTICATION"):
        return "Open"
    for protocol in ("WPA3", "WPA2", "WPA", "WEP"):
        if protocol in value:
            return protocol
    return "Unknown"


def normalize_frequency(freq):
    if freq is None:
        return None
    freq = int(freq)
    if freq > 100000:
        freq = freq // 1000
    return freq


def get_band(freq):
    if freq is None:
        return "Unknown"
    if 2400 <= freq <= 2500:
        return "2.4 GHz"

    elif 5000 <= freq <= 5900:
        return "5 GHz"

    elif 5925 <= freq <= 7125:
        return "6 GHz"

    return "Unknown"


def get_channel(freq):
    if freq is None:
        return "Unknown"

    # 2.4 GHz channels
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5

    elif freq == 2484:
        return 14

    # 5 GHz channels
    elif 5000 <= freq <= 5900:
        return (freq - 5000) // 5

    # 6 GHz channels
    elif 5955 <= freq <= 7115:
        return (freq - 5950) // 5

    return "Unknown"


def signal_quality(dbm):
    if dbm is None:
        return 0
    quality = 2 * (dbm + 100)

    if quality > 100:
        quality = 100

    elif quality < 0:
        quality = 0

    return quality


def scan():
    results = checknetwork.scan_network()
    networks_by_bssid = {}
    for network in results:
        if isinstance(network, dict):
            source = network
        else:
            source = {
                "ssid": getattr(network, "ssid", ""),
                "bssid": getattr(network, "bssid", ""),
                "signal": getattr(network, "signal", None),
                "frequency": getattr(network, "freq", None),
                "akm": getattr(network, "authentication", ""),
            }

        ssid = str(source.get("ssid", "") or "").strip()
        if ssid == "":
            ssid = "<Hidden>"
        authentication = source.get("authentication") or source.get("akm") or source.get("encryption")
        encryption = get_encryption(authentication)
        freq = normalize_frequency(source.get("frequency", source.get("freq")))
        raw_channel = source.get("channel")
        channel = raw_channel if isinstance(raw_channel, int) else get_channel(freq)
        band = source.get("band") or get_band(freq)
        if band == "Unknown" and isinstance(channel, int):
            band = "2.4 GHz" if channel <= 14 else "6 GHz" if channel >= 178 else "5 GHz" if channel <= 177 else "Unknown"
        bssid = str(source.get("bssid", "") or "").strip().casefold().rstrip(":")
        signal = source.get("signal")
        signal_percent = source.get("signal_percent")
        quality = source.get("quality")
        if quality is None:
            quality = signal_percent if signal_percent is not None else signal_quality(signal)
        network_info = {
            "ssid": ssid,
            "bssid": bssid,
            "signal": signal,
            "quality": quality,
            "encryption": encryption,
            "authentication": str(authentication or "Unknown"),
            "cipher": source.get("cipher", "Unknown"),
            "signal_percent": signal_percent,
            "frequency": freq,
            "band": band,
            "channel": channel,
            "radio_type": source.get("radio_type", "Unknown"),
            "network_type": source.get("network_type", "Unknown"),
        }
        key = bssid or f"{ssid.casefold()}:{freq}"
        if key not in networks_by_bssid:
            networks_by_bssid[key] = network_info
        elif (signal if signal is not None else -999) > (networks_by_bssid[key]["signal"] or -999):
            networks_by_bssid[key] = network_info
    return list(networks_by_bssid.values())
