import checknetwork
from pywifi import const


def get_encryption(akm):
    security = []
    akm = set(akm or ())

    if const.AKM_TYPE_NONE in akm:
        security.append("Open")

    if const.AKM_TYPE_WPAPSK in akm:
        security.append("WPA")

    if const.AKM_TYPE_WPA2PSK in akm:
        security.append("WPA2")

    if hasattr(const, "AKM_TYPE_WPA3SAE") and const.AKM_TYPE_WPA3SAE in akm:
        security.append("WPA3")

    if security:
        return "/".join(security)

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

    # Store networks by BSSID (unique MAC address)
    networks_by_bssid = {}

    for network in results:

        # Replace blank SSID with <Hidden>
        ssid = str(getattr(network, "ssid", "") or "").strip()
        if ssid == "":
            ssid = "<Hidden>"

        # Process network information
        encryption = get_encryption(getattr(network, "akm", ()))

        freq = normalize_frequency(getattr(network, "freq", None))

        band = get_band(freq)

        channel = get_channel(freq)

        bssid = str(getattr(network, "bssid", "") or "").strip().lower()

        signal = getattr(network, "signal", None)
        quality = signal_quality(signal)

        # Store all network information in one dictionary
        network_info = {
            "ssid": ssid,
            "bssid": bssid,
            "signal": signal,
            "quality": quality,
            "encryption": encryption,
            "frequency": freq,
            "band": band,
            "channel": channel
        }

        # Store each BSSID only once
        key = bssid or f"{ssid.casefold()}:{freq}"
        if key not in networks_by_bssid:
            networks_by_bssid[key] = network_info

        # If the same BSSID appears again, keep the stronger signal
        elif (signal if signal is not None else -999) > (networks_by_bssid[key]["signal"] or -999):
            networks_by_bssid[key] = network_info

    return list(networks_by_bssid.values())
