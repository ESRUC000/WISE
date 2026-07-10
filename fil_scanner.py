import checknetwork
from pywifi import const


def get_encryption(akm):
    security = []

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
    if freq > 100000:
        freq = freq // 1000
    return freq


def get_band(freq):
    if 2400 <= freq <= 2500:
        return "2.4 GHz"

    elif 5000 <= freq <= 5900:
        return "5 GHz"

    elif 5925 <= freq <= 7125:
        return "6 GHz"

    return "Unknown"


def get_channel(freq):

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
        ssid = network.ssid.strip()
        if ssid == "":
            ssid = "<Hidden>"

        # Process network information
        encryption = get_encryption(network.akm)

        freq = normalize_frequency(network.freq)

        band = get_band(freq)

        channel = get_channel(freq)

        bssid = network.bssid

        quality = signal_quality(network.signal)

        # Store all network information in one dictionary
        network_info = {
            "ssid": ssid,
            "bssid": bssid,
            "signal": network.signal,
            "quality": quality,
            "encryption": encryption,
            "frequency": freq,
            "band": band,
            "channel": channel
        }

        # Store each BSSID only once
        if bssid not in networks_by_bssid:
            networks_by_bssid[bssid] = network_info

        # If the same BSSID appears again, keep the stronger signal
        elif network.signal > networks_by_bssid[bssid]["signal"]:
            networks_by_bssid[bssid] = network_info

    return list(networks_by_bssid.values())