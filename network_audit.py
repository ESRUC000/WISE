"""Heuristic SSID hygiene and duplicate-access-point checks."""

HIDDEN_NAMES = {"", "<hidden>", "hidden network", "<unknown>"}
DEFAULT_PREFIXES = (
    "default", "linksys", "netgear", "tp-link", "tplink", "dlink", "d-link",
    "asus", "belkin", "huawei", "homehub", "router",
)
SECURITY_RANK = {"unsecured": 0, "weak": 1, "unknown": -1, "secure": 2, "very secure": 3}


def is_hidden_ssid(ssid):
    return str(ssid or "").strip().casefold() in HIDDEN_NAMES


def is_default_ssid(ssid):
    value = str(ssid or "").strip().casefold()
    return not is_hidden_ssid(value) and value.startswith(DEFAULT_PREFIXES)


def analyze_networks(networks):
    """Annotate networks with conservative identity warnings and advice."""
    visible_by_ssid = {}
    for network in networks:
        ssid = str(network.get("ssid", "")).strip()
        if not is_hidden_ssid(ssid):
            visible_by_ssid.setdefault(ssid.casefold(), []).append(network)

    for network in networks:
        ssid = str(network.get("ssid", "")).strip()
        ssid_key = ssid.casefold()
        findings = []
        recommendations = []
        if is_hidden_ssid(ssid):
            findings.append("Hidden SSID")
            recommendations.append(
                "A hidden SSID is still discoverable and does not replace WPA2/WPA3 security."
            )
        elif is_default_ssid(ssid):
            findings.append("Possible factory-default SSID")
            recommendations.append(
                "Choose a distinctive network name that does not reveal the router model or default setup."
            )

        peer_networks = visible_by_ssid.get(ssid_key, [])
        distinct_bssids = {str(peer.get("bssid", "")).casefold() for peer in peer_networks
                           if peer.get("bssid")}
        own_rank = SECURITY_RANK.get(str(network.get("security_status", "unknown")).casefold(), -1)
        stronger_peer = any(
            SECURITY_RANK.get(str(peer.get("security_status", "unknown")).casefold(), -1) > own_rank
            for peer in peer_networks if peer is not network
        )
        suspected = len(distinct_bssids) > 1 and own_rank >= 0 and own_rank <= 1 and stronger_peer
        if suspected:
            findings.append("Possible evil-twin / rogue access point")
            recommendations.append(
                "This SSID is also advertised by a more securely configured access point. Verify the BSSID with the network owner before connecting."
            )

        network["ssid_hygiene"] = {
            "hidden": is_hidden_ssid(ssid),
            "default_name": is_default_ssid(ssid),
            "findings": findings,
        }
        network["rogue_ap_suspected"] = suspected
        network["identity_recommendations"] = recommendations
        configuration_recommendations = []
        if is_hidden_ssid(ssid):
            configuration_recommendations.append(
                "A hidden SSID is not a security control; keep WPA2/WPA3 encryption enabled."
            )
        elif is_default_ssid(ssid):
            configuration_recommendations.append(
                "Replace the factory-default SSID with a distinctive network name."
            )
        network["configuration_recommendations"] = configuration_recommendations

    return networks