from fil_scanner import scan

from perf_check import analyze as performance_analyze
from sec_check import analyze as security_analyze
from channel_check import analyze as channel_analyze
from recommendations import analyze as recommendation_analyze
from channel_recommender import recommend_channel
from network_audit import analyze_networks as audit_networks


def analyze(connected_connection=None):

    # Scan nearby networks
    networks = scan()

    # Analyze the overall wireless environment
    connected_bssid = (connected_connection or {}).get("bssid")
    environment = recommend_channel(networks, connected_bssid=connected_bssid)

    analyzed_networks = []

    # Analyze each network
    for network in networks:
        is_connected = False
        if connected_connection:
            connected_ssid = str(connected_connection.get("ssid", "")).strip().casefold()
            connected_bssid = str(connected_connection.get("bssid", "")).strip().casefold()
            candidate_bssid = str(network.get("bssid", "")).strip().casefold()
            is_connected = bool(connected_bssid and candidate_bssid == connected_bssid)
            if not is_connected and not connected_bssid:
                is_connected = str(network.get("ssid", "")).strip().casefold() == connected_ssid

        network = performance_analyze(network)
        network = security_analyze(network)
        network = channel_analyze(network)
        network = recommendation_analyze(
            network,
            environment,
            networks,
            is_connected=is_connected,
        )

        analyzed_networks.append(network)

    audited_networks = audit_networks(analyzed_networks)
    if connected_connection:
        connected_ssid = str(connected_connection.get("ssid", "")).strip().casefold()
        connected_bssid = str(connected_connection.get("bssid", "")).strip().casefold()
        for network in audited_networks:
            is_connected = ((connected_bssid and str(network.get("bssid", "")).strip().casefold() == connected_bssid)
                            or (not connected_bssid and str(network.get("ssid", "")).strip().casefold() == connected_ssid))
            if not is_connected:
                network["configuration_recommendations"] = []
            else:
                network.setdefault("configuration_recommendations", []).append(
                    "Confirm the router administrator account uses a unique password and current firmware."
                )
    return audited_networks, environment