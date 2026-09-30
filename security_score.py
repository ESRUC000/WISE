"""Transparent 100-point scoring for Wi-Fi security, performance, and configuration."""

from network_audit import is_default_ssid, is_hidden_ssid


PROTOCOL_POINTS = {
    "WPA3": 35,
    "WPA2": 30,
    "WPA": 18,
    "WEP": 8,
    "OPEN": 0,
}


def _tiered_points(value, tiers):
    if value is None:
        return 0
    for threshold, points in tiers:
        if value <= threshold:
            return points
    return tiers[-1][1]


def score_connection(
    connection,
    company_network=False,
    password_policy_ok=False,
    performance_metrics=None,
    router_admin_password_ok=False,
):
    """Return category scores with fixed security/performance/configuration weights."""
    authentication = str(connection.get("authentication", "Unknown")).upper()
    protocol = next((name for name in PROTOCOL_POINTS if name in authentication), None)
    protocol_score = PROTOCOL_POINTS.get(protocol, 0)
    cipher = str(connection.get("cipher", "Unknown")).upper()
    cipher_points = 15 if any(name in cipher for name in ("GCMP", "CCMP", "AES")) else 0
    rogue_ap_penalty = 15 if connection.get("rogue_ap_suspected") else 0
    security_score = max(0, min(protocol_score + cipher_points, 50) - rogue_ap_penalty)

    metrics = performance_metrics or connection.get("performance_metrics") or {}
    ping = metrics.get("ping") or {}
    dns = metrics.get("dns") or {}
    speed = metrics.get("speed") or {}
    signal = connection.get("signal_percent")
    signal_points = _tiered_points(signal, ((20, 1), (40, 2), (60, 4), (80, 5), (float("inf"), 6)))
    rates = [connection.get(key) for key in ("receive_rate_mbps", "transmit_rate_mbps")
             if connection.get(key) is not None]
    link_rate = min(rates) if rates else None
    link_points = _tiered_points(link_rate, ((10, 0), (25, 1), (50, 2), (150, 3), (float("inf"), 4)))
    latency_points = _tiered_points(ping.get("latency_ms"), ((25, 7), (50, 6), (100, 4), (200, 2), (float("inf"), 0)))
    loss_points = _tiered_points(ping.get("packet_loss_percent"), ((0, 5), (1, 4), (5, 3), (15, 1), (float("inf"), 0)))
    dns_points = _tiered_points(dns.get("resolution_ms"), ((50, 3), (100, 2), (250, 1), (float("inf"), 0)))
    download_points = _tiered_points(speed.get("download_mbps"), ((0, 0), (10, 1), (25, 2), (50, 3), (100, 4), (float("inf"), 5)))
    performance_score = min(signal_points + link_points + latency_points + loss_points + dns_points + download_points, 30)

    configuration = 0
    configuration += 5 if password_policy_ok else 0
    configuration += 5 if router_admin_password_ok else 0
    ssid = str(connection.get("ssid", ""))
    configuration += 5 if ssid and not is_hidden_ssid(ssid) and not is_default_ssid(ssid) else 0
    analysis = connection.get("analysis") or {}
    channel_status = connection.get("channel_status", analysis.get("channel_status", "Unknown"))
    if channel_status in ("Recommended", "Good", "Excellent"):
        configuration += 5
    elif channel_status == "Overlapping":
        configuration += 2
    configuration_score = min(configuration, 20)

    total = security_score + performance_score + configuration_score
    performance_note = (
        f"Signal {signal_points}/6; link rate {link_points}/4; ping {latency_points}/7; loss {loss_points}/5; "
        f"DNS {dns_points}/3; download {download_points}/5"
    )
    configuration_note = (
        f"Wi-Fi password {5 if password_policy_ok else 0}/5; router admin password "
        f"{5 if router_admin_password_ok else 0}/5; SSID hygiene "
        f"{5 if ssid and not is_hidden_ssid(ssid) and not is_default_ssid(ssid) else 0}/5; "
        f"channel {configuration_score - (5 if password_policy_ok else 0) - (5 if router_admin_password_ok else 0) - (5 if ssid and not is_hidden_ssid(ssid) and not is_default_ssid(ssid) else 0)}/5"
    )
    breakdown = [
        {"category": "Security", "earned": security_score, "possible": 50,
         "note": f"{protocol or 'Unknown'} authentication; cipher {cipher_points}/15; suspected rogue AP penalty {rogue_ap_penalty}"},
        {"category": "Performance", "earned": performance_score, "possible": 30,
         "note": performance_note},
        {"category": "Configuration", "earned": configuration_score, "possible": 20,
         "note": configuration_note},
    ]
    return {
        "total": total,
        "security": security_score,
        "performance": performance_score,
        "configuration": configuration_score,
        "protocol": security_score,
        "company_and_password": configuration_score,
        "other": performance_score,
        "signal_points": signal_points,
        "cipher_points": cipher_points,
        "rogue_ap_penalty": rogue_ap_penalty,
        "protocol_name": protocol or "Unknown",
        "company_network": bool(company_network),
        "password_policy_ok": bool(password_policy_ok),
        "router_admin_password_ok": bool(router_admin_password_ok),
        "max_score": 100,
        "breakdown": breakdown,
    }


def compare_scores(previous, current):
    """Describe the change between successive saved scans of a network."""
    if previous is None:
        return {"change": None, "label": "Baseline scan"}
    change = current["total"] - previous["total"]
    if change > 0:
        label = f"Improved by {change} points"
    elif change < 0:
        label = f"Decreased by {abs(change)} points"
    else:
        label = "No score change"
    return {"change": change, "label": label}