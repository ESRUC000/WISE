"""Transparent 100-point scoring for the currently connected Wi-Fi network."""


PROTOCOL_POINTS = {
    "WPA3": 60,
    "WPA2": 48,
    "WPA": 24,
    "WEP": 8,
    "OPEN": 0,
}


def score_connection(connection, company_network=False, password_policy_ok=False):
    """Return total and category scores. Company/password checks are user-confirmed."""
    authentication = str(connection.get("authentication", "Unknown")).upper()
    protocol = next((name for name in PROTOCOL_POINTS if name in authentication), None)
    protocol_score = PROTOCOL_POINTS.get(protocol, 0)

    company_score = 20 if not company_network and password_policy_ok else 0
    signal = connection.get("signal_percent")
    if signal is None:
        signal_points = 0
    elif signal >= 80:
        signal_points = 10
    elif signal >= 60:
        signal_points = 8
    elif signal >= 40:
        signal_points = 5
    elif signal >= 20:
        signal_points = 2
    else:
        signal_points = 0

    cipher = str(connection.get("cipher", "Unknown")).upper()
    cipher_points = 10 if any(name in cipher for name in ("GCMP", "CCMP", "AES")) else 0
    other_score = signal_points + cipher_points
    total = protocol_score + company_score + other_score

    return {
        "total": total,
        "protocol": protocol_score,
        "company_and_password": company_score,
        "other": other_score,
        "signal_points": signal_points,
        "cipher_points": cipher_points,
        "protocol_name": protocol or "Unknown",
        "company_network": bool(company_network),
        "password_policy_ok": bool(password_policy_ok),
        "max_score": 100,
        "breakdown": [
            {"category": "Security protocol", "earned": protocol_score, "possible": 60,
             "note": f"{protocol or 'Unknown'} authentication"},
            {"category": "Company SSID/password", "earned": company_score, "possible": 20,
             "note": "Based on your confirmation in the app"},
            {"category": "Other safeguards", "earned": other_score, "possible": 20,
             "note": f"Signal {signal_points}/10; encryption cipher {cipher_points}/10"},
        ],
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
