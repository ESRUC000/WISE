"""Optional console report for testing nearby-network analysis on a PC."""


def main():
    from analyzer import analyze

    networks, environment = analyze()
    print("=" * 70)
    print("WIRELESS ENVIRONMENT")
    print("=" * 70)
    print(f"Recommended Channel : {environment['recommended_channel'] or 'Unavailable'}")
    print(f"Congestion Status   : {environment['status']}")
    print(f"Recommendation      : {environment['message']}")
    print("\nChannel Congestion Scores")
    for channel, score in environment["channel_scores"].items():
        print(f"Channel {channel:<2}: {score}")

    for network in networks:
        print(f"\n{'-' * 70}\n")
        for label, key, suffix in (
            ("SSID", "ssid", ""), ("BSSID", "bssid", ""),
            ("Signal", "signal", " dBm"), ("Quality", "quality", "%"),
            ("Encryption", "encryption", ""), ("Security status", "security_status", ""),
            ("Frequency", "frequency", " MHz"), ("Band", "band", ""),
            ("Channel", "channel", ""), ("Channel status", "channel_status", ""),
        ):
            print(f"{label:<18}: {network.get(key, 'Unknown')}{suffix}")
        for label, key in (
            ("Performance", "performance_recommendations"),
            ("Security", "security_recommendations"),
            ("Channel", "channel_advice"),
            ("Band", "band_recommendations"),
        ):
            print(f"\n{label} recommendations")
            for recommendation in network.get(key, []):
                print(f"  - {recommendation}")


if __name__ == "__main__":
    main()
