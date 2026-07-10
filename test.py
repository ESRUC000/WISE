from analyzer import analyze

networks, environment = analyze()

print("=" * 70)
print("WIRELESS ENVIRONMENT")
print("=" * 70)

print(f"Recommended Channel : {environment['recommended_channel']}")
print(f"Congestion Status   : {environment['status']}")
print(f"Recommendation      : {environment['message']}")

print("\nChannel Congestion Scores")

for channel, score in environment["channel_scores"].items():
    print(f"Channel {channel:<2}: {score}")

print("=" * 70)

for network in networks:
    print(f"""
SSID              : {network['ssid']}
BSSID             : {network['bssid']}

Signal            : {network['signal']} dBm
Quality           : {network['quality']}%
Signal Status     : {network['signal_status']}

Encryption        : {network['encryption']}
Security Status   : {network['security_status']}
Security Message  : {network['security_message']}

Frequency         : {network['frequency']} MHz
Band              : {network['band']}
Band Status       : {network['band_status']}

Channel           : {network['channel']}
Channel Status    : {network['channel_status']}
Channel Message   : {network['channel_message']}
""")

    print("Performance Recommendations")
    for recommendation in network.get("performance_recommendations", []):
        print(f"  • {recommendation}")

    print()

    print("Security Recommendations")
    for recommendation in network.get("security_recommendations", []):
        print(f"  • {recommendation}")

    print()

    print("Channel Recommendations")
    for recommendation in network.get("channel_advice", []):
        print(f"  • {recommendation}")

    print()

    print("Band Recommendations")
    for recommendation in network.get("band_recommendations", []):
        print(f"  • {recommendation}")

    print("\n" + "=" * 70 + "\n")

