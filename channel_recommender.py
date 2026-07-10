def recommend_channel(networks):
    """
    Analyze all nearby Wi-Fi networks and recommend the best channel.
    """

    # Only consider the non-overlapping 2.4 GHz channels
    channel_scores = {
        1: 0,
        6: 0,
        11: 0
    }

    for network in networks:

        # Ignore non-2.4 GHz networks
        if network["band"] != "2.4 GHz":
            continue

        channel = network["channel"]
        quality = network["quality"]

        # Stronger signals contribute more interference
        if channel in [1, 2, 3]:
            channel_scores[1] += quality

        elif channel in [4, 5]:
            channel_scores[1] += quality // 2
            channel_scores[6] += quality // 2

        elif channel in [6, 7, 8]:
            channel_scores[6] += quality

        elif channel in [9, 10]:
            channel_scores[6] += quality // 2
            channel_scores[11] += quality // 2

        elif channel in [11, 12, 13, 14]:
            channel_scores[11] += quality

    best_channel = min(channel_scores, key=channel_scores.get)
    best_score = channel_scores[best_channel]

    if best_score < 100:
        congestion = "Low Congestion"

    elif best_score < 250:
        congestion = "Moderate Congestion"

    else:
        congestion = "High Congestion"

    return {
        "recommended_channel": best_channel,
        "channel_scores": channel_scores,
        "status": congestion,
        "message": (
            f"Channel {best_channel} currently has the lowest estimated "
            "interference among nearby 2.4 GHz networks."
        )
    }