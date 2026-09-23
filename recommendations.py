# recommendations.py

def get_security_recommendation(network):

    recommendations = []

    status = network["security_status"]

    if status == "Very Secure":
        recommendations.append(
            "Keep WPA3 enabled. WISE cannot verify password strength or router firmware from this scan."
        )

    elif status == "Secure":
        recommendations.append(
            "Upgrade to WPA3 if your router and devices support it."
        )

    elif status == "Weak":
        recommendations.append(
            "Upgrade your router to WPA2 or WPA3."
        )
        recommendations.append(
            "Avoid transmitting sensitive information until the network is upgraded."
        )

    elif status == "Unsecured":
        recommendations.append(
            "Enable WPA2 or WPA3 encryption immediately."
        )
        recommendations.append(
            "Avoid logging into banking or sensitive accounts."
        )
        recommendations.append(
            "Use a trusted VPN if you must use this network."
        )

    else:
        recommendations.append(
            "Unable to determine the network security."
        )

    return recommendations


def get_channel_recommendation(network, environment):

    recommendations = []

    status = network["channel_status"]

    if status == "Overlapping" and environment.get("recommended_channel") is not None:
        recommendations.append(
            f"Change your router to channel {environment['recommended_channel']} to reduce interference."
        )

    elif status in ["Recommended", "Good", "Excellent"]:
        recommendations.append(
            "No channel changes are currently recommended."
        )

    else:
        recommendations.append(
            "Unable to determine whether a channel change is needed."
        )

    return recommendations


def get_performance_recommendation(network):

    recommendations = []

    quality = network["quality"]

    if quality >= 80:
        recommendations.append(
            "No performance improvements are currently recommended."
        )

    elif quality >= 60:
        recommendations.append(
            "Move slightly closer to the router if you require higher speeds."
        )

    elif quality >= 40:
        recommendations.append(
            "Move closer to the router."
        )
        recommendations.append(
            "Reduce walls or other obstacles between your device and the router."
        )

    elif quality >= 20:
        recommendations.append(
            "Move closer to the router."
        )
        recommendations.append(
            "Avoid thick walls and metal objects blocking the Wi-Fi signal."
        )
        recommendations.append(
            "Consider repositioning the router for better coverage."
        )

    else:
        recommendations.append(
            "Move much closer to the router."
        )
        recommendations.append(
            "Consider installing a Wi-Fi extender or mesh Wi-Fi system."
        )

    return recommendations


def get_band_recommendation(network, networks):

    recommendations = []

    # -----------------------------
    # Currently on 2.4 GHz
    # -----------------------------
    if network["band"] == "2.4 GHz":

        for other in networks:

            if other["ssid"] != network["ssid"]:
                continue

            if other["bssid"] == network["bssid"]:
                continue

            if other["band"] != "5 GHz":
                continue

            if other["quality"] >= 60:
                recommendations.append(
                    "Switch to the 5 GHz band for higher speeds."
                )

            elif other["quality"] >= 40:
                recommendations.append(
                    "A 5 GHz version of this network is available, but its signal is only moderate."
                )

            break

        if not recommendations:
            recommendations.append(
                "No band changes are currently recommended."
            )

    # -----------------------------
    # Currently on 5 GHz
    # -----------------------------
    elif network["band"] == "5 GHz":

        if network["quality"] < 35:

            switched = False

            for other in networks:

                if other["ssid"] != network["ssid"]:
                    continue

                if other["bssid"] == network["bssid"]:
                    continue

                if other["band"] == "2.4 GHz" and other["quality"] > network["quality"]:

                    recommendations.append(
                        "Switch to the 2.4 GHz band for a more stable connection."
                    )

                    switched = True
                    break

            if not switched:
                recommendations.append(
                    "Move closer to the router before switching bands."
                )

        else:
            recommendations.append(
                "No band changes are currently recommended."
            )

    # -----------------------------
    # Currently on 6 GHz
    # -----------------------------
    elif network["band"] == "6 GHz":

        recommendations.append(
            "No band changes are currently recommended."
        )

    else:

        recommendations.append(
            "Unable to determine whether a band change is recommended."
        )

    return recommendations


def analyze(network, environment, networks):

    network["performance_recommendations"] = \
        get_performance_recommendation(network)

    network["security_recommendations"] = \
        get_security_recommendation(network)

    network["channel_advice"] = \
        get_channel_recommendation(network, environment)

    network["band_recommendations"] = \
        get_band_recommendation(network, networks)

    return network
