def get_signal_status(quality):

    if quality >= 80:
        return "Excellent"

    elif quality >= 60:
        return "Good"

    elif quality >= 40:
        return "Fair"

    elif quality >= 20:
        return "Weak"

    return "Very Weak"


def get_band_status(band):

    if band == "6 GHz":
        return "Fastest"

    elif band == "5 GHz":
        return "Fast"

    elif band == "2.4 GHz":
        return "Long Range"

    return "Unknown"


def analyze(network):

    network["signal_status"] = get_signal_status(network["quality"])

    network["band_status"] = get_band_status(network["band"])

    return network