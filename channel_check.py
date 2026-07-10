def get_channel_status(band, channel):

    # 2.4 GHz
    if band == "2.4 GHz":

        if channel in [1, 6, 11]:
            return "Recommended"

        elif 1 <= channel <= 14:
            return "Overlapping"

        return "Unknown"

    # 5 GHz
    elif band == "5 GHz":

        if 36 <= channel <= 165:
            return "Good"

        return "Unknown"

    # 6 GHz
    elif band == "6 GHz":

        if 1 <= channel <= 233:
            return "Excellent"

        return "Unknown"

    return "Unknown"


def get_channel_message(status):

    if status == "Recommended":
        return "This channel is one of the recommended non-overlapping channels."

    elif status == "Overlapping":
        return "This channel overlaps with nearby channels and may experience additional interference."

    elif status == "Good":
        return "This channel is suitable for high-speed wireless communication."

    elif status == "Excellent":
        return "This channel belongs to the 6 GHz band, which generally offers the least interference."

    return "Channel information could not be determined."


def analyze(network):

    status = get_channel_status(
        network["band"],
        network["channel"]
    )

    network["channel_status"] = status
    network["channel_message"] = get_channel_message(status)

    return network