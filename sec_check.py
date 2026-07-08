
def get_security_status(encryption):

    if encryption == "Open":
        return "Unsecured"

    elif "WPA3" in encryption:
        return "Very Secure"

    elif "WPA2" in encryption:
        return "Secure"

    elif "WPA" in encryption:
        return "Weak"

    return "Unknown"


def get_security_message(status):

    if status == "Very Secure":
        return "This network uses the latest security standard."

    elif status == "Secure":
        return "This network is protected with modern encryption."

    elif status == "Weak":
        return "This network uses an older security protocol."

    elif status == "Unsecured":
        return "Anyone nearby may be able to intercept your traffic."

    return "Security could not be determined."


def analyze(network):

    status = get_security_status(network["encryption"])

    network["security_status"] = status
    network["security_message"] = get_security_message(status)

    return network