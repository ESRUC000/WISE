from fil_scanner import scan
from perf_check import analyze as performance_analyze
from sec_check import analyze as security_analyze

networks = scan()

for network in networks:

    network = performance_analyze(network)
    network = security_analyze(network)

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
--------------------------------------------
""")