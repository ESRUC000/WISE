from pywifi import PyWiFi
import time

wifi = PyWiFi()
iface = wifi.interfaces()[0]

def scan_network():
    iface.scan()
    time.sleep(3)
    scanned_networks = iface.scan_results()
    return scanned_networks
 



