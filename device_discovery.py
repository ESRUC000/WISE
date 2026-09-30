"""Discover active IPv4 hosts on the connected subnet using ARP."""

import ipaddress
import socket

MAX_SUBNET_HOSTS = 1024


def _connected_ipv4_network(interface_name=None):
    try:
        import psutil
        from scapy.all import conf
    except ImportError as error:
        raise RuntimeError("Install Scapy and psutil to discover local network devices.") from error

    interface_addresses = psutil.net_if_addrs()
    if interface_name:
        candidates = [(name, address) for name, addresses in interface_addresses.items()
                      if name.casefold() == interface_name.casefold()
                      for address in addresses if address.family == socket.AF_INET]
        if not candidates:
            raise RuntimeError(f"Could not find an IPv4 address for connected Wi-Fi interface {interface_name!r}.")
        _system_name, address = candidates[0]
        route = conf.route.route(address.address)
        scapy_interface, _source_ip, gateway_ip = route
    else:
        scapy_interface, source_ip, gateway_ip = conf.route.route("0.0.0.0")
        address = next((address for addresses in interface_addresses.values() for address in addresses
                        if address.family == socket.AF_INET and address.address == source_ip), None)
        if address is None:
            raise RuntimeError("Could not identify the active network interface.")

    if not address.netmask:
        raise RuntimeError("The connected Wi-Fi interface has no IPv4 subnet mask.")
    interface = ipaddress.ip_interface(f"{address.address}/{address.netmask}")
    network = interface.network
    if network.num_addresses > MAX_SUBNET_HOSTS:
        raise RuntimeError(
            f"The connected subnet has {network.num_addresses} addresses; discovery is limited to {MAX_SUBNET_HOSTS}."
        )
    return scapy_interface, interface, network, gateway_ip


def discover_devices(interface_name=None, timeout=2):
    """Return responding devices from only the active interface's IPv4 subnet."""
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError as error:
        raise RuntimeError("Install Scapy to discover local network devices.") from error

    scapy_interface, local_interface, network, gateway_ip = _connected_ipv4_network(interface_name)
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
    try:
        answered, _ = srp(request, iface=scapy_interface, timeout=timeout, retry=1, verbose=False)
    except PermissionError as error:
        raise RuntimeError("Device discovery requires administrator/root privileges and a working packet-capture driver.") from error
    except OSError as error:
        raise RuntimeError(f"ARP discovery failed: {error}") from error

    devices = {}
    for _sent, received in answered:
        address = str(received.psrc)
        mac = str(received.hwsrc).lower()
        devices[address] = {
            "ip": address, "mac": mac, "is_local": address == str(local_interface.ip),
            "is_gateway": address == gateway_ip,
        }
    if gateway_ip and gateway_ip != "0.0.0.0" and gateway_ip not in devices:
        devices[gateway_ip] = {"ip": gateway_ip, "mac": "Unknown", "is_local": False, "is_gateway": True}
    return {
        "interface": str(scapy_interface), "subnet": str(network), "gateway_ip": gateway_ip,
        "devices": sorted(devices.values(), key=lambda item: ipaddress.ip_address(item["ip"])),
    }