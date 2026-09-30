"""On-demand network performance measurements."""

import re
import socket
import subprocess
import sys
import time


def measure_ping(host="1.1.1.1", count=4, timeout_ms=1200):
    command = (["ping", "-n", str(count), "-w", str(timeout_ms), host]
               if sys.platform == "win32" else
               ["ping", "-c", str(count), "-W", str(max(1, timeout_ms // 1000)), host])
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=(count * timeout_ms / 1000) + 3)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"host": host, "latency_ms": None, "packet_loss_percent": 100, "error": str(error)}

    replies = [float(value) for value in re.findall(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", result.stdout, re.IGNORECASE)]
    received = min(len(replies), count)
    return {
        "host": host,
        "latency_ms": round(sum(replies) / len(replies), 2) if replies else None,
        "packet_loss_percent": round((count - received) * 100 / count, 1),
        "error": None if replies else "No ping replies received.",
    }


def measure_dns(host="example.com", port=443):
    started = time.perf_counter()
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as error:
        return {"host": host, "resolution_ms": None, "address_count": 0, "error": str(error)}
    return {
        "host": host,
        "resolution_ms": round((time.perf_counter() - started) * 1000, 2),
        "address_count": len({entry[4][0] for entry in addresses}),
        "error": None,
    }


def measure_speed():
    try:
        import speedtest
    except ImportError as error:
        raise RuntimeError("Install speedtest-cli to run a download/upload speed test.") from error

    try:
        tester = speedtest.Speedtest(secure=True)
        tester.get_best_server()
        download = tester.download() / 1_000_000
        upload = tester.upload() / 1_000_000
        return {"download_mbps": round(download, 2), "upload_mbps": round(upload, 2)}
    except Exception as error:
        raise RuntimeError(f"Speed test failed: {error}") from error


def measure_performance(include_speed_test=False):
    """Run bounded ping and DNS checks; run speedtest only when explicitly requested."""
    result = {"ping": measure_ping(), "dns": measure_dns()}
    if include_speed_test:
        try:
            result["speed"] = measure_speed()
        except RuntimeError as error:
            result["speed"] = {"download_mbps": None, "upload_mbps": None, "error": str(error)}
    else:
        result["speed"] = None
    return result


def get_performance_recommendations(metrics, connection=None):
    recommendations = []
    connection = connection or {}
    ping = metrics.get("ping") or {}
    dns = metrics.get("dns") or {}
    speed = metrics.get("speed") or {}

    latency = ping.get("latency_ms")
    if latency is not None and latency > 100:
        recommendations.append("High latency detected; move closer to the router or reduce competing network traffic.")
    loss = ping.get("packet_loss_percent")
    if loss is not None and loss > 2:
        recommendations.append("Packet loss detected; check Wi-Fi interference, router placement, and cabling.")
    resolution = dns.get("resolution_ms")
    if resolution is not None and resolution > 200:
        recommendations.append("DNS resolution is slow; compare your router's DNS settings with a trusted resolver.")
    download = speed.get("download_mbps")
    if download is not None and download < 25:
        recommendations.append("Measured download speed is low; check your internet plan and other active downloads.")
    radio_type = str(connection.get("radio_type", "")).casefold()
    analysis = connection.get("analysis") or {}
    bands = {str(network.get("band", "")).casefold()
             for network in connection.get("nearby_networks", [])
             if str(network.get("ssid", "")).strip().casefold()
             == str(connection.get("ssid", "")).strip().casefold()}
    bands.update({str(analysis.get("band", "")).casefold()})
    if "802.11n" in radio_type and any("5 ghz" in band or "6 ghz" in band for band in bands):
        recommendations.append(
            "A 5/6 GHz version of this SSID is nearby, but the connection uses 802.11n; check adapter/router mode and reconnect to the faster band."
        )
    if not recommendations:
        recommendations.append("No major performance issues were detected by these measurements.")
    return recommendations