"""PDF report generation for WISE assessments."""

from datetime import datetime
from xml.sax.saxutils import escape


def export_pdf(path, connection, score_info, nearby_networks=(), score_change="", device_snapshot=None):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as error:
        raise RuntimeError("Install ReportLab to export PDF reports.") from error

    styles = getSampleStyleSheet()
    document = SimpleDocTemplate(path, pagesize=A4, rightMargin=17 * mm, leftMargin=17 * mm,
                                 topMargin=16 * mm, bottomMargin=16 * mm)
    story = [
        Paragraph("WISE Wi-Fi Security Assessment", styles["Title"]),
        Paragraph(datetime.now().astimezone().strftime("Generated %Y-%m-%d %H:%M %Z"), styles["Normal"]),
        Spacer(1, 6 * mm),
        Paragraph(f"Network: {escape(str(connection.get('ssid', 'Unknown')))}", styles["Heading2"]),
        Paragraph(f"Overall score: {score_info.get('total', 0)} / 100", styles["Heading2"]),
    ]
    if score_change:
        story.append(Paragraph(f"Score change: {escape(str(score_change))}", styles["Normal"]))

    score_rows = [["Category", "Score", "Assessment"]]
    score_rows.extend([
        [item.get("category", ""), f"{item.get('earned', 0)} / {item.get('possible', 0)}",
         Paragraph(escape(str(item.get("note", ""))), styles["BodyText"])]
        for item in score_info.get("breakdown", [])
    ])
    score_table = Table(score_rows, colWidths=(38 * mm, 27 * mm, 110 * mm), repeatRows=1)
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14233B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D5DFE9")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([score_table, Spacer(1, 5 * mm), Paragraph("Connection details", styles["Heading2"])])

    details = [
        ("Authentication", connection.get("authentication", "Unknown")),
        ("Cipher", connection.get("cipher", "Unknown")),
        ("Signal", f"{connection.get('signal_percent', 'Unknown')}%"),
        ("RSSI", f"{connection.get('rssi', 'Unknown')} dBm"),
        ("Band", (connection.get("analysis") or {}).get("band", "Unknown")),
        ("Channel", connection.get("channel", "Unknown")),
        ("Channel status", connection.get("channel_status", "Unknown")),
        ("Radio type", connection.get("radio_type", "Unknown")),
        ("Receive rate", f"{connection.get('receive_rate_mbps', 'Unknown')} Mbps"),
        ("Transmit rate", f"{connection.get('transmit_rate_mbps', 'Unknown')} Mbps"),
        ("Possible rogue AP", "Yes - verify this SSID/BSSID" if connection.get("rogue_ap_suspected") else "No"),
    ]
    detail_table = Table([[label, escape(str(value))] for label, value in details], colWidths=(38 * mm, 137 * mm))
    detail_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D5DFE9")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F4F7FB")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(detail_table)

    metrics = connection.get("performance_metrics") or {}
    if metrics:
        ping = metrics.get("ping") or {}
        dns = metrics.get("dns") or {}
        speed = metrics.get("speed") or {}
        story.extend([Spacer(1, 5 * mm), Paragraph("Performance measurements", styles["Heading2"])])
        story.append(Paragraph(
            escape(f"Ping: {ping.get('latency_ms', 'N/A')} ms; packet loss: {ping.get('packet_loss_percent', 'N/A')}%; "
                   f"DNS: {dns.get('resolution_ms', 'N/A')} ms; download: {speed.get('download_mbps', 'N/A')} Mbps; "
                   f"upload: {speed.get('upload_mbps', 'N/A')} Mbps"), styles["BodyText"]
        ))

    recommendations = list(connection.get("performance_recommendations", []))
    recommendations.extend(connection.get("channel_advice", []))
    recommendations.extend(connection.get("configuration_recommendations", []))
    analysis = connection.get("analysis") or {}
    for key in ("security_recommendations", "performance_recommendations", "identity_recommendations",
                "configuration_recommendations", "channel_advice", "band_recommendations"):
        recommendations.extend(analysis.get(key, []))
    recommendations = list(dict.fromkeys(recommendations))
    if recommendations:
        story.extend([Spacer(1, 5 * mm), Paragraph("Recommendations", styles["Heading2"])])
        for recommendation in recommendations[:30]:
            story.append(Paragraph(f"&#8226; {escape(str(recommendation))}", styles["BodyText"]))

    if device_snapshot:
        story.extend([Spacer(1, 5 * mm), Paragraph("Latest device discovery", styles["Heading2"])])
        story.append(Paragraph(
            escape(f"{device_snapshot.get('scanned_at', 'Unknown')} | {device_snapshot.get('subnet', 'Unknown')} | "
                   f"Gateway: {device_snapshot.get('gateway_ip') or 'Unknown'}"), styles["BodyText"]
        ))
        device_rows = [["IP address", "MAC address", "Role"]]
        device_rows.extend([
            [str(device.get("ip", "")), str(device.get("mac", "Unknown")),
             ", ".join(role for role, active in (("Gateway", device.get("is_gateway")),
                                                    ("New", device.get("is_new")),
                                                    ("This device", device.get("is_local"))) if active)]
            for device in device_snapshot.get("devices", [])[:40]
        ])
        table = Table(device_rows, colWidths=(45 * mm, 55 * mm, 82 * mm), repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14233B")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D5DFE9")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(table)

    alerts = [network for network in nearby_networks
              if network.get("rogue_ap_suspected") or (network.get("ssid_hygiene") or {}).get("findings")]
    if alerts:
        story.extend([Spacer(1, 5 * mm), Paragraph("Network identity findings", styles["Heading2"])])
        for network in alerts[:20]:
            findings = (network.get("ssid_hygiene") or {}).get("findings", [])
            if network.get("rogue_ap_suspected"):
                findings = [*findings, "Possible rogue access point"]
            story.append(Paragraph(
                escape(f"{network.get('ssid', 'Hidden')} ({network.get('bssid', 'Unknown')}): {', '.join(findings)}"),
                styles["BodyText"],
            ))

    document.build(story)
    return path