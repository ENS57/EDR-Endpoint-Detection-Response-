import json
from datetime import datetime, UTC


def generate_report(results, analysis, alerts):
    timestamp = datetime.now(UTC).isoformat()

    # =========================
    # TXT REPORT (HUMAN READABLE)
    # =========================
    report = "EDR Detection Report\n"
    report += "=" * 60 + "\n"
    report += f"Timestamp: {timestamp}\n\n"

    # =========================
    # ALERT SECTION
    # =========================
    report += "🚨 ALERTS\n"
    report += "=" * 60 + "\n"

    if alerts:
        for alert in alerts:
            report += f"[{alert['severity'].upper()}] {alert['message']}\n"
    else:
        report += "No active threats detected.\n"

    report += "\n"

    # =========================
    # DETAILED FUNCTION ANALYSIS
    # =========================
    report += "🔍 FUNCTION ANALYSIS\n"
    report += "=" * 60 + "\n\n"

    for func, data in results.items():
        report += f"[{func}]\n"
        report += "-" * 40 + "\n"

        if isinstance(data, dict):
            status = data.get("status", "UNKNOWN")
            report += f"Status: {status}\n"

            pattern = data.get("pattern")
            if pattern:
                report += f"Pattern: {pattern}\n"

            diff_count = data.get("diff_count")
            if diff_count is not None:
                report += f"Byte Differences: {diff_count}\n"

            if diff_count and diff_count > 0:
                report += "Differences (sample):\n"
                for d in data.get("diff_sample", []):
                    report += f"  Offset {d['offset']} | MEM: {d['mem']} | DISK: {d['disk']}\n"

        else:
            report += f"Status: {data}\n"

        report += "\n"

    # =========================
    # ADVANCED ANALYSIS
    # =========================
    report += "🔎 ADVANCED ANALYSIS\n"
    report += "=" * 60 + "\n"
    report += analysis + "\n"

    # =========================
    # CONCLUSION
    # =========================
    report += "\n🧠 CONCLUSION\n"
    report += "=" * 60 + "\n"
    report += (
        "This system performs user-mode hook detection by comparing in-memory syscall stubs "
        "with their original disk counterparts.\n"
        "Detected anomalies may indicate EDR hooking, inline patching, or malicious tampering.\n"
        "Alerts are generated based on behavioral deviations and integrity violations.\n"
        "Kernel-level monitoring and advanced stealth techniques may evade this detection model.\n"
    )

    # =========================
    # SAVE TXT (FIXED 🔥)
    # =========================
    with open("reports/report.txt", "w", encoding="utf-8") as f:
        f.write(report)

    print("📄 TXT report saved: reports/report.txt")

    # =========================
    # JSON REPORT
    # =========================
    structured = {
        "metadata": {
            "timestamp": timestamp,
            "total_functions": len(results),
            "alert_count": len(alerts)
        },
        "alerts": alerts,
        "results": results,
        "analysis": analysis
    }

    with open("reports/report.json", "w", encoding="utf-8") as f:
        json.dump(structured, f, indent=4)

    print("📄 JSON report saved: reports/report.json")