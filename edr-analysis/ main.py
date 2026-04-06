from core.detector import analyze_ntdll
from core.analyzer import advanced_analysis
from report import generate_report
from core.unhooker import simulate_unhook
from core.bypass import analyze_bypass_surface

from datetime import datetime, UTC
import argparse


# =========================
# ALERT ENGINE
# =========================
def generate_alerts(results):
    alerts = []

    for func, data in results.items():
        if not isinstance(data, dict):
            continue

        status = data.get("status")
        severity = data.get("severity", "low")
        threat = data.get("threat_type", "unknown")
        mitre = data.get("mitre_technique")

        if status == "COMPROMISED":
            alerts.append({
                "type": threat,
                "severity": severity,
                "function": func,
                "message": f"Critical issue detected in {func}",
                "mitre": mitre
            })

        elif status == "SUSPICIOUS":
            alerts.append({
                "type": threat,
                "severity": severity,
                "function": func,
                "message": f"Suspicious behavior in {func}",
                "mitre": mitre
            })

    return alerts


# =========================
# MAIN EDR PIPELINE
# =========================
def main():
    parser = argparse.ArgumentParser(description="EDR Detection Engine")

    parser.add_argument("--only-alerts", action="store_true", help="Show only alerts")
    parser.add_argument("--no-report", action="store_true", help="Disable report generation")

    args = parser.parse_args()

    print("🚀 EDR Detection Engine Started...\n")

    start_time = datetime.now(UTC)

    # =========================
    # 1. DATA COLLECTION
    # =========================
    print("📥 Collecting telemetry...")
    results = analyze_ntdll()

    # =========================
    # 2. DETECTION ENGINE
    # =========================
    print("🧠 Running detection engine...")
    alerts = generate_alerts(results)

    # =========================
    # 3. ANALYSIS
    # =========================
    print("🔬 Running advanced analysis...")
    analysis = advanced_analysis(results)

    # =========================
    # 4. RESPONSE SIMULATION
    # =========================
    print("🛡️ Simulating response actions...")
    unhook = simulate_unhook(results)
    bypass = analyze_bypass_surface(results)

    # =========================
    # 5. SUMMARY
    # =========================
    total = len(results)
    alert_count = len(alerts)

    high = sum(1 for a in alerts if a["severity"] == "high")
    medium = sum(1 for a in alerts if a["severity"] == "medium")
    low = sum(1 for a in alerts if a["severity"] == "low")

    print("\n📊 EDR SUMMARY")
    print("=" * 50)
    print(f"Total Functions Analyzed : {total}")
    print(f"Total Alerts             : {alert_count}")
    print(f"High Severity            : {high}")
    print(f"Medium Severity          : {medium}")
    print(f"Low Severity             : {low}")

    # =========================
    # 6. ALERT OUTPUT
    # =========================
    print("\n🚨 ALERTS")
    print("=" * 50)

    if not alerts:
        print("No threats detected ✅")

    if args.only_alerts:
        for alert in alerts:
            print(f"[{alert['severity'].upper()}] {alert['message']}")
    else:
        for alert in alerts:
            print(f"[{alert['severity'].upper()}] {alert['message']} ({alert['function']})")

    # =========================
    # 7. REPORT
    # =========================
    if not args.no_report:
        print("\n📄 Generating report...")
        generate_report(results, analysis + unhook + bypass, alerts)

    end_time = datetime.now(UTC)

    print("\n✅ EDR Analysis Completed")
    print(f"⏱️ Duration: {end_time - start_time}")


if __name__ == "__main__":
    main()