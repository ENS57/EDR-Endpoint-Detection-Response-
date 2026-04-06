def advanced_analysis(results):
    analysis = "\n🔎 ADVANCED SECURITY ANALYSIS\n"
    analysis += "=" * 60 + "\n"

    compromised = 0
    suspicious = 0
    clean = 0

    severity_count = {
        "high": 0,
        "medium": 0,
        "low": 0
    }

    # =========================
    # PER FUNCTION ANALYSIS
    # =========================
    for func, data in results.items():
        analysis += f"\n[{func}]\n"
        analysis += "-" * 40 + "\n"

        if not isinstance(data, dict):
            analysis += f"Status: {data}\n"
            continue

        status = data.get("status", "UNKNOWN")
        pattern = data.get("pattern", "N/A")
        severity = data.get("severity", "low")
        threat = data.get("threat_type", "none")
        mitre = data.get("mitre_technique", "N/A")
        diff_count = data.get("diff_count", 0)

        analysis += f"Status: {status}\n"
        analysis += f"Severity: {severity}\n"
        analysis += f"Threat Type: {threat}\n"
        analysis += f"MITRE: {mitre}\n"
        analysis += f"Pattern: {pattern}\n"
        analysis += f"Byte Differences: {diff_count}\n"

        # =========================
        # COUNTERS
        # =========================
        if severity in severity_count:
            severity_count[severity] += 1

        if status == "COMPROMISED":
            compromised += 1
            analysis += "🚨 Critical integrity violation detected\n"

        elif status == "SUSPICIOUS":
            suspicious += 1
            analysis += "⚠️ Suspicious behavior observed\n"

        elif status == "CLEAN":
            clean += 1
            analysis += "✅ System call integrity verified\n"

        # =========================
        # DIFF DETAILS
        # =========================
        if diff_count > 0:
            analysis += "Differences detected in memory vs disk\n"

    # =========================
    # GLOBAL ANALYSIS
    # =========================
    analysis += "\n📊 GLOBAL SYSTEM EVALUATION\n"
    analysis += "=" * 60 + "\n"

    analysis += f"Compromised Functions : {compromised}\n"
    analysis += f"Suspicious Functions  : {suspicious}\n"
    analysis += f"Clean Functions       : {clean}\n\n"

    analysis += "Severity Distribution:\n"
    analysis += f"  High   : {severity_count['high']}\n"
    analysis += f"  Medium : {severity_count['medium']}\n"
    analysis += f"  Low    : {severity_count['low']}\n"

    # =========================
    # INTERPRETATION (🔥)
    # =========================
    analysis += "\n🧠 THREAT INTERPRETATION\n"
    analysis += "=" * 60 + "\n"

    if compromised > 0:
        analysis += "- High-confidence tampering detected (possible EDR hook or malware)\n"

    if suspicious > 0:
        analysis += "- Behavioral anomalies detected in syscall structure\n"

    if compromised == 0 and suspicious == 0:
        analysis += "- No strong indicators of compromise detected\n"

    if severity_count["high"] > 0:
        analysis += "- Immediate investigation recommended\n"

    # =========================
    # SECURITY INSIGHT (🔥 PRO LEVEL)
    # =========================
    analysis += "\n🛡️ SECURITY INSIGHTS\n"
    analysis += "=" * 60 + "\n"

    analysis += "- User-mode hooks typically indicate EDR monitoring or malware tampering\n"
    analysis += "- Inline patching may redirect execution flow\n"
    analysis += "- Syscall integrity is critical for OS trust boundaries\n"
    analysis += "- Differences between memory and disk indicate runtime manipulation\n"

    # =========================
    # TECHNICAL NOTES
    # =========================
    analysis += "\n⚙️ TECHNICAL NOTES\n"
    analysis += "=" * 60 + "\n"

    analysis += "- Detection based on syscall stub validation\n"
    analysis += "- Memory vs disk byte comparison applied\n"
    analysis += "- MITRE ATT&CK mapping included\n"
    analysis += "- Kernel-level hooks are not detectable from user-mode\n"
    analysis += "- ETW-based monitoring is outside detection scope\n"

    return analysis