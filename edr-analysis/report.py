import json


def generate_report(results, analysis):
    # =========================
    # TXT REPORT (HUMAN READABLE)
    # =========================
    report = "EDR Hook Analysis Report\n"
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

            mem_hex = data.get("memory_hex")
            disk_hex = data.get("disk_hex")

            if mem_hex and disk_hex:
                report += "\nMemory Bytes:\n"
                report += mem_hex + "\n"

                report += "Disk Bytes:\n"
                report += disk_hex + "\n"

        else:
            report += f"Status: {data}\n"

        report += "\n"

    # =========================
    # ANALYSIS
    # =========================
    report += "\n🔎 ADVANCED ANALYSIS\n"
    report += "=" * 60 + "\n"
    report += analysis + "\n"

    # =========================
    # CONCLUSION
    # =========================
    report += "\n🧠 CONCLUSION\n"
    report += "=" * 60 + "\n"
    report += (
        "This analysis compared in-memory NTDLL syscall stubs with the original disk version.\n"
        "Byte-level differences and opcode pattern validation were used to detect potential hooks.\n"
        "Protected memory regions may indicate OS or EDR self-defense mechanisms.\n"
        "Kernel-level monitoring cannot be detected from user-mode.\n"
    )

    # TXT SAVE
    with open("report.txt", "w", encoding="utf-8") as f:
        f.write(report)

    print("📄 TXT report saved: report.txt")

    # =========================
    # JSON REPORT (GITHUB / TOOL)
    # =========================
    with open("report.json", "w", encoding="utf-8") as f:
        json.dump({
            "results": results,
            "analysis": analysis
        }, f, indent=4)

    print("📄 JSON report saved: report.json")