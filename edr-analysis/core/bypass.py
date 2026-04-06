def analyze_bypass_surface(results):
    report = "\n🔐 BYPASS ANALYSIS\n"
    report += "=" * 50 + "\n"

    hooked = 0

    for func, data in results.items():
        status = data.get("status")

        if status in ["INLINE_HOOK_SUSPECTED", "BYTE_MISMATCH"]:
            hooked += 1

    if hooked == 0:
        report += "No user-mode hooks detected.\n"
        report += "→ Direct syscall bypass not required.\n\n"

    else:
        report += f"{hooked} hooked functions detected.\n"
        report += "→ Potential bypass strategies:\n"
        report += "   - Direct syscall invocation\n"
        report += "   - Manual syscall stub reconstruction\n"
        report += "   - Fresh NTDLL mapping\n\n"

    report += "🧠 ADVANCED NOTE:\n"
    report += "Modern EDR solutions may monitor at kernel-level or via ETW,\n"
    report += "making user-mode bypass techniques insufficient.\n"

    return report