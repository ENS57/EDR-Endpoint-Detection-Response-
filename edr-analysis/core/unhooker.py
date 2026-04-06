def simulate_unhook(results):
    report = "\n🔄 UNHOOKING SIMULATION\n"
    report += "=" * 50 + "\n"

    for func, data in results.items():
        status = data.get("status")

        if status in ["INLINE_HOOK_SUSPECTED", "BYTE_MISMATCH"]:
            report += f"[!] {func}\n"
            report += "  → Hook detected\n"
            report += "  → Simulated action: Restore from disk image\n"
            report += "  → Expected result: Clean syscall stub\n\n"

        elif status == "CLEAN":
            report += f"[+] {func} already clean\n\n"

        elif status == "UNREADABLE":
            report += f"[?] {func} protected (cannot restore safely)\n\n"

    report += "🧠 NOTE:\n"
    report += "Actual memory patching is avoided due to system stability and security risks.\n"

    return report