def advanced_analysis(results):
    analysis = "\n🔎 ADVANCED SECURITY ANALYSIS\n"
    analysis += "=" * 60 + "\n"

    hooked = 0
    modified = 0
    protected = 0
    clean = 0

    for func, data in results.items():
        analysis += f"\n[{func}]\n"
        analysis += "-" * 40 + "\n"

        # Eğer eski tip string geldiyse (fallback)
        if isinstance(data, str):
            analysis += f"Status: {data}\n"
            continue

        status = data.get("status", "UNKNOWN")
        pattern = data.get("pattern", "N/A")
        diff_count = data.get("diff_count", 0)

        analysis += f"Status: {status}\n"
        analysis += f"Pattern: {pattern}\n"
        analysis += f"Byte Differences: {diff_count}\n"

        # =========================
        # DETECTION LOGIC
        # =========================
        if status == "INLINE_HOOK_SUSPECTED":
            analysis += "⚠️ Inline hook pattern detected\n"
            hooked += 1

        elif status == "BYTE_MISMATCH":
            analysis += "⚠️ Memory differs from disk\n"
            modified += 1

        elif status == "UNREADABLE":
            analysis += "⚠️ Memory region is protected\n"
            protected += 1

        elif status == "CLEAN":
            analysis += "✅ Valid syscall stub\n"
            clean += 1

        # =========================
        # DIFF DETAILS
        # =========================
        if diff_count > 0:
            analysis += "Differences (sample):\n"
            for d in data.get("diff_sample", []):
                analysis += f"  Offset {d['offset']} | MEM: {d['mem']} | DISK: {d['disk']}\n"

        # =========================
        # HEX VIEW (SHORT)
        # =========================
        mem_hex = data.get("memory_hex")
        disk_hex = data.get("disk_hex")

        if mem_hex and disk_hex:
            analysis += "\nMemory (first bytes):\n"
            analysis += mem_hex[:50] + "...\n"

            analysis += "Disk (first bytes):\n"
            analysis += disk_hex[:50] + "...\n"

    # =========================
    # GLOBAL ANALYSIS
    # =========================
    analysis += "\n📊 GLOBAL SYSTEM EVALUATION\n"
    analysis += "=" * 60 + "\n"

    analysis += f"Hooked Functions: {hooked}\n"
    analysis += f"Modified Functions: {modified}\n"
    analysis += f"Protected Functions: {protected}\n"
    analysis += f"Clean Functions: {clean}\n"

    # =========================
    # INTERPRETATION
    # =========================
    analysis += "\n🧠 INTERPRETATION\n"
    analysis += "=" * 60 + "\n"

    if hooked > 0:
        analysis += "- Inline hook behavior detected (possible user-mode EDR)\n"

    if modified > 0:
        analysis += "- Byte-level inconsistencies detected\n"

    if protected > 0:
        analysis += "- Memory protection active (EDR or OS self-defense)\n"

    if hooked == 0 and modified == 0 and protected > 0:
        analysis += "- No visible hook, but protection suggests monitoring\n"

    if hooked == 0 and modified == 0 and protected == 0:
        analysis += "- No evidence of user-mode monitoring\n"

    # =========================
    # TECHNICAL NOTES
    # =========================
    analysis += "\n⚙️ TECHNICAL NOTES\n"
    analysis += "=" * 60 + "\n"
    analysis += "- Syscall stub pattern validation performed\n"
    analysis += "- Byte-level memory integrity verified\n"
    analysis += "- Detection based on opcode structure and diff analysis\n"
    analysis += "- Kernel-level hooks cannot be detected from user-mode\n"
    analysis += "- ETW-based monitoring is not visible in this analysis\n"

    return analysis