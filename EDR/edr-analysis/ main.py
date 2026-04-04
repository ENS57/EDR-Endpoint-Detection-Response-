from detector import analyze_ntdll
from analyzer import advanced_analysis
from report import generate_report
from unhooker import simulate_unhook
from bypass import analyze_bypass_surface


def main():
    print("🔍 EDR Hook Analysis Started...\n")

    # =========================
    # ANALYSIS
    # =========================
    results = analyze_ntdll()

    # =========================
    # SUMMARY (ÖNEMLİ)
    # =========================
    total = len(results)
    clean = sum(1 for r in results.values() if r.get("status") == "CLEAN")
    hooked = sum(1 for r in results.values() if r.get("status") == "HOOK_SUSPECTED")
    modified = sum(1 for r in results.values() if r.get("status") == "MODIFIED")
    unreadable = sum(1 for r in results.values() if r.get("status") == "UNREADABLE")

    print("📊 SUMMARY")
    print("=" * 40)
    print(f"Total Functions : {total}")
    print(f"Clean           : {clean}")
    print(f"Hook Suspected  : {hooked}")
    print(f"Modified        : {modified}")
    print(f"Unreadable      : {unreadable}")

    # =========================
    # ADVANCED ANALYSIS
    # =========================
    analysis = advanced_analysis(results)
    print(analysis)

    # =========================
    # UNHOOK SIMULATION
    # =========================
    unhook = simulate_unhook(results)
    print(unhook)

    # =========================
    # BYPASS ANALYSIS
    # =========================
    bypass = analyze_bypass_surface(results)
    print(bypass)

    # =========================
    # REPORT
    # =========================
    generate_report(results, analysis + unhook + bypass)

    print("\n📄 Report generated successfully.")


if __name__ == "__main__":
    main()