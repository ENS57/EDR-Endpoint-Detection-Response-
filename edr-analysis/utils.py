def interpret_results(results):
    analysis = "\n🔎 DETAYLI ANALİZ:\n"
    analysis += "=" * 30 + "\n"

    hooked = 0
    unreadable = 0

    for func, status in results.items():
        if "HOOK" in status:
            analysis += f"[!] {func} -> Hook şüphesi var\n"
            hooked += 1

        elif "OKUNAMADI" in status:
            analysis += f"[?] {func} -> Memory erişimi engellendi\n"
            unreadable += 1

        elif "CLEAN" in status:
            analysis += f"[+] {func} -> Temiz\n"

    analysis += "\n📊 GENEL DURUM:\n"

    if hooked > 0:
        analysis += "→ Sistem üzerinde kullanıcı-mode hook bulunabilir (EDR/AV ihtimali)\n"

    if unreadable > 0:
        analysis += "→ Memory erişim kısıtları mevcut (Windows koruma / EDR self-defense)\n"

    if hooked == 0 and unreadable > 0:
        analysis += "→ Hook doğrudan gözlenemedi ancak sistem koruma mekanizması aktif\n"

    if hooked == 0 and unreadable == 0:
        analysis += "→ Hook tespit edilmedi, sistem temiz görünüyor\n"

    return analysis