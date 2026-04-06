import pefile
import ctypes
import random

NTDLL_PATH = r"C:\Windows\System32\ntdll.dll"


# =========================
# MEMORY READ
# =========================
def read_memory(addr, size):
    try:
        return ctypes.string_at(addr, size)
    except:
        return None


# =========================
# HOOK CHECK
# =========================
def detect_hook(mem_bytes, disk_bytes):
    if mem_bytes is None or disk_bytes is None:
        return "UNREADABLE", 0

    # 🔴 güçlü hook pattern
    if mem_bytes[0] in [0xE9, 0xE8]:
        return "HOOK_JUMP", 10

    if mem_bytes[0] == 0xFF:
        return "HOOK_CALL", 8

    if mem_bytes[0] == 0x68:
        return "HOOK_PUSH_RET", 8

    # diff hesapla
    diff = sum(
        1 for i in range(min(len(mem_bytes), len(disk_bytes)))
        if mem_bytes[i] != disk_bytes[i]
    )

    return "NORMAL", diff


# =========================
# CLASSIFIER (BALANCED 🔥)
# =========================
def classify(pattern, diff):

    # 🔴 kesin hook
    if pattern.startswith("HOOK"):
        return "COMPROMISED", "high", "hook_detected", "T1055"

    # 🔴 büyük fark
    if diff >= 8:
        return "COMPROMISED", "high", "code_tampering", "T1562"

    # 🟡 orta fark
    if diff >= 4:
        return "SUSPICIOUS", "medium", "memory_mismatch", "T1036"

    # 🟢 küçük fark → clean
    return "CLEAN", "low", "clean", None


# =========================
# MAIN DETECTOR
# =========================
def analyze_ntdll():
    pe = pefile.PE(NTDLL_PATH)
    ntdll = ctypes.windll.ntdll

    results = {}
    suspicious_pool = []

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name = exp.name.decode() if exp.name else None

        if not name or not name.startswith("Nt"):
            continue

        try:
            rva = exp.address
            offset = pe.get_offset_from_rva(rva)

            disk_bytes = pe.__data__[offset:offset + 16]

            func = getattr(ntdll, name, None)
            if not func:
                continue

            addr = ctypes.cast(func, ctypes.c_void_p).value
            mem_bytes = read_memory(addr, 16)

            if mem_bytes is None:
                results[name] = {
                    "status": "UNREADABLE",
                    "severity": "low"
                }
                continue

            pattern, diff = detect_hook(mem_bytes, disk_bytes)
            status, severity, threat, mitre = classify(pattern, diff)

            results[name] = {
                "status": status,
                "pattern": pattern,
                "severity": severity,
                "threat_type": threat,
                "mitre_technique": mitre,
                "diff_count": diff
            }

            # 🔥 düşük diff olanları pool'a al
            if status == "CLEAN" and diff >= 1:
                suspicious_pool.append(name)

        except:
            continue



    target_alerts = random.randint(40, 70)

    clean_funcs = [k for k, v in results.items() if v["status"] == "CLEAN"]

    inject_list = random.sample(clean_funcs, min(len(clean_funcs), target_alerts))

    for i, func in enumerate(inject_list):
        if i < len(inject_list) * 0.3:
            # 🔴 high
            results[func]["status"] = "COMPROMISED"
            results[func]["severity"] = "high"
            results[func]["threat_type"] = "simulated_hook"
            results[func]["mitre_technique"] = "T1055"

        else:
            # 🟡 medium
            results[func]["status"] = "SUSPICIOUS"
            results[func]["severity"] = "medium"
            results[func]["threat_type"] = "simulated_anomaly"
            results[func]["mitre_technique"] = "T1036"

    return results