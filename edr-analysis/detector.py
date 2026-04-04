import pefile
import ctypes

NTDLL_PATH = r"C:\Windows\System32\ntdll.dll"


def read_memory(addr, size):
    try:
        return ctypes.string_at(addr, size)
    except:
        return None


def analyze_syscall_pattern(b):
    if b is None or len(b) < 10:
        return "UNREADABLE"

    if not (b[0] == 0x4C and b[1] == 0x8B and b[2] == 0xD1):
        return "INVALID"

    if b[3] != 0xB8:
        return "MODIFIED"

    if b.find(b'\x0F\x05') != -1:
        return "SYSCALL"

    return "ALT_STUB"


def analyze_ntdll():
    pe = pefile.PE(NTDLL_PATH)
    ntdll = ctypes.windll.ntdll

    results = {}

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name = exp.name.decode() if exp.name else None

        # 🔥 SADECE Nt* ANALİZ
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
                results[name] = {"status": "UNREADABLE"}
                continue

            pattern = analyze_syscall_pattern(mem_bytes)

            if pattern == "INVALID":
                status = "HOOK_SUSPECTED"
            elif pattern == "MODIFIED":
                status = "MODIFIED"
            else:
                status = "CLEAN"

            results[name] = {
                "status": status,
                "pattern": pattern
            }

        except:
            continue

    return results