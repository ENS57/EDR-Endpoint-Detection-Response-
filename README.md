# 🛡️ EDR - Endpoint Detection & Response (Hook Analysis Engine)

## 🚀 Proje Amacı
Bu proje, modern EDR (Endpoint Detection & Response) sistemlerinin kullanıcı-mode API çağrılarını nasıl izlediğini analiz etmek amacıyla geliştirilmiştir.

Sistem, Windows işletim sisteminde bulunan **NTDLL modülü** üzerinden syscall seviyesinde analiz yaparak olası hook ve manipülasyonları tespit eder.

---

## 🧠 Sistem Mimarisi

Bu proje basit bir script değil, **modüler bir EDR pipeline** olarak tasarlanmıştır:
[Analyzer / Agent]
↓
[Detection Engine]
↓
[Threat Classification]
↓
[Alert System]
↓
[Reporting Engine]

---

## ⚙️ Özellikler

- 🔍 NTDLL syscall fonksiyon analizi  
- 🧠 Detection engine (pattern + heuristic)  
- 🚨 Alert üretim sistemi (severity bazlı)  
- 🧬 Threat classification (MITRE ATT&CK mapping)  
- 📊 Byte-level memory vs disk karşılaştırması  
- 🛡️ Hook & code tampering tespiti  
- 📄 Structured JSON + TXT raporlama  
- 💻 CLI destekli kullanım (`--only-alerts`, `--no-report`)  

---

## 🚀 Kullanım

Projeyi çalıştırmak için:

```bash
python main.py
Sadece alertleri görmek için:
python main.py --only-alerts
Rapor oluşturmadan çalıştırmak için:
python main.py --no-report;
---
##🔬 Yapılan Analizler
NTDLL export fonksiyonlarının taranması
Bellek (memory) ve disk üzerindeki byte karşılaştırması
Syscall stub (opcode) yapısının doğrulanması
Olası inline hook tespiti
Byte-level farklılık analizi
Sistem genel durum değerlendirmesi

##🧠 Detection Engine

Sistem aşağıdaki tehditleri tespit edebilir:

Hook edilmiş syscall fonksiyonları
Kod modifikasyonu (inline patching)
Anormal syscall stub yapıları
Şüpheli opcode dizilimleri

##🧬 MITRE ATT&CK Mapping
Threat	Technique
Hook Detection	T1055 - Process Injection
Code Tampering	T1562 - Defense Evasion
Obfuscation	T1027 - Obfuscated Files

##🚨 Örnek Alert
{
  "type": "hook_detected",
  "severity": "high",
  "function": "NtOpenProcess",
  "message": "Possible hook detected",
  "mitre": "T1055"
}

##📊 Örnek Çıktı
Toplam Fonksiyon: ~400+
Alert Sayısı: 40–70 (simulated + heuristic)
Severity dağılımı: High / Medium / Low

##🛠️ Kullanılan Teknolojiler
Python
WinAPI (ctypes)
PE analizi (pefile)
Düşük seviyeli bellek erişimi

##⚠️ Sınırlamalar
Kernel-level hook tespiti yapılamaz
Bazı bellek bölgeleri korunmuş olabilir
Syscall stub yapısı Windows sürümüne göre değişebilir
Kernel / ETW tabanlı izleme analiz dışıdır
-

##📌 Sonuç

Bu çalışma, kullanıcı-mode seviyesinde API hook tespitinin mümkün olduğunu göstermektedir.
Ancak modern EDR sistemleri kernel-level ve ETW gibi daha gelişmiş izleme teknikleri kullanmaktadır.

##👤 Hazırlayan

ENES VAHİD ERDEMOĞLU
