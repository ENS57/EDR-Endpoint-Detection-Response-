# 📌 EDR (Endpoint Detection & Response) Hook Analizi ve Bypass Yaklaşımları

## 🎯 Proje Amacı

Bu projenin amacı, modern EDR (Endpoint Detection & Response) çözümlerinin kullanıcı-mode API çağrılarını nasıl izlediğini analiz etmek ve bu izleme mekanizmalarının nasıl çalıştığını teknik olarak incelemektir.

Çalışma kapsamında:
- Windows API çağrı izleme mekanizmalarının anlaşılması
- NTDLL hooking mantığının analizi
- Hook tespiti ve bütünlük doğrulama teknikleri
- Alternatif syscall yaklaşımlarının teorik incelenmesi

hedeflenmektedir.

> ⚠️ Not: Bu çalışma eğitim ve savunma amaçlıdır. Amaç, güvenlik sistemlerinin nasıl çalıştığını anlamaktır.

---

## 🧠 Temel Kavramlar

Bu projede aşağıdaki sistem ve güvenlik kavramları kullanılacaktır:

- Windows User-mode / Kernel-mode ayrımı
- NTDLL.dll ve Native API
- API Hooking (Inline Hook, IAT Hook)
- Syscall mekanizması
- EDR çalışma prensipleri
- Memory integrity

---

## 🧰 Kullanılacak Teknolojiler

- C++ → Düşük seviyeli Windows API erişimi
- Rust → Güvenli sistem programlama ve memory kontrolü
- WinAPI → Sistem çağrıları
- PE parsing araçları → DLL analizleri

---

## 🗺️ Teknik Yol Haritası

### 1. 🔍 EDR ve Hooking Mekanizmasının Analizi

- EDR çözümlerinin nasıl çalıştığı incelenir
- User-mode API hooking mantığı araştırılır
- Özellikle NTDLL üzerindeki müdahaleler analiz edilir

**Beklenen çıktı:**
- Hooking mantığının teknik olarak anlaşılması

---

### 2. ⚙️ NTDLL Yapısının İncelenmesi

- NTDLL.dll içindeki syscall stub’ları analiz edilir
- Önemli fonksiyonlar incelenir:
  - NtOpenProcess
  - NtReadVirtualMemory
  - NtWriteVirtualMemory

**Beklenen çıktı:**
- NTDLL içindeki kritik API akışının anlaşılması

---

### 3. 🧪 Hook Tespiti (Detection)

- Bellekteki NTDLL ile disk üzerindeki NTDLL karşılaştırılır
- Byte-level fark analizi yapılır
- Hook’lu fonksiyonlar tespit edilir

**Teknik yaklaşım:**
- In-memory vs on-disk binary karşılaştırma

**Beklenen çıktı:**
- Hook uygulanmış fonksiyonların listesi

---

### 4. 🔄 NTDLL Bütünlük Yeniden Sağlama (Unhooking Yaklaşımı)

- Diskteki temiz NTDLL kopyası okunur
- Bellekteki ilgili bölümler restore edilir

**Amaç:**
- Orijinal fonksiyon akışını geri yüklemek

**Beklenen çıktı:**
- Hook’lanmamış temiz fonksiyon yapısı

---

### 5. ⚡ Syscall Mekanizmasının İncelenmesi

- Windows syscall yapısı analiz edilir
- User-mode → Kernel-mode geçişi incelenir

**Kapsam:**
- Syscall ID yapısı
- Stub fonksiyonlar

**Beklenen çıktı:**
- Native syscall akışının anlaşılması

---

### 6. 🔐 Alternatif Çağrı Yaklaşımlarının Teorik İncelenmesi

- API yerine doğrudan syscall kullanımı kavramsal olarak analiz edilir
- Güvenlik sistemlerinin bu çağrıları nasıl izlediği tartışılır

**Beklenen çıktı:**
- EDR bypass yüzeylerinin teorik analizi

---

### 7. 🧪 Test ve Doğrulama

- Hook tespiti ve bütünlük doğrulama sonuçları test edilir
- Sistem davranışı gözlemlenir

**Amaç:**
- Analizin doğrulanması

---

## 📊 Beklenen Çıktılar

- Hook edilmiş API’lerin tespiti
- NTDLL bütünlük karşılaştırma sonuçları
- Hook öncesi / sonrası fark analizi
- Syscall mekanizmasının teknik açıklaması

---

## ⚠️ Zorluklar

- Anti-tamper korumaları
- Kernel-level monitoring
- Modern EDR çözümlerinin gelişmiş teknikleri
- Yanlış memory patch işlemleri

---

## 🚀 Gelişmiş Çalışmalar (Opsiyonel)

- Kernel-mode monitoring analizi
- ETW (Event Tracing for Windows) incelemesi
- Farklı EDR ürünlerinin karşılaştırılması
- Davranışsal analiz teknikleri

---

## 📌 Sonuç

Bu proje, modern EDR sistemlerinin çalışma prensiplerini ve API izleme mekanizmalarını anlamaya yönelik ileri seviye bir analiz çalışmasıdır.

Sistem güvenliği açısından:
- Hooking teknikleri
- Memory bütünlüğü
- Syscall yapısı

gibi kritik konular derinlemesine incelenmiştir.

---

## 🔥 Kısa Özet

Bu çalışmada, EDR çözümlerinin kullanıcı-mode API çağrılarını izleme mekanizmaları analiz edilmiş, NTDLL üzerindeki hook’lar tespit edilmiş ve sistem çağrılarının alternatif kullanımı teorik olarak incelenmiştir.