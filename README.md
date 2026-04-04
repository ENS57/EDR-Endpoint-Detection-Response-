# EDR Hook Analizi Projesi

## 📌 Proje Amacı
Bu proje, modern EDR (Endpoint Detection & Response) sistemlerinin kullanıcı-mode API çağrılarını nasıl izlediğini analiz etmek amacıyla geliştirilmiştir. Çalışma kapsamında Windows işletim sisteminde bulunan NTDLL modülü incelenerek olası API hook işlemleri tespit edilmektedir.

---

## 🧠 Proje Kapsamı
Proje, özellikle NTDLL içerisindeki **Nt* syscall fonksiyonlarına** odaklanmaktadır. Bu fonksiyonlar kullanıcı-mode ile kernel-mode arasındaki geçişi sağladığı için EDR çözümleri tarafından sıklıkla izlenmektedir.

---

## ⚙️ Yapılan Analizler
- NTDLL export fonksiyonlarının taranması  
- Bellek (memory) ve disk üzerindeki byte karşılaştırması  
- Syscall stub (opcode) yapısının doğrulanması  
- Olası inline hook tespiti  
- Byte-level farklılık analizi  
- Sistem genel durum değerlendirmesi  

---

## 🔍 Kullanılan Yöntemler
Projede aşağıdaki teknikler kullanılmıştır:

- PE dosya analizi (pefile kütüphanesi)  
- ctypes ile düşük seviyeli bellek erişimi  
- Byte seviyesinde karşılaştırma (memory vs disk)  
- Opcode pattern analizi  
- Heuristic (sezgisel) hook tespiti  

---

## 📊 Örnek Çıktı
Toplam Fonksiyon: 250
Temiz: 248
Hook Şüphesi: 2
Değiştirilmiş: 0
Okunamayan: 0

---

## ⚠️ Sınırlamalar
- Kernel-level hook tespiti yapılamaz  
- Bazı bellek bölgeleri işletim sistemi tarafından korunabilir  
- Syscall stub yapısı Windows sürümüne göre değişebilir  
- Unhooking işlemi sistem stabilitesi açısından uygulanmamış, teorik olarak ele alınmıştır  

---

## 🔐 Güvenlik Notu
Bu proje yalnızca eğitim ve savunma amaçlı geliştirilmiştir. Amaç, sistem güvenliğini analiz etmek ve EDR mekanizmalarını anlamaktır.

---

## 📌 Sonuç
Yapılan analizler sonucunda, kullanıcı-mode API hook tespiti byte seviyesinde doğrulama ile gerçekleştirilebilmiştir. Ancak modern EDR çözümlerinin yalnızca user-mode değil, kernel-level ve ETW tabanlı izleme yöntemleri de kullandığı değerlendirilmiştir.

---

## 🚀 Kullanılan Teknolojiler
- Python  
- WinAPI (ctypes)  
- PE analizi (pefile)  
- Düşük seviyeli bellek erişimi  
