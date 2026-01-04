# 🛡️ TechDetector - Kullanım Kılavuzu (User Guide)

**Sürüm:** 2.0 (Military-Grade Edition)  
**Durum:** Kararlı (Stable)  
**Tarih:** 04 Ocak 2026

---

## 1. Giriş
**TechDetector**, web varlıkları üzerinde derinlemesine istihbarat toplamak, güvenlik zaafiyetlerini belirlemek ve teknoloji altyapısını en ince detayına kadar haritalandırmak için tasarlanmış ileri düzey bir **Siber İstihbarat (Cyber Intelligence)** aracıdır.

Sıradan tarayıcıların aksine, **TechDetector**:
*   **Aktif ve Pasif** taramayı birleştirir.
*   **WAF (Web Application Firewall)** arkasına saklanmış teknolojileri tespit eder.
*   **OSINT (Açık Kaynak İstihbaratı)** yöntemleriyle insan faktörünü (eposta, sosyal medya) analiz eder.
*   **Bulut Varlıklarını (Cloud Assets)** fuzzing yöntemiyle keşfeder.

Bu araç, **"Sıfır Hata"** prensibiyle çalışır ve raporlamada **Askeri Standartlarda** hassasiyet sunar.

---

## 2. Kurulum

Sistemi çalıştırmak için Python 3.8+ gereklidir. Gerekli kütüphaneleri yükleyin:

```bash
pip install -r requirements.txt
```

*(Temel bağımlılıklar: `requests`, `beautifulsoup4`, `dnspython`, `urllib3`)*

---

## 3. Temel Kullanım

En basit haliyle bir hedefi taramak için:

```bash
python3 tech_detector/main.py https://hedef-site.com
```

Bu komut:
1.  Siteye bağlanır.
2.  Temel teknolojileri analiz eder.
3.  Sonuçları ekrana basar.

---

## 4. İleri Düzey Komutlar ve Stratejiler

Sistemin gerçek gücünü ortaya çıkarmak için aşağıdaki parametreleri kullanın:

### 🚀 Tam Donanımlı İstihbarat Taraması (Önerilen)
WAF tespiti, OSINT, Cloud Recon ve derinlemesine dosya analizi dahil her şeyi çalıştırır.

```bash
python3 tech_detector/main.py https://hedef-site.com --deep --report --csv --threads 10
```

*   `--deep`: Sadece ana sayfayı değil, site içindeki diğer linkleri de (crawl) gezerek alt sayfalardaki teknolojileri ve sızıntıları bulur.
*   `--report`: Tarama sonunda interaktif bir **HTML Raporu** oluşturur.
*   `--csv`: Sonuçları Excel uyumlu CSV formatında kaydeder.
*   `--threads 10`: Taramayı 10 eşzamanlı işlemle hızlandırır.

### Diğer Parametreler

| Parametre | Açıklama |
| :--- | :--- |
| `--proxy http://1.2.3.4:8080` | Taramayı bir proxy sunucusu üzerinden geçirerek kimliğinizi gizler. |
| `--user-agent "MyBot/1.0"` | Özel bir User-Agent kimliği kullanır. (Sistem varsayılan olarak rastgele modern tarayıcı kimlikleri kullanır). |
| `--timeout 15` | Bağlantı zaman aşımı süresini (saniye) ayarlar. Yavaş siteler için artırın. |
| `--verbose` | Ekrana daha detaylı (debug) çıktılar basar. |

---

## 5. Raporları Yorumlama

Sistem tarama sonucunda `reports/` klasörü altına HTML ve CSV dosyaları bırakır.

### 🛡️ Güvenlik Notu (Security Grade)
Rapor başlığında A'dan F'ye kadar bir not görürsünüz:
*   **A (80-100)**: Çok güvenli. Tüm güvenlik headerları (HSTS, CSP, X-Frame vb.) tam.
*   **B/C**: Orta seviye. Bazı eksikler var.
*   **D/F (0-49)**: Kritik risk. Güvenlik önlemleri yetersiz, hassas bilgi sızıntısı olabilir.

### 🔍 Tespit Güven Oranı (Confidence)
Her tespitin yanında bir yüzde (%) ve kanıt (evidence) bulunur:
*   **%100**: Kesin Tespit. (Örn: `server: nginx` header'ı veya `wp-content` HTML yapısı).
*   **%80**: Yüksek İhtimal. (Örn: JS dosya isimlerinde `jquery` geçmesi).
*   **%70 (Implied)**: Çıkarım. (Örn: `Shopify` tespit edildiği için `Cloudflare` ve `Nginx` olduğu varsayılır. Bu, WAF arkasındaki gizli teknolojileri ortaya çıkarır).

### 🧠 Özel Modüller
Raporun "Detailed Findings" kısmında şunları arayın:
*   **WAF / Firewall**: Cloudflare, AWS WAF, Akamai gibi koruma kalkanları.
*   **OSINT**: Siteden kazınan E-posta adresleri ve Sosyal Medya profilleri.
*   **Cloud Assets**: `s3.amazonaws.com` veya `blob.core.windows.net` gibi açık bulut depolama alanları.
*   **Leaked Secret**: HTML veya JS kodları içinde unutulmuş API Key, Token veya şifreler.

---

## 6. Sıkça Sorulan Sorular

**S: Sistem `ticaretus.com` dışında çalışır mı?**
**C:** Evet. Sistem evrenseldir. `fingerprints.json` dosyasındaki 3000+ kural setini kullanarak dünyadaki herhangi bir web sitesini analiz edebilir.

**S: Neden bazı teknolojiler "Implied" (Çıkarım) olarak görünüyor?**
**C:** Bazı modern yapılar (örn. Shopify, Wix), altyapıda Cloudflare veya AWS kullanır ancak bunu gizler. TechDetector, üst teknolojiyi (Shopify) tanıdığında, alt teknolojiyi (Cloudflare) otomatik olarak "Çıkarım" yoluyla rapora ekler. Bu sayede görünmeyen altyapı hakkında da bilgi sahibi olursunuz.

**S: Tarama çok uzun sürüyor, ne yapmalıyım?**
**C:** `--threads` sayısını artırın (örn: 20). Ancak çok yüksek değerler hedef sitenin sizi engellemesine (WAF Block) neden olabilir. İdeal aralık 5-15'tir.

---

**Yunus Güngör | TechDetector**
*Advanced Cyber Surveillance System*
