# Multicheck-IOC-Tool

SOC IOC MultiCheck Tool, tehdit göstergelerini (IP adresleri, domain'ler, hash değerleri, URL'ler, e-posta adresleri) otomatik olarak tanımlayan ve bunları çoklu OSINT (Open Source Intelligence) kaynaklarında hızlı bir şekilde araştırmanızı sağlayan bir güvenlik aracıdır.
Tamamen tarayıcı tabanlı çalışır, kurulum gerektirmez ve tüm işlemler yerel olarak gerçekleşir.

<img width="1234" height="511" alt="image" src="https://github.com/user-attachments/assets/1ba3cb12-309b-45e6-9139-20d5d35b3ecb" />

# Özellikler;

# 1. Otomatik IOC Tür Algılama
Araç, girdiğiniz her IOC'yi akıllıca analiz eder ve otomatik olarak türünü belirler:

-IPv4 Adresleri: 8.8.8.8, 192.168.1.1
-Domain'ler: example.com, malicious-site.net
-URL'ler: https://phishing-site.com/login
-Hash Değerleri: MD5, SHA1, SHA256 formatlarında dosya hash'ler

Her IOC türü için en uygun tehdit istihbaratı kaynaklarını otomatik olarak seçer, böylece IP adresleri için AbuseIPDB ve Shodan, dosya hash'leri için VirusTotal gibi ilgili platformlar gösterilir.

# 2. Toplu (Bulk) İşleme
Bir seferde onlarca veya yüzlerce IOC'yi analiz edebilirsiniz. Her satıra bir IOC yazmanız yeterli:
Örneğin;

8.8.8.8
malicious-domain.com
44d88612fea8a8f36de82e1278abb02f
https://phishing-site.com

Tek bir tıklamayla tüm IOC'ler analiz edilir ve her biri için ilgili kaynaklar listelenir.

# 3. İstatistik Dashboard'u
Analiz sonrası otomatik olarak görünen istatistik paneli şunları gösterir:

-Toplam IOC Sayısı: Kaç adet gösterge analiz edildi
-Benzersiz Tür Sayısı: Kaç farklı IOC türü tespit edildi
-Toplam Kaynak Sayısı: Kaç adet tehdit istihbaratı kaynağı kullanılabilir

<img width="994" height="369" alt="image" src="https://github.com/user-attachments/assets/9dc693fe-c294-4495-aa3f-c2794aca1e50" />

Ayrıca, görsel çubuk grafikler ile IOC türlerinin dağılımını yüzdelik dilimlerle görebilirsiniz. Örneğin: %60 IP adresi, %30 domain, %10 hash gibi.

# 4. Özet Raporu
"Özet Kopyala" butonu ile detaylı bir inceleme raporu oluşturabilirsiniz:

╔════════════════════════════════════════════════════════════════╗
║            IOC İNCELEME ÖZET RAPORU                       ║
╚════════════════════════════════════════════════════════════════╝

İnceleme Detayları:
────────────────────────────────────────────────────────────────
  Zaman Damgası:   11.02.2026, 14:30:45
  Analist:         SOC Analisti
  Toplam IOC:      25
  Araç Versiyonu:  Gelişmiş MultiCheck v2.0

IOC Tür Özeti:
────────────────────────────────────────────────────────────────
  🌐 IPV4            : 15 IOC
  🔗 DOMAIN          : 8 IOC
  🔐 MD5             : 2 IOC

# Rapor her IOC için:

-Tür bilgisi 
-Öncelik seviyesi (KRİTİK, YÜKSEK, ORTA, DÜŞÜK)
-Kontrol edilen tüm kaynaklar ve URL'leri

içerir. Bu raporu doğrudan SIEM sistemine, ticket'a veya e-postaya yapıştırabilirsiniz.

Desteklenen Tehdit İstihbaratı Kaynakları
Araç, IOC türüne göre en uygun kaynaklara otomatik yönlendirme yapar:

IP Adresleri için:

VirusTotal
AbuseIPDB
Shodan
AlienVault OTX
Talos Intelligence

<img width="1053" height="292" alt="image" src="https://github.com/user-attachments/assets/b8987bd5-6ad9-421c-a88b-392bf9335265" />


Domain ve URL'ler için:

VirusTotal
URLScan.io
URLhaus
Whois
ThreatCrowd

<img width="1048" height="132" alt="image" src="https://github.com/user-attachments/assets/f0ca650d-6868-4676-b1ee-fae17a6ac89f" />

Hash Değerleri için:

VirusTotal
AlienVault OTX
Hybrid Analysis
MalwareBazaar

<img width="995" height="275" alt="image" src="https://github.com/user-attachments/assets/01b070d2-7eb1-41a8-9e03-a5f3efea81eb" />


E-posta Adresleri için:

Have I Been Pwned
EmailRep
MXToolbox Blacklist

<img width="989" height="281" alt="image" src="https://github.com/user-attachments/assets/e0ff4140-727c-4024-9c17-f94b7565d892" />


## Avantajları
- Zaman Tasarrufu
Normalde her IOC için manuel olarak 5-10 farklı siteyi açıp kontrol etmeniz gerekirdi. Bu araç ile tek tıkla tüm kaynaklar organize bir şekilde sunulur.
- Hatasız Analiz
Her IOC türü için doğru kaynaklar otomatik seçilir. IP adresini hash platformunda veya domain'i IP kontrol sitesinde aramak gibi hatalar yapmazsınız.
- Kurulum Gerektirmez
Tamamen web tabanlı, tek bir HTML dosyası. İndirin, tarayıcıda açın, kullanmaya başlayın.
- Gizlilik
Tüm işlemler tarayıcınızda yerel olarak yapılır. IOC'leriniz hiçbir sunucuya gönderilmez.
- Ücretsiz ve Açık
Herhangi bir lisans veya kayıt gerektirmez. SOC ekipleri tarafından sınırsız kullanılabilir.

Nasıl Kullanılır?

HTML dosyasını indirin ve tarayıcınızda açın
IOC'leri girin: Her satıra bir IOC (IP, domain, hash, URL, e-posta)
"Tümünü Analiz Et" butonuna tıklayın
Sonuçları inceleyin - her IOC için ilgili kaynaklara tek tıkla ulaşın
İsterseniz "Özet Kopyala" ile detaylı rapor oluşturun

Bonus: Ctrl+Enter kısayolu ile hızlıca analiz başlatabilirsiniz.

Not: Bu araç OSINT kaynaklarına erişim sağlar. Detaylı analiz için her kaynağın kendi platformunda inceleme yapılması önerilir.











