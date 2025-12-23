# Log Gözcüsü

**Log Gözcüsü**, web sunucusu günlük dosyalarını (access.log) gerçek zamanlı olarak izleyen, kural tabanlı ve yapay zeka destekli bir güvenlik analiz aracıdır. Potansiyel siber saldırıları tespit eder, raporlar ve kullanıcıyı uyarır.

![Log Gözcüsü Arayüzü](https://i.imgur.com/example.png) <!-- Gerçek bir ekran görüntüsü URL'si ile değiştirilecek -->

## ✨ Temel Özellikler

- **Gerçek Zamanlı Log Analizi**: `access.log` dosyasını sürekli izleyerek yeni girişleri anında analiz eder.
- **Hibrit Tehdit Tespiti**:
  - **Kural Tabanlı Analiz**: `rules.json` dosyasında tanımlanan esnek ve güçlü regex kuralları ile bilinen saldırı kalıplarını (SQLi, XSS, Path Traversal vb.) anında yakalar.
  - **Yapay Zeka Destekli Analiz**: Kural dışı veya şüpheli log satırlarını [OpenRouter.ai](https://openrouter.ai/) API'si üzerinden gelişmiş yapay zeka modelleri (örn: Claude 3.5 Sonnet) ile analiz ederek daha derin ve akıllı bir anomali tespiti yapar.
- **Grafiksel Kullanıcı Arayüzü (GUI)**:
  - **Etkileşimli Dashboard**: Tespit edilen tehdit verilerini (`threat_data.jsonl`) görselleştiren dinamik bir arayüz.
    - Zamana göre saldırı yoğunluğu grafiği.
    - En çok saldıran IP adresleri ve saldırı türleri için grafikler.
    - Verileri IP ve kategoriye göre filtreleme.
  - **Canlı Log Akışı**: Ajanın tüm aktivitelerini ve tespitlerini renk kodlamasıyla canlı olarak gösterir.
  - **Kolay Kontrol**: Tek tıkla ajanı başlatma, durdurma ve yeniden başlatma imkanı.
- **Detaylı Raporlama**:
  - `tehdit_raporu.txt`: İnsan tarafından okunabilir, detaylı saldırı raporları.
  - `analiz_raporu.txt`: İncelenen her log satırı için (hem zararlı hem zararsız) analiz sonuçları.
  - `durum_raporu.txt`: Periyodik olarak ajanın genel durumu hakkında istatistiksel raporlar.
  - `threat_data.jsonl`: Yapılandırılmış JSON formatında tehdit verileri. SIEM gibi diğer güvenlik araçlarıyla kolayca entegre edilebilir.
- **E-posta Bildirimleri**: Bir tehdit tespit edildiğinde anında e-posta ile uyarı gönderir.

## 🛠️ Kurulum

1.  **Projeyi Klonlayın**:
    ```bash
    git clone https://github.com/kullanici/log-gozcusu.git
    cd log-gozcusu
    ```

2.  **Gerekli Python Kütüphanelerini Yükleyin**:
    - **Temel Çalışma İçin**: Projenin çalışması için ek bir kütüphane gerekmez, sadece standart Python kütüphaneleri kullanılır.
    - **Dashboard Özelliği İçin**: Grafiksel dashboard'u kullanmak için `pandas` ve `matplotlib` gereklidir.
      ```bash
      pip install pandas matplotlib
      ```

3.  **Ortam Değişkenlerini Ayarlayın**:
    Proje ana dizininde `.env.example` dosyasını `.env` olarak kopyalayın.
    ```bash
    cp .env.example .env
    ```
    Ardından `.env` dosyasını düzenleyin:

    - **Yapay Zeka Analizi İçin (Önerilir)**:
      - [OpenRouter.ai](https://openrouter.ai/) sitesinden bir API anahtarı alın.
      - `.env` dosyasına ekleyin:
        ```
        OPENROUTER_API_KEY="sk-or-..."
        ```
      - *Alternatif olarak, bu anahtarı programın GUI'si üzerinden de girebilirsiniz.*

    - **E-posta Bildirimleri İçin (İsteğe Bağlı)**:
      - Gmail için "Uygulama Şifresi" oluşturun ([Google Hesap Güvenliği](https://myaccount.google.com/security) sayfasından).
      - `.env` dosyasına bilgileri girin:
        ```
        ALERT_EMAIL_USER="mailadresiniz@gmail.com"
        ALERT_EMAIL_PASS="uygulama_sifreniz"
        ```
      - *Uyarıların gönderileceği hedef e-posta adresi, programın arayüzünden girilebilir.*

## 🚀 Kullanım

1.  **`access.log` Dosyasını Ekleyin**:
    Analiz etmek istediğiniz `access.log` dosyasını projenin ana dizinine yerleştirin. Test için örnek bir `access.log` dosyası projede mevcuttur.

2.  **Arayüzü Başlatın**:
    ```bash
    python gui.py
    ```

3.  **Ajanı Çalıştırın**:
    - Açılan başlangıç ekranında, uyarıların gönderilmesini istediğiniz e-posta adresini girin (isteğe bağlı).
    - "Ajanı Çalıştır" butonuna tıklayın.
    - Artık "Canlı Loglar" sekmesinden ajanın çalışmalarını izleyebilir ve "Dashboard" sekmesinden tespit edilen tehditleri görsel olarak analiz edebilirsiniz.

## 🔧 Yapılandırma

- **Saldırı Kuralları (`rules.json`)**:
  Kendi özel tespit kurallarınızı eklemek veya mevcutları düzenlemek için `rules.json` dosyasını değiştirebilirsiniz. Her kural `pattern` (regex), `category`, `severity` gibi alanlar içerir.

- **Yapay Zeka Modeli**:
  Varsayılan olarak `anthropic/claude-3.5-sonnet` modeli kullanılır. Farklı bir model kullanmak isterseniz `.env` dosyasına aşağıdaki değişkeni ekleyebilirsiniz:
  ```
  OPENROUTER_MODEL="google/gemini-pro"
  ```

## 🤝 Katkıda Bulunma

Katkılarınız projeyi daha da geliştirmemize yardımcı olur! Lütfen bir "pull request" açmaktan veya "issue" bildirmekten çekinmeyin.

## 📄 Lisans

Bu proje MIT Lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakınız.
