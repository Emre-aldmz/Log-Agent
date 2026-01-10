# Log Gözcüsü - Agentic AI Security Tool

**Log Gözcüsü**, web sunucusu günlük dosyalarını (access.log) gerçek zamanlı olarak izleyen, **kendi kendine öğrenebilen** ve **otonom tepki verebilen** yeni nesil bir siber güvenlik ajanıdır. 

Sıradan analiz araçlarının aksine, sadece raporlamakla kalmaz; **yeni saldırı tiplerini öğrenir**, **saldırganları engeller** ve **sizinle sohbet ederek** durumu analiz eder.

![Dashboard](static/screenshot.png)

## ✨ Temel Özellikler

### 🛡️ 1. Otonom Tehdit Tespiti ve Savunma
- **Kural Tabanlı Hızlı Analiz**: SQLi, XSS gibi bilinen saldırıları anında yakalar
- **Yapay Zeka (AI) Doğrulaması**: OpenRouter API ile %99 doğruluk oranı
- **Aktif Savunma**: Kritik saldırılarda IP adresini otomatik `iptables` ile engeller
- **Anomali Tespiti**: Trafik hacminde anormal artışları istatistiksel olarak tespit eder

### 🧠 2. Kendi Kendine Öğrenme (Self-Learning)
- Yeni saldırı tipi geldiğinde AI'dan yardım alarak **yeni regex kuralı üretir**
- Kuralı `rules.json` dosyasına `LEARNED_...` etiketiyle kaydeder
- Bir sonraki benzer saldırıda AI'ya ihtiyaç duymadan engeller

### 💬 3. Siber Güvenlik Asistanı (Chat)
- Ajanınızla konuşun: *"Bugün en çok hangi ülkeden saldırı aldık?"*
- Elindeki verileri tarayarak Türkçe cevap verir

### 📊 4. Web Dashboard (YENİ!)
- **Canlı İstatistikler**: Tehdit sayısı, kategoriler, top saldırgan IP'ler
- **Grafikler**: Category pie chart, saatlik dağılım
- **Real-time Log**: WebSocket ile canlı log akışı
- **Uzaktan Erişim**: Herhangi bir tarayıcıdan izleyebilirsiniz

---

## 🗂️ Dosya Yapısı

```
Log-Gozcusu/
├── ajan.py              # Ana ajan logic (AI, kural eşleştirme, IP ban)
├── gui.py               # Admin Panel (CustomTkinter desktop GUI)
├── daemon.py            # 7/24 Backend Service
├── api.py               # FastAPI Web Server
├── static/              # Web Dashboard
│   ├── dashboard.html
│   ├── style.css
│   └── app.js
├── data/
│   ├── rules.json       # Saldırı kuralları veritabanı
│   └── threat_data.jsonl# Tespit edilen tehditler
├── reports/             # Otomatik raporlar
├── tests/               # Test dosyaları
├── docs/                # Dokümantasyon
├── utils/               # Yardımcı modüller
├── docker-compose.yml   # DVWA test ortamı
├── test_scenarios.sh    # Saldırı test senaryoları
└── requirements.txt     # Python bağımlılıkları
```

---

## 🛠️ Kurulum

### 1. Gereksinimler
- Python 3.8+
- Linux (Aktif Savunma için önerilir)

### 2. Kurulum
```bash
git clone https://github.com/Emre-aldmz/Log-Gozcusu-AgenticAI.git
cd Log-Gozcusu-AgenticAI
python -m venv .venv
source .venv/bin/activate  # veya .venv/bin/activate.fish
pip install -r requirements.txt
```

### 3. Yapılandırma
`.env` dosyasını düzenleyin:
```env
OPENROUTER_API_KEY=your_api_key
ALERT_EMAIL_USER=your@gmail.com
ALERT_EMAIL_PASS=app_password
ALERT_EMAIL_TO=alert@example.com
ACTIVE_DEFENSE_ENABLED=true
ACTIVE_DEFENSE_DRY_RUN=true
```

---

## 🚀 Kullanım

### Admin Panel (Desktop GUI)
```bash
python gui.py
# IP engelleme için: sudo python gui.py
```

### Web Dashboard (Uzaktan İzleme)
```bash
# API sunucusunu başlat
.venv/bin/uvicorn api:app --host 0.0.0.0 --port 8000

# Tarayıcıda aç: http://localhost:8000
# veya: http://<sunucu-ip>:8000
```

### 7/24 Daemon (Background Service)
```bash
python daemon.py
# Durdurmak için: python daemon.py stop
# Durum kontrolü: python daemon.py status
```

---

## 🧪 Test Ortamı (DVWA)

DVWA (Damn Vulnerable Web App) ile güvenli test ortamı:

```bash
# Docker başlat
docker-compose up -d

# DVWA'ya eriş: http://localhost:8080
# Kullanıcı: admin, Şifre: password

# Saldırı testlerini çalıştır
./test_scenarios.sh

# Log Gözcüsü'nü DVWA loglarıyla çalıştır
LOG_PATH=./dvwa_logs/access.log python daemon.py
```

---

## 📡 API Endpoints

| Endpoint | Method | Açıklama |
|----------|--------|----------|
| `/` | GET | Web Dashboard |
| `/api/status` | GET | Daemon durumu |
| `/api/stats` | GET | İstatistikler (tehdit sayısı, kategoriler) |
| `/api/threats` | GET | Tehdit listesi (filtrelenebilir) |
| `/api/logs/recent` | GET | Son log satırları |
| `/api/logs/live` | WS | Real-time log stream |
| `/api/reports` | GET | Rapor listesi |
| `/docs` | GET | Swagger API dokümantasyonu |

---

## 🤝 Katkıda Bulunma
Bu proje açık kaynaklıdır. Özellikle:
- Yeni regex kuralları
- AI prompt geliştirmeleri
- Multi-log parser (error.log, auth.log)

için PR gönderebilirsiniz.

## 📄 Lisans
MIT License.
