#!/bin/bash

LOG_FILE="logs/access.log"

# Tarih formatı: 09/Jan/2026:01:30:00 +0300
DATE=$(date "+%d/%b/%Y:%H:%M:%S %z")

echo "--- Simülasyon Başlıyor: 5 Temiz + 5 Saldırı ---"

# === 5 TEMİZ LOG (BENIGN) ===
# 1. Ana sayfa ziyareti (Chrome)
echo "192.168.1.10 - - [$DATE] \"GET /index.php HTTP/1.1\" 200 4520 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\"" >> $LOG_FILE
sleep 1

# 2. Resim dosyası (Firefox)
echo "192.168.1.15 - - [$DATE] \"GET /assets/images/logo.png HTTP/1.1\" 200 12500 \"https://site.com/index.php\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0\"" >> $LOG_FILE
sleep 1

# 3. CSS dosyası yüklemesi (Safari)
echo "192.168.1.18 - - [$DATE] \"GET /css/style.css HTTP/1.1\" 200 3200 \"https://site.com/about.php\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15\"" >> $LOG_FILE
sleep 1

# 4. API health check (İç servis)
echo "10.0.0.5 - - [$DATE] \"GET /api/v1/health HTTP/1.1\" 200 45 \"-\" \"K8s-Probe/1.26\"" >> $LOG_FILE
sleep 1

# 5. Normal login sayfası ziyareti
echo "172.16.0.22 - - [$DATE] \"GET /login.php HTTP/1.1\" 200 1850 \"-\" \"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36\"" >> $LOG_FILE
sleep 2


# === 5 SALDIRI LOGU (ATTACK) ===
# 1. SQL Injection (Union Based)
echo "45.33.22.11 - - [$DATE] \"GET /products.php?id=1' UNION SELECT user,password FROM users-- HTTP/1.1\" 200 532 \"-\" \"sqlmap/1.6.10#stable\"" >> $LOG_FILE
sleep 1

# 2. XSS (Reflected)
echo "185.220.101.5 - - [$DATE] \"GET /search.php?q=<script>alert(document.cookie)</script> HTTP/1.1\" 200 4100 \"-\" \"Mozilla/5.0 (Compatible; EvilBot/1.0)\"" >> $LOG_FILE
sleep 1

# 3. Path Traversal (LFI)
echo "203.0.113.88 - - [$DATE] \"GET /download.php?file=../../../../etc/passwd HTTP/1.1\" 200 950 \"-\" \"curl/7.68.0\"" >> $LOG_FILE
sleep 1

# 4. Command Injection
echo "198.51.100.3 - - [$DATE] \"POST /admin/ping.php HTTP/1.1\" 200 150 \"ip=127.0.0.1; cat /etc/shadow\" \"Mozilla/5.0\"" >> $LOG_FILE
sleep 1

# 5. Bruteforce / Honeypot (Admin Login)
echo "66.249.66.1 - - [$DATE] \"POST /wp-admin/login.php HTTP/1.1\" 401 530 \"-\" \"Python-urllib/3.9\"" >> $LOG_FILE

echo "--- Simülasyon Tamamlandı. Loglar 'logs/access.log' dosyasına eklendi. ---"
