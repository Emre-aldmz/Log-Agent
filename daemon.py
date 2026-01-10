#!/usr/bin/env python3
"""
Log Gözcüsü - Backend Daemon Service
=====================================
7/24 çalışan arka plan servisi.
Log dosyalarını izler, tehditleri tespit eder ve veritabanına yazar.

Kullanım:
    python daemon.py                    # Foreground'da çalıştır
    python daemon.py --daemonize        # Arka planda çalıştır (Linux)
    python daemon.py stop               # Çalışan daemon'u durdur

Systemd service olarak kurmak için:
    sudo cp log_gozcusu.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable log_gozcusu
    sudo systemctl start log_gozcusu
"""

import os
import sys
import signal
import time
import json
import threading
import queue
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List
from urllib.parse import unquote_plus
from dotenv import load_dotenv

from ajan import LogWatcherAgent, analyze_with_ai, generate_regex_from_ai
from store import data_store, log_system
import uvicorn

# Ortam değişkenlerini yükle
from dotenv import load_dotenv
load_dotenv()

# Proje modüllerini import et
from ajan import (
    LogWatcherAgent,
    ThreatModel,
    ActiveDefense,
    AnomalyDetector,
    create_ai_client,
    parse_apache_log_line,
    analyze_with_ai,
    generate_regex_from_ai
)

# ==============================================================================
# CONFIGURATION
# ==============================================================================

class DaemonConfig:
    """Daemon yapılandırması. Çoğu değer .env dosyasından okunur."""
    
    # Base paths
    BASE_DIR = Path(__file__).parent.resolve()
    DATA_DIR = BASE_DIR / "data"
    REPORTS_DIR = BASE_DIR / "reports"
    
    # Log paths (çoklu log desteği için liste)
    LOG_PATHS = [
        Path(os.environ.get("LOG_PATH", "logs/access.log")),
    ]
    
    # Ek log dosyaları (varsa)
    EXTRA_LOG_PATHS = os.environ.get("EXTRA_LOG_PATHS", "")
    if EXTRA_LOG_PATHS:
        for p in EXTRA_LOG_PATHS.split(","):
            LOG_PATHS.append(Path(p.strip()))
    
    # Data files
    RULES_PATH = BASE_DIR / "data" / "rules.json"
    THREAT_DATA_PATH = BASE_DIR / "data" / "threat_data.jsonl"
    
    # Report files
    THREAT_REPORT_PATH = REPORTS_DIR / "tehdit_raporu.txt"
    STATUS_REPORT_PATH = REPORTS_DIR / "durum_raporu.txt"
    ANALYSIS_REPORT_PATH = REPORTS_DIR / "analiz_raporu.txt"
    
    # Daemon settings
    POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "1.0"))
    
    # API Server settings
    API_HOST = os.environ.get("API_HOST", "0.0.0.0")
    API_PORT = int(os.environ.get("API_PORT", "8000"))
    STATUS_INTERVAL = int(os.environ.get("STATUS_INTERVAL", "300"))  # 5 dakika
    
    # PID file (daemon durumunu kontrol için)
    PID_FILE = BASE_DIR / ".daemon.pid"
    
    # Log level
    DEBUG = os.environ.get("DEBUG", "false").lower() == "true"


# ==============================================================================
# SHARED DATA STORE (API ile paylaşım için)
# ==============================================================================

# SharedDataStore sınıfı store.py'ye taşındı.
# Global data store (store.py üzerinden gelir)

# Helper fonksiyon da store.py'ye taşındı (log_system)


# ==============================================================================
# LOG DAEMON
# ==============================================================================

class LogDaemon:
    """7/24 çalışan log izleme daemon'u."""
    
    def __init__(self, config: DaemonConfig = None):
        self.config = config or DaemonConfig()
        self.running = False
        self.agent: Optional[LogWatcherAgent] = None
        self._threads: List[threading.Thread] = []
        
        # Klasörlerin var olduğundan emin ol
        self.config.DATA_DIR.mkdir(exist_ok=True)
        self.config.REPORTS_DIR.mkdir(exist_ok=True)
        
        # Eğer rules.json data/ altında değilse, eski konumdan kopyala
        self._migrate_data_files()
    
    def _migrate_data_files(self):
        """Eski konumdaki dosyaları yeni data/ klasörüne taşı."""
        migrations = [
            (self.config.BASE_DIR / "rules.json", self.config.RULES_PATH),
            (self.config.BASE_DIR / "threat_data.jsonl", self.config.THREAT_DATA_PATH),
        ]
        
        for old, new in migrations:
            if old.exists() and not new.exists():
                log_system(f"Dosya taşındı: {old} -> {new}", "MIGRATION")
                new.parent.mkdir(parents=True, exist_ok=True)
                old.rename(new)
    
    def _setup_signal_handlers(self):
        """Graceful shutdown için sinyal yakalayıcıları."""
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        log_system(f"Sinyal alındı ({signum}), kapatılıyor...", "DAEMON")
        self.stop()
    
    def _write_pid_file(self):
        """PID dosyasına yaz (durum kontrolü için)."""
        with open(self.config.PID_FILE, "w") as f:
            f.write(str(os.getpid()))
    
    def _remove_pid_file(self):
        """PID dosyasını sil."""
        try:
            self.config.PID_FILE.unlink()
        except FileNotFoundError:
            pass
    
    def _init_agent(self) -> LogWatcherAgent:
        """LogWatcherAgent'ı başlat."""
        
        # Ana log dosyası
        main_log = self.config.LOG_PATHS[0]
        
        if not main_log.exists():
            log_system(f"Log dosyası bulunamadı: {main_log}", "UYARI")
            log_system("Boş dosya oluşturuluyor...", "UYARI")
            main_log.parent.mkdir(parents=True, exist_ok=True)
            main_log.touch()
        
        # rules.json yoksa boş oluştur
        if not self.config.RULES_PATH.exists():
            self.config.RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config.RULES_PATH, "w") as f:
                json.dump([], f)
        
        agent = LogWatcherAgent(
            log_path=main_log,
            report_path=self.config.THREAT_REPORT_PATH,
            status_path=self.config.STATUS_REPORT_PATH,
            analysis_path=self.config.ANALYSIS_REPORT_PATH,
            threat_data_path=self.config.THREAT_DATA_PATH,
            rules_path=self.config.RULES_PATH,
            poll_interval=self.config.POLL_INTERVAL,
            log_callback=log_system  # Callback buraya taşındı
        )
        # self.agent.log_callback atamasına gerek kalmadı (init içinde yapılıyor)
        
        return agent
    
    def _run_log_monitoring(self):
        """Ana log izleme döngüsü (agent'ın run() fonksiyonunu sarmalayan)."""
        try:
            # Agent'ı başlat
            self.agent = self._init_agent()
            
            # Callback bağla (GUI'ye log basmak için - ajan.py içinde defined)
            if hasattr(self.agent, 'log_callback'):
                self.agent.log_callback = log_system
            
            # API için agent referansını sakla
            data_store.active_agent = self.agent
            
            data_store.update_status(
                running=True,
                started_at=datetime.now().isoformat()
            )
            
            log_system(f"Log izleme başladı: {self.config.LOG_PATHS[0]}", "DAEMON")
            
            # Agent'ın _follow_log ve process döngüsünü burada yeniden implemente ediyoruz
            # (data_store'a yazmak için)
            
            log_path = self.config.LOG_PATHS[0]
            
            with log_path.open("r", encoding="utf-8", errors="ignore") as f:
                # Dosyanın sonuna git (sadece yeni satırları oku)
                f.seek(0, 2)
                
                while self.running:
                    line = f.readline()
                    if line:
                        line = line.rstrip("\n")
                        if not line.strip():
                            continue
                        
                        # URL decode - %3C -> <, %27 -> ', + -> space vb.
                        decoded_line = unquote_plus(line)
                        
                        # Agent ile analiz (decoded) - ÖNCE Analiz
                        threat_found = self._process_line(decoded_line)
                        
                        # Sonra Data store'a ekle (Tehdit bilgisiyle)
                        data_store.add_log_line(decoded_line, threat_info=threat_found)
                        
                        data_store.update_status(
                            total_lines=data_store.get_status()["total_lines"] + 1
                        )
                        
                    else:
                        time.sleep(self.config.POLL_INTERVAL)
                        
        except Exception as e:
            print(f"[DAEMON ERROR] {e}")
            import traceback
            traceback.print_exc()
        finally:
            data_store.update_status(running=False)
    
    def _process_line(self, raw_line: str) -> Optional[Dict]:
        """Tek bir log satırını işle. Tehdit bulursa threat objesini döner."""
        
        if not self.agent:
            return None
        
        # Öğrenilmiş false positive kontrolü
        if raw_line.strip() in self.agent.false_positives:
            return None
        
        # Debug output
        if self.config.DEBUG:
            log_system(f"{raw_line[:80]}...", "DEBUG")
        
        # Anomali kaydet ve kontrol et
        self.agent.anomaly_detector.record_request()
        anomaly = self.agent.anomaly_detector.check_anomaly()
        
        anom_threat = None
        if anomaly:
            log_system(f"Trafik artışı! ({anomaly['count']} req/min, Eşik: {anomaly['threshold']:.1f})", "ANOMALI")
            anom_threat = {
                "timestamp": datetime.now().isoformat(),
                "category": "Traffic Spike",
                "severity": anomaly["severity"],
                "ip": None, # Parse edilmedi henüz
                "rule_id": "TRAFFIC_SPIKE",
                "log_entry": f"Anormal trafik: {anomaly['count']} istek (Eşik: {anomaly['threshold']:.1f})",
                "source": "AnomalyDetector"
            }
            data_store.add_threat(anom_threat)
            # Anomaliyi log satırıyla ilişkilendirmek biraz zor çünkü trafik genel bir durum
            # Ama yine de dönebiliriz.
        
        # Parse
        parsed = parse_apache_log_line(raw_line)
        if anom_threat:
            anom_threat["ip"] = parsed.get("ip") if parsed else None
        
        # HoneyPot kontrolü
        honeypot_match = next(
            (url for url in self.agent.honeypot_urls if url in raw_line), 
            None
        )
        
        if honeypot_match:
            threat = {
                "timestamp": datetime.now().isoformat(),
                "category": "HoneyPot Trap",
                "severity": "critical",
                "ip": parsed.get("ip") if parsed else None,
                "log_entry": raw_line[:200],
                "source": "HoneyPot"
            }
            data_store.add_threat(threat)
            self.agent.act_on_attack(raw_line, parsed, {
                "id": "HONEYPOT_TRAP",
                "category": "HoneyPot Trap",
                "severity": "critical",
                "confidence": "definite",
                "description": f"Tuzak URL erişimi: {honeypot_match}"
            })
            return threat
        
        # Kural eşleştirme
        rule, _ = self.agent.model.match(raw_line)
        
        if rule:
            threat = {
                "timestamp": datetime.now().isoformat(),
                "category": rule.get("category", "Unknown"),
                "severity": rule.get("severity", "medium"),
                "ip": parsed.get("ip") if parsed else None,
                "rule_id": rule.get("id"),
                "log_entry": raw_line[:200],
                "source": "rule-based"
            }
            data_store.add_threat(threat)
            
            # Agent'ın kendi aksiyon fonksiyonunu çağır
            self.agent.act_on_attack(raw_line, parsed, rule)
            return threat
        
        else:
            # Kural eşleşmedi AMA şüpheli mi? (Agentic AI Devreye Girsin)
            SUSPICIOUS_KEYWORDS = [
                "UNION", "SELECT", "SCRIPT", "ALERT", "/ETC/", "PASSWD", 
                "CMD=", "cmd=", "1=1", "OR '1'='1'", "XSS", "WIN.INI", "SYSTEM32",
                "BENCHMARK", "SLEEP(", "ERRO", "EXPECT://", "PHP://", "DATA://",
                "FILE://", "LDAP://", "GOPHER://", "DICT://", "FTP://", "TFTP://",
                "ADMIN", "BASH", "SH", "POWERSHELL", "WGET", "CURL", "NETCAT",
                "NC ", "PING ", "WHOAMI", "CAT ", "DIR ", "LS ", "uname",
                "root", "boot.ini", "web.config", ".env", ".git", ".svn",
                # 2024-2025 Updates (Google Threat Intel)
                "169.254.169.254", "metadata.google.internal", # SSRF / Cloud Metadata
                "%0a", "%0d", "%00", # Log Injection / Null Byte
                "jndi:", "${", # Java/Log4j Injection
                "../../", "..%2f", # Path Traversal
                "/proc/self", "/proc/version", # LFI / Info Disclosure
                "auth.log", "access.log" # Log Poisoning Attempts
            ]
            
            is_suspicious = any(kw.lower() in raw_line.lower() for kw in SUSPICIOUS_KEYWORDS)
            
            if is_suspicious:
                if self.config.DEBUG:
                    log_system(f"Şüpheli log tespit edildi, AI analizi başlatılıyor: {raw_line[:50]}...", "AI")
                
                # AI Analizi Çağır
                ai_verdict = analyze_with_ai(self.agent.ai_client, raw_line)
                
                if ai_verdict and ai_verdict.get("label") == "attack":
                    log_system(f"TEHDİT ONAYLANDI! ({ai_verdict.get('probable_category')})", "AI")
                    
                    # Otomatik Kural Oluştur
                    cat = ai_verdict.get('probable_category', 'Unknown')
                    new_rule_pattern = generate_regex_from_ai(self.agent.ai_client, raw_line, cat)
                    if new_rule_pattern:
                        new_rule = {
                            "id": f"AI_LEARNED_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                            "category": ai_verdict.get("probable_category", "Unknown"),
                            "severity": "high",
                            "confidence": "suspicious",
                            "pattern": new_rule_pattern,
                            "description": f"[AI] {ai_verdict.get('reason', 'AI detected attack')}",
                            "enabled": True,
                            "source": "auto-learning"
                        }
                        
                        # Kuralı ekle ve kaydet
                        self.agent.model.add_rule(new_rule)
                        log_system(f"Yeni kural öğrenildi ve kaydedildi: {new_rule['id']}", "AI")
                        
                        # Tehdidi işle
                        threat = {
                            "timestamp": datetime.now().isoformat(),
                            "category": new_rule["category"],
                            "severity": "high",
                            "ip": parsed.get("ip") if parsed else None,
                            "rule_id": new_rule["id"],
                            "log_entry": raw_line[:200],
                            "source": "AI-Agent"
                        }
                        data_store.add_threat(threat)
                        self.agent.act_on_attack(raw_line, parsed, new_rule)
                        return threat
        
        # Eğer anomali varsa onu dön, yoksa None
        return anom_threat
    
    def _run_api_server(self):
        """API server'ı ayrı thread'de çalıştır."""
        try:
            # api.py'deki app'i import et
            import api
            # Global AI client'ı aktar
            api.global_ai_client = self.agent.ai_client
            
            from api import app
            
            config = uvicorn.Config(
                app,
                host=self.config.API_HOST,
                port=self.config.API_PORT,
                log_level="warning",  # Çok fazla log basmasın
                access_log=False
            )
            server = uvicorn.Server(config)
            server.run()
        except Exception as e:
            print(f"[API ERROR] {e}")
    
    def start(self, daemonize: bool = False):
        """Daemon'u başlat."""
        
        log_system("=" * 60, "SYS")
        log_system("  LOG GÖZCÜSÜ - UNIFIED SERVICE", "SYS")
        log_system("=" * 60, "SYS")
        log_system(f"  Log Path    : {self.config.LOG_PATHS}", "SYS")
        log_system(f"  Rules Path  : {self.config.RULES_PATH}", "SYS")
        log_system(f"  API URL     : http://{self.config.API_HOST}:{self.config.API_PORT}", "SYS")
        log_system(f"  Debug Mode  : {self.config.DEBUG}", "SYS")
        log_system("=" * 60, "SYS")
        
        # Signal handlers
        self._setup_signal_handlers()
        
        # PID file
        self._write_pid_file()
        
        self.running = True
        
        # Log monitoring thread
        monitor_thread = threading.Thread(
            target=self._run_log_monitoring,
            daemon=True,
            name="LogMonitor"
        )
        self._threads.append(monitor_thread)
        monitor_thread.start()
        
        # API Server thread
        api_thread = threading.Thread(
            target=self._run_api_server,
            daemon=True,
            name="APIServer"
        )
        self._threads.append(api_thread)
        api_thread.start()
        
        log_system("[DAEMON] Log izleme + API server başlatıldı.", "SYS")
        log_system(f"[DAEMON] Dashboard: http://localhost:{self.config.API_PORT}", "SYS")
        log_system("[DAEMON] Durdurmak için Ctrl+C", "SYS")
        
        # Ana thread bekle
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
    
    def stop(self):
        """Daemon'u durdur."""
        print("[DAEMON] Durduruluyor...")
        self.running = False
        
        # Thread'lerin bitmesini bekle
        for t in self._threads:
            t.join(timeout=5)
        
        self._remove_pid_file()
        print("[DAEMON] Durduruldu.")
    
    @classmethod
    def is_running(cls) -> bool:
        """Daemon çalışıyor mu kontrol et."""
        pid_file = DaemonConfig.PID_FILE
        if not pid_file.exists():
            return False
        
        try:
            with open(pid_file) as f:
                pid = int(f.read().strip())
            # PID'nin hala çalışıp çalışmadığını kontrol et
            os.kill(pid, 0)
            return True
        except (ValueError, ProcessLookupError, PermissionError):
            return False
    
    @classmethod
    def stop_running_daemon(cls):
        """Çalışan daemon'u durdur."""
        pid_file = DaemonConfig.PID_FILE
        if not pid_file.exists():
            print("Çalışan daemon bulunamadı.")
            return
        
        try:
            with open(pid_file) as f:
                pid = int(f.read().strip())
            print(f"Daemon durduruluyor (PID: {pid})...")
            os.kill(pid, signal.SIGTERM)
            time.sleep(2)
            print("Daemon durduruldu.")
        except Exception as e:
            print(f"Hata: {e}")


# ==============================================================================
# MAIN
# ==============================================================================

def main():
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        
        if cmd == "stop":
            LogDaemon.stop_running_daemon()
            return
        
        if cmd == "status":
            if LogDaemon.is_running():
                print("Daemon çalışıyor.")
            else:
                print("Daemon çalışmıyor.")
            return
        
        if cmd == "--daemonize":
            # Linux'ta arka planda çalıştır (basit fork)
            if os.name != "nt":  # Windows değilse
                pid = os.fork()
                if pid > 0:
                    print(f"Daemon başlatıldı (PID: {pid})")
                    sys.exit(0)
    
    # Daemon'u başlat
    daemon = LogDaemon()
    daemon.start()


if __name__ == "__main__":
    main()
