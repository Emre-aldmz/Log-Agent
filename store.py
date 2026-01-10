import threading
import queue
from datetime import datetime
from typing import Dict, List, Optional

class SharedDataStore:
    """Thread-safe veri deposu. API ve Daemon arasında köprü."""
    
    def __init__(self):
        self._lock = threading.Lock()
        self._status = {
            "running": False,
            "started_at": None,
            "total_lines": 0,
            "total_threats": 0,
            "last_threat": None,
            "threats_by_category": {},
            "last_updated": None
        }
        self._recent_logs: List[Dict] = []  # Son 100 log satırı
        self._system_logs: List[Dict] = []  # Son 50 sistem mesajı (Daemon/AI)
        self._recent_threats: List[Dict] = []  # Son 50 tehdit
        self._log_queue = queue.Queue(maxsize=1000)  # WebSocket için
        self.active_agent = None  # Aktif ajan referansı (API'den komut göndermek için)
    
    def get_status(self) -> Dict:
        with self._lock:
            return dict(self._status)
    
    def update_status(self, **kwargs):
        with self._lock:
            self._status.update(kwargs)
            self._status["last_updated"] = datetime.now().isoformat()
    
    def add_log_line(self, line: str, threat_info: Optional[Dict] = None):
        with self._lock:
            # Yapılandırılmış log nesnesi
            log_entry = {
                "content": line,
                "timestamp": datetime.now().isoformat(),
                "is_threat": bool(threat_info),
                "severity": threat_info.get("severity", "normal") if threat_info else "normal",
                "category": threat_info.get("category") if threat_info else None,
                "type": "access"
            }
            self._recent_logs.append(log_entry)
            if len(self._recent_logs) > 100:
                self._recent_logs.pop(0)
        
        # WebSocket queue'ya ekle
        try:
            self._log_queue.put_nowait(log_entry)
        except queue.Full:
            try:
                self._log_queue.get_nowait()
                self._log_queue.put_nowait(log_entry)
            except queue.Empty:
                pass

    def add_system_log(self, message: str, level: str = "info"):
        """Sistem/Daemon mesajlarını kaydet (GUI için)."""
        log_entry = {
            "content": message,
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "type": "system"
        }
        with self._lock:
            # Basit deduplication: Son mesaj ile aynıysa ve üzerinden çok zaman geçmediyse ekleme
            if self._system_logs:
                last_msg = self._system_logs[-1]
                if last_msg["content"] == message and last_msg["level"] == level:
                    # Tekrar sayısını artırabiliriz veya direk yok sayabiliriz.
                    # Şimdilik " (x2)" gibi bir güncelleme yapalım veya spam olmasın diye geçelim.
                    # Ancak GUI anlık akan bir yer, güncellemek zor olabilir.
                    # Sadece son mesaj birebir aynıysa eklemeyelim (flood koruması).
                    return

            self._system_logs.append(log_entry)
            if len(self._system_logs) > 50:
                self._system_logs.pop(0)

    def add_threat(self, threat: Dict):
        with self._lock:
            self._recent_threats.append(threat)
            if len(self._recent_threats) > 50:
                self._recent_threats.pop(0)
            
            self._status["total_threats"] += 1
            self._status["last_threat"] = threat
            
            cat = threat.get("category", "Other")
            self._status["threats_by_category"][cat] = \
                self._status["threats_by_category"].get(cat, 0) + 1
    
    def get_recent_logs(self, count: int = 100) -> List[Dict]:
        with self._lock:
            return list(self._recent_logs[-count:])

    def get_system_logs(self, count: int = 50) -> List[Dict]:
        with self._lock:
            return list(self._system_logs[-count:])
    
    def get_recent_threats(self, count: int = 50) -> List[Dict]:
        with self._lock:
            return list(self._recent_threats[-count:])
    
    def get_log_queue(self) -> queue.Queue:
        return self._log_queue


# Global singleton instance
data_store = SharedDataStore()

def log_system(message: str, level: str = "info"):
    """Helper to log system events globally."""
    data_store.add_system_log(message, level)
