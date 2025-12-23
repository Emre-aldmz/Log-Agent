import re
import time
import json
import os
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

import urllib.request
import urllib.error

# ==========================
# AI entegrasyonu (OpenRouter)
#   - Standart kütüphanelerle (urllib)
#   - OpenAI-style /chat/completions
# ==========================

OPENROUTER_BASE_URL = os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai")
OPENROUTER_CHAT_PATH = "/api/v1/chat/completions"


def create_ai_client() -> Optional[dict]:
    """
    OpenRouter için minimal client objesi döner.
    Env öncelik sırası:
      1. LOG_GOZCUSU_GUI_API_KEY (GUI'den gelen)
      2. OPENROUTER_API_KEY      (.env veya sistemden gelen)
    """
    # Öncelik 1: GUI'den gelen anahtar
    api_key = os.environ.get("LOG_GOZCUSU_GUI_API_KEY")
    source = "GUI"

    # Öncelik 2: Ortam değişkeninden (örn. .env dosyasından) gelen anahtar
    if not api_key:
        api_key = os.environ.get("OPENROUTER_API_KEY")
        source = "Environment"

    if not api_key:
        print("[UYARI] API anahtarı bulunamadı. AI analizi devre dışı.")
        return None
    
    print(f"[INFO] API anahtarı '{source}' kaynağından yüklendi.")

    model = os.environ.get("OPENROUTER_MODEL", "anthropic/claude-3.5-sonnet")
    base_url = os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai").rstrip("/")

    return {
        "api_key": api_key,
        "model": model,
        "base_url": base_url,
    }


def _xai_post_json(client: dict, path: str, payload: dict, timeout: int = 30) -> Optional[dict]:
    """
    OpenRouter endpointine POST atar, JSON döner.
    """
    url = f"{client['base_url']}{path}"
    data = json.dumps(payload).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        # Cloudflare / anti-bot için gerçekçi bir UA
        "User-Agent": os.environ.get(
            "LOG_GOZCUSU_UA",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Authorization": f"Bearer {client['api_key']}",
    }

    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return json.loads(body)

    except urllib.error.HTTPError as e:
        raw = ""
        try:
            raw = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        print(f"[UYARI] AI analizi HTTP hatası: {e.code} - {raw[:300]}")
        return None

    except Exception as e:
        print(f"[UYARI] AI analizi yapılamadı: {e}")
        return None


def _http_post_json(url: str, headers: Dict[str, str], payload: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    return json.loads(raw)


def _clean_code_fences(text: str) -> str:
    t = (text or "").strip()
    if t.startswith("```"):
        lines = t.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        t = "\n".join(lines).strip()
    return t


def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    """
    Model bazen ```json ...``` veya açıklama ile dönebilir.
    Buradan ilk JSON objesini yakalamaya çalışır.
    """
    t = _clean_code_fences(text)

    # 1) Direkt JSON denemesi
    try:
        return json.loads(t)
    except Exception:
        pass

    # 2) İçeride ilk { ... } aralığını dene
    l = t.find("{")
    r = t.rfind("}")
    if l != -1 and r != -1 and r > l:
        candidate = t[l:r + 1]
        try:
            return json.loads(candidate)
        except Exception:
            return None
    return None


# Alias: eski kodlarda _try_parse_json ismi kullanıldığı için
def _try_parse_json(text: str) -> Optional[Dict[str, Any]]:
    return _extract_json_object(text)


def analyze_with_ai(client: Any, log_line: str) -> Optional[Dict[str, Any]]:
    """
    Her log satırı için AI'dan {label, probable_category, reason} döndürmeye çalışır.
    """
    if not client:
        return None

    prompt = (
        "You are a cyber security analyst AI.\n"
        "Input is ONE HTTP access log line.\n"
        "Decide if it is an attack attempt or benign traffic.\n"
        "Return ONLY valid JSON with:\n"
        '  - label: \"attack\" or \"benign\"\n'
        '  - probable_category: \"SQLi\" | \"XSS\" | \"Path Traversal\" | \"Command Injection\" | '
        '\"Bruteforce\" | \"Other\" | \"None\"\n'
        "  - reason: short 1-2 sentence explanation\n"
        "No markdown. No code fences.\n\n"
        f"Log line:\n{log_line}\n"
    )

    payload = {
        "model": client["model"],
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 256,   # kredi/tokens için sınır
    }

    resp = _xai_post_json(client, OPENROUTER_CHAT_PATH, payload, timeout=45)
    if not resp:
        return None

    try:
        content = resp["choices"][0]["message"]["content"]
    except Exception:
        return None

    result = _try_parse_json(content)
    if not isinstance(result, dict):
        print(f"[UYARI] AI cevabı JSON değil. Ham (kısaltılmış): {str(content)[:200]}")
        return None

    # normalize
    result.setdefault("label", "benign")
    result.setdefault("probable_category", "Other")
    result.setdefault("reason", "No reason returned.")
    return result


def ai_parse_log_structure(client: Any, log_line: str) -> Optional[Dict[str, Any]]:
    """
    Serbest formatlı log satırından şu alanları çekmeye çalışır:
    - ip
    - method
    - path
    - query (yoksa boş string)
    - status (string) veya null
    - ua veya null
    """
    if not client:
        return None

    prompt = (
        "You are a log parsing assistant.\n"
        "Extract fields if possible from ONE raw HTTP access log line.\n"
        "Fields:\n"
        "- ip\n"
        "- method\n"
        "- path\n"
        "- query (empty string if none)\n"
        "- status (string) or null\n"
        "- ua or null\n"
        "If a field is unknown, use null (query uses empty string).\n"
        "Return ONLY one valid JSON object. No markdown, no code fences.\n\n"
        f"Log line:\n{log_line}\n"
    )

    payload = {
        "model": client["model"],
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.0,
        "max_tokens": 256,
    }

    resp = _xai_post_json(client, OPENROUTER_CHAT_PATH, payload, timeout=30)
    if not resp:
        return None

    try:
        content = resp["choices"][0]["message"]["content"].strip()
    except Exception:
        return None

    obj = _try_parse_json(content)
    if not isinstance(obj, dict):
        print(f"[UYARI] AI parse cevabı JSON değil. Ham: {content[:200]}")
        return None

    # Normalizasyon
    ip = obj.get("ip")
    method = obj.get("method")
    path = obj.get("path") or obj.get("resource")
    query = obj.get("query")
    status = obj.get("status")
    ua = obj.get("ua") or obj.get("user_agent")

    if query is None:
        query = ""

    parsed = {
        "ip": ip,
        "method": method,
        "path": path,
        "resource": path,
        "query": query,
        "status": status,
        "ua": ua,
    }
    return parsed


# ==========================
# Konsol animasyon yardımcıları
# ==========================

def typewriter(text: str, delay: float = 0.01):
    for ch in text:
        print(ch, end="", flush=True)
        time.sleep(delay)
    print()


def scan_animation(prefix: str = "[AJAN] Log satırı inceleniyor", cycles: int = 3, delay: float = 0.08):
    for i in range(cycles):
        dots = "." * ((i % 3) + 1)
        print(f"\r{prefix}{dots}   ", end="", flush=True)
        time.sleep(delay)
    print("\r" + " " * (len(prefix) + 5), end="\r")


# ==========================
# Mail gönderme modülü
# ==========================

def send_email_alert(subject: str, body: str):
    smtp_user = os.environ.get("ALERT_EMAIL_USER")
    smtp_pass = os.environ.get("ALERT_EMAIL_PASS")
    target_email = os.environ.get("ALERT_EMAIL_TO")

    if not (smtp_user and smtp_pass and target_email):
        print("[UYARI] Email ortam değişkenleri eksik. Mail gönderilmeyecek.", flush=True)
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = target_email
    msg.set_content(body)

    try:
        print("[DEBUG] send_email_alert çağrıldı, mail gönderilmeye çalışılıyor...", flush=True)
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(smtp_user, smtp_pass)
            smtp.send_message(msg)
        print("[LOG GÖZCÜSÜ] Uyarı maili gönderildi.", flush=True)
    except Exception as e:
        print(f"[UYARI] Mail gönderilemedi: {e}", flush=True)



# ==========================
# Apache Combined Log Parser
# ==========================

APACHE_COMBINED_REGEX = re.compile(
    r'(?P<ip>\S+) '              # IP
    r'\S+ \S+ '                  # ident, user
    r'\[(?P<time>[^\]]+)\] '     # [10/Oct/2025:13:55:36 +0300]
    r'"(?P<method>\S+) '         # "GET
    r'(?P<path>.+?)'             # path (boşluk da olabilir)
    r'(?: HTTP/(?P<http_ver>\S+))?" '  # HTTP/1.1
    r'(?P<status>\d{3}) '        # 200
    r'(?P<size>\S+) '            # 2326
    r'"(?P<referer>[^"]*)" '     # referer
    r'"(?P<ua>[^"]*)"'           # user agent
)


def parse_apache_log_line(line: str) -> Optional[Dict[str, Any]]:
    m = APACHE_COMBINED_REGEX.match(line)
    if not m:
        return None

    data = m.groupdict()
    path = data.get("path", "") or ""

    if "?" in path:
        resource, query = path.split("?", 1)
    else:
        resource, query = path, ""

    data["resource"] = resource
    data["query"] = query
    data["path"] = resource  # tek isimle kullanmak için
    return data


# ==========================
# ThreatModel: JSON kurallı
# ==========================

class ThreatModel:
    def __init__(self, rules_path: Path) -> None:
        self.rules_path = rules_path
        self._compiled = []
        self._load_rules()

    def _load_rules(self):
        if not self.rules_path.exists():
            raise FileNotFoundError(f"Kural dosyası bulunamadı: {self.rules_path}")

        with self.rules_path.open("r", encoding="utf-8") as f:
            rules = json.load(f)

        compiled_rules = []
        for rule in rules:
            if not rule.get("enabled", True):
                continue
            pattern = rule.get("pattern")
            if not pattern:
                continue
            try:
                c = re.compile(pattern)
            except re.error as e:
                print(f"[UYARI] Kural derlenemedi ({rule.get('id')}): {e}")
                continue
            rule_copy = dict(rule)
            rule_copy["compiled"] = c
            compiled_rules.append(rule_copy)

        self._compiled = compiled_rules
        print(f"[ThreatModel] {len(self._compiled)} kural yüklendi.")

    def match(self, log_line: str) -> Tuple[Optional[dict], Optional[re.Match]]:
        for rule in self._compiled:
            m = rule["compiled"].search(log_line)
            if m:
                return rule, m
        return None, None


# ==========================
# LogWatcherAgent
# ==========================

class LogWatcherAgent:
    def __init__(
        self,
        log_path: Path,
        report_path: Path,
        status_path: Path,
        analysis_path: Path,
        threat_data_path: Path,
        rules_path: Path,
        poll_interval: float = 1.0,
        status_interval_seconds: int = 300,
    ):
        self.log_path = log_path
        self.report_path = report_path
        self.status_path = status_path
        self.analysis_path = analysis_path
        self.threat_data_path = threat_data_path  # Eklendi
        self.poll_interval = poll_interval
        self.status_interval = timedelta(seconds=status_interval_seconds)

        self.model = ThreatModel(rules_path)
        self.ai_client = create_ai_client()

        self.total_lines = 0
        self.total_attacks = 0
        self.attacks_by_category: Dict[str, int] = {}
        self.last_status_time = datetime.now()

    def _follow_log(self):
        with self.log_path.open("r", encoding="utf-8", errors="ignore") as f:
            while True:
                line = f.readline()
                if line:
                    scan_animation()
                    yield line
                else:
                    time.sleep(self.poll_interval)
                    self._maybe_write_status()

    def _ensure_parsed(self, raw_line: str, parsed: Optional[dict]) -> Optional[dict]:
        if parsed is not None:
            return parsed

        # Parser bozulduysa AI parse dene
        if self.ai_client is not None:
            ai_parsed = ai_parse_log_structure(self.ai_client, raw_line)
            if isinstance(ai_parsed, dict):
                if "query" not in ai_parsed or ai_parsed["query"] is None:
                    ai_parsed["query"] = ""
                if "path" in ai_parsed and "resource" not in ai_parsed:
                    ai_parsed["resource"] = ai_parsed.get("path")
                return ai_parsed
        return None

    def _write_analysis(self, raw_line: str, parsed: Optional[dict], verdict: Dict[str, Any]):
        """
        Her log satırı için analiz raporu (benign dahil) oluşturur.
        """
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        p = parsed or {}
        entry = [
            f"[{now}] ANALIZ",
            f"Label    : {verdict.get('label')}",
            f"Category : {verdict.get('probable_category')}",
            f"Reason   : {verdict.get('reason')}",
            f"IP       : {p.get('ip')}",
            f"Method   : {p.get('method')}",
            f"Path     : {p.get('path') or p.get('resource')}",
            f"Query    : {p.get('query', '')}",
            f"Status   : {p.get('status')}",
            f"UA       : {p.get('ua')}",
            f"Log      : {raw_line.strip()}",
            "-" * 80,
        ]
        with self.analysis_path.open("a", encoding="utf-8") as f:
            f.write("\n".join(entry) + "\n")

    def act_on_attack(self, raw_line: str, parsed: Optional[dict], rule: dict, extra_info: Optional[dict] = None):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        header = (
            f"[{timestamp}] UYARI: {rule['category']} tespit edildi! "
            f"(kural={rule['id']}, seviye={rule['severity']}, confidence={rule.get('confidence', 'unknown')})"
        )

        details_lines = [f"Açıklama : {rule.get('description', '')}"]
        p = parsed or {}

        if parsed:
            details_lines.append(f"IP       : {p.get('ip')}")
            details_lines.append(f"Method   : {p.get('method')}")
            details_lines.append(f"Kaynak   : {p.get('path') or p.get('resource')}")
            details_lines.append(f"Sorgu    : {p.get('query', '')}")
            details_lines.append(f"Status   : {p.get('status')}")
            details_lines.append(f"User-Ag. : {p.get('ua')}")
        else:
            details_lines += [
                "IP       : (parse edilemedi)",
                "Method   : (parse edilemedi)",
                "Kaynak   : (parse edilemedi)",
                "Sorgu    : (parse edilemedi)",
                "Status   : (parse edilemedi)",
                "User-Ag. : (parse edilemedi)",
            ]

        if extra_info:
            details_lines.append(f"Kaynak   : {extra_info.get('source', 'rules/AI')}")
            details_lines.append(f"Etiket   : {extra_info.get('label')}")
            details_lines.append(f"AI Kat.  : {extra_info.get('probable_category')}")
            details_lines.append(f"AI Notu  : {extra_info.get('reason')}")

        details_lines.append(f"Log Satırı: {raw_line.strip()}")

        print("!" * 80)
        typewriter(header, delay=0.005)
        for line in details_lines:
            typewriter(line, delay=0.003)
        print("!" * 80)

        details_text = "\n".join(details_lines) + "\n"
        with self.report_path.open("a", encoding="utf-8") as f:
            f.write(header + "\n")
            f.write(details_text)
            f.write("-" * 80 + "\n")

        self.total_attacks += 1
        cat = rule["category"]
        self.attacks_by_category[cat] = self.attacks_by_category.get(cat, 0) + 1

        # Yapısal JSON verisini `threat_data.jsonl` dosyasına yaz
        try:
            threat_data = {
                "timestamp": timestamp,
                "category": rule.get("category", "Other"),
                "ip": p.get("ip"),
                "rule_id": rule.get("id"),
                "severity": rule.get("severity"),
                "confidence": rule.get("confidence"),
                "source": (extra_info or {}).get("source", "rule-based"),
                "log_line": raw_line.strip(),
            }
            with self.threat_data_path.open("a", encoding="utf-8") as f:
                json.dump(threat_data, f)
                f.write("\n")
        except Exception as e:
            print(f"[UYARI] JSON veri dosyasına yazılamadı: {e}", flush=True)


        subject = "[LOG GÖZCÜSÜ] " + rule["category"] + " tespit edildi"
        body = header + "\n\n" + details_text
        send_email_alert(subject, body)

    def _maybe_write_status(self):
        now = datetime.now()
        if now - self.last_status_time < self.status_interval:
            return

        self.last_status_time = now
        lines = [
            f"[{now.strftime('%Y-%m-%d %H:%M:%S')}] DURUM RAPORU",
            f"Toplam işlenen satır         : {self.total_lines}",
            f"Toplam tespit edilen saldırı : {self.total_attacks}",
        ]

        if self.attacks_by_category:
            lines.append("Kategori bazında dağılım:")
            for cat, count in self.attacks_by_category.items():
                lines.append(f"  - {cat}: {count}")
        else:
            lines.append("Son rapordan bu yana saldırı tespit edilmedi.")

        lines.append("-" * 80)
        report_text = "\n".join(lines) + "\n"

        print("[LOG GÖZCÜSÜ] Proaktif durum raporu yazılıyor...")
        with self.status_path.open("a", encoding="utf-8") as f:
            f.write(report_text)

    def run(self):
        print(f"[LOG GÖZCÜSÜ] {self.log_path} izleniyor...")
        print(f"Tehdit raporu dosyası : {self.report_path}")
        print(f"Durum raporu dosyası  : {self.status_path}")
        print(f"Analiz raporu dosyası : {self.analysis_path}")
        print(f"JSON veri dosyası     : {self.threat_data_path}")
        print(f"Kural dosyası         : {self.model.rules_path}")
        if self.ai_client is None:
            print("AI analizi: DEVRE DIŞI (OPENROUTER_API_KEY yok)")
        else:
            print(f"AI analizi: AKTİF (OpenRouter, model={self.ai_client['model']})")
        print()

        for raw_line in self._follow_log():
            raw_line = raw_line.rstrip("\n")
            if not raw_line.strip():
                continue

            print(f"[DEBUG] Yeni log satırı algılandı: {raw_line!r}")
            self.total_lines += 1

            parsed = parse_apache_log_line(raw_line)
            rule, _ = self.model.match(raw_line)

            # Parser bozulduysa mümkünse AI ile parse et (rapor kalitesini artırır)
            parsed = self._ensure_parsed(raw_line, parsed)

            # 1) Kural yoksa -> AI-only analiz
            if not rule:
                if self.ai_client is not None:
                    verdict = analyze_with_ai(self.ai_client, raw_line)
                    if verdict:
                        self._write_analysis(raw_line, parsed, verdict)

                        if verdict.get("label") == "attack":
                            pseudo_rule = {
                                "id": "AI_ONLY_DETECTION",
                                "category": verdict.get("probable_category", "Other"),
                                "severity": "medium",
                                "confidence": "ai-only",
                                "description": "Kural eşleşmedi; AI-only tespit."
                            }
                            verdict["source"] = "AI-only"
                            self.act_on_attack(raw_line, parsed, pseudo_rule, verdict)
                    else:
                        # AI cevap veremezse bile: satır işlendi bilgisini analiz raporuna düş
                        fallback = {
                            "label": "unknown",
                            "probable_category": "Unknown",
                            "reason": "AI analysis unavailable/failed; logged for manual review."
                        }
                        self._write_analysis(raw_line, parsed, fallback)
                else:
                    # AI yoksa: yine de analiz raporuna yaz
                    fallback = {
                        "label": "unknown",
                        "probable_category": "Unknown",
                        "reason": "No rule matched and AI is disabled."
                    }
                    self._write_analysis(raw_line, parsed, fallback)

                self._maybe_write_status()
                continue

            # 2) Kural var -> definite ise direkt; suspicious ise AI ile doğrula
            confidence = rule.get("confidence", "definite")

            if confidence == "definite":
                verdict = {
                    "label": "attack",
                    "probable_category": rule.get("category", "Other"),
                    "reason": "High-confidence rule matched."
                }
                self._write_analysis(raw_line, parsed, verdict)

                extra_info = {
                    "source": "rule-based",
                    "label": "attack",
                    "probable_category": rule["category"],
                    "reason": "High-confidence rule matched."
                }
                self.act_on_attack(raw_line, parsed, rule, extra_info)

            elif confidence == "suspicious":
                ai_verdict = analyze_with_ai(self.ai_client, raw_line) if self.ai_client else None

                if ai_verdict:
                    ai_verdict.setdefault("probable_category", rule.get("category", "Other"))
                    ai_verdict.setdefault("reason", "No reason returned.")
                    ai_verdict.setdefault("label", "benign")
                    self._write_analysis(raw_line, parsed, ai_verdict)

                    if ai_verdict.get("label") == "attack":
                        ai_verdict["source"] = "rule + AI"
                        self.act_on_attack(raw_line, parsed, rule, ai_verdict)
                    else:
                        # benign dese bile, şu an tehdit raporuna düşürmüyoruz
                        pass
                else:
                    # AI yok/çöktü -> yine de suspicious raporu + analiz kaydı
                    fallback = {
                        "label": "suspicious",
                        "probable_category": rule.get("category", "Other"),
                        "reason": "Suspicious rule matched, but AI could not confirm."
                    }
                    self._write_analysis(raw_line, parsed, fallback)

                    extra_info = {
                        "source": "rule-only (AI yok / unavailable)",
                        "label": "suspicious",
                        "probable_category": rule["category"],
                        "reason": "Suspicious rule matched, but AI could not confirm (analysis unavailable)."
                    }
                    self.act_on_attack(raw_line, parsed, rule, extra_info)

            self._maybe_write_status()


def main():
    base_dir = Path(__file__).resolve().parent
    log_path = base_dir / "access.log"
    report_path = base_dir / "tehdit_raporu.txt"
    status_path = base_dir / "durum_raporu.txt"
    analysis_path = base_dir / "analiz_raporu.txt"
    threat_data_path = base_dir / "threat_data.jsonl"
    rules_path = base_dir / "rules.json"

    if not log_path.exists():
        print(f"HATA: {log_path} bulunamadı. access.log dosyasını aynı klasöre koy.")
        return

    agent = LogWatcherAgent(
        log_path=log_path,
        report_path=report_path,
        status_path=status_path,
        analysis_path=analysis_path,
        threat_data_path=threat_data_path,
        rules_path=rules_path,
        poll_interval=1.0,
        status_interval_seconds=30,  # demo için kısa
    )

    try:
        agent.run()
    except KeyboardInterrupt:
        print("\n[LOG GÖZCÜSÜ] Ajan durduruldu.")


if __name__ == "__main__":
    main()