#!/usr/bin/env python3
"""
Log Gözcüsü - FastAPI Web Server
=================================
REST API ve WebSocket ile admin erişimi sağlar.

Kullanım:
    python api.py                    # Sunucuyu başlat (localhost:8000)
    python api.py --port 3000        # Farklı port

Endpoints:
    GET  /                           → Web Dashboard
    GET  /api/status                 → Daemon ve sistem durumu
    GET  /api/stats                  → Dashboard istatistikleri
    GET  /api/threats                → Tehdit listesi
    GET  /api/threats/{id}           → Tek tehdit detayı
    POST /api/threats/{id}/feedback  → Feedback gönder
    GET  /api/logs/recent            → Son log satırları
    WS   /api/logs/live              → WebSocket: Real-time log stream
    GET  /api/reports                → Rapor listesi
"""

import os
import sys
import json
import asyncio
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from ajan import ask_security_assistant, create_ai_client

# Global AI Client (Daemon tarafından set edilecek)
global_ai_client = None

from dotenv import load_dotenv
load_dotenv()

# FastAPI imports
try:
    from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Query
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn
except ImportError:
    print("FastAPI yüklü değil. Yüklemek için:")
    print("  pip install fastapi uvicorn[standard] websockets python-multipart")
    sys.exit(1)

# Daemon'un data store'unu import et
try:
    from store import data_store
    from daemon import DaemonConfig, LogDaemon
except ImportError:
    # Daemon import edilemezse bağımsız çalış
    data_store = None
    DaemonConfig = None
    LogDaemon = None
    print("[UYARI] Store/Daemon import edilemedi. Bazı özellikler çalışmayabilir.")

# ==============================================================================
# CONFIG
# ==============================================================================

BASE_DIR = Path(__file__).parent.resolve()
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"

# Port
API_PORT = int(os.environ.get("API_PORT", "8000"))
API_HOST = os.environ.get("API_HOST", "0.0.0.0")

# ==============================================================================
# FASTAPI APP
# ==============================================================================

app = FastAPI(
    title="Log Gözcüsü API",
    description="Siber güvenlik ajan sistemi için REST API",
    version="1.0.0"
)

# CORS - Admin PC'lerden erişim için
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Prod'da spesifik IP'ler eklenebilir
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static dosyaları serve et (dashboard)
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def read_threat_data(limit: int = 100) -> List[Dict]:
    """threat_data.jsonl dosyasından tehditleri oku."""
    threat_file = DATA_DIR / "threat_data.jsonl"
    
    if not threat_file.exists():
        # Eski konumu kontrol et
        old_file = BASE_DIR / "threat_data.jsonl"
        if old_file.exists():
            threat_file = old_file
        else:
            return []
    
    threats = []
    try:
        with open(threat_file, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    threat = json.loads(line.strip())
                    threats.append(threat)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"[API ERROR] Threat data okunamadı: {e}")
    
    # En son eklenenler önce
    return list(reversed(threats[-limit:]))


def read_reports() -> List[Dict]:
    """Rapor dosyalarını listele."""
    reports = []
    
    # Önce reports/, sonra base dir'da ara
    search_dirs = [REPORTS_DIR, BASE_DIR]
    
    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
        
        for f in search_dir.glob("*.txt"):
            # Zaten eklenmişse atla
            if any(r["name"] == f.name for r in reports):
                continue
            
            try:
                stat = f.stat()
                reports.append({
                    "name": f.name,
                    "path": str(f),
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
            except Exception:
                pass
    
    return sorted(reports, key=lambda x: x["modified"], reverse=True)


# ==============================================================================
# API ENDPOINTS
# ==============================================================================

@app.get("/", response_class=HTMLResponse)
async def root():
    """Ana sayfa - Dashboard'a yönlendir."""
    dashboard_file = STATIC_DIR / "dashboard.html"
    
    if dashboard_file.exists():
        return FileResponse(dashboard_file)
    
    # Dashboard yoksa basit info sayfası
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Log Gözcüsü API</title>
        <style>
            body { font-family: system-ui; background: #1a1a2e; color: #eee; padding: 40px; }
            h1 { color: #00d9ff; }
            a { color: #00d9ff; }
            code { background: #16213e; padding: 2px 8px; border-radius: 4px; }
        </style>
    </head>
    <body>
        <h1>🛡️ Log Gözcüsü API</h1>
        <p>API çalışıyor. Dashboard henüz kurulmamış.</p>
        <h2>API Endpoints:</h2>
        <ul>
            <li><code>GET /api/status</code> - Sistem durumu</li>
            <li><code>GET /api/stats</code> - İstatistikler</li>
            <li><code>GET /api/threats</code> - Tehdit listesi</li>
            <li><code>GET /api/logs/recent</code> - Son loglar</li>
            <li><code>WS /api/logs/live</code> - Canlı log stream</li>
            <li><code>GET /api/reports</code> - Raporlar</li>
        </ul>
        <p><a href="/docs">📚 API Dokümantasyonu (Swagger)</a></p>
    </body>
    </html>
    """)


@app.get("/api/status")
async def get_status():
    """Daemon ve sistem durumunu döndür."""
    
    daemon_running = LogDaemon.is_running() if LogDaemon else False
    
    status = {
        "daemon_running": daemon_running,
        "api_running": True,
        "timestamp": datetime.now().isoformat(),
    }
    
    # Data store varsa ek bilgiler
    if data_store:
        ds_status = data_store.get_status()
        status.update({
            "monitoring_active": ds_status.get("running", False),
            "started_at": ds_status.get("started_at"),
            "total_lines_processed": ds_status.get("total_lines", 0),
            "total_threats": ds_status.get("total_threats", 0),
            "last_updated": ds_status.get("last_updated"),
        })
    
    return status


@app.get("/api/stats")
async def get_stats():
    """Dashboard için istatistikler."""
    
    threats = read_threat_data(limit=1000)
    
    # Kategori dağılımı
    categories = {}
    ips = {}
    hourly = {}
    
    for t in threats:
        cat = t.get("category", "Other")
        categories[cat] = categories.get(cat, 0) + 1
        
        ip = t.get("ip")
        if ip:
            ips[ip] = ips.get(ip, 0) + 1
        
        ts = t.get("timestamp", "")
        if ts:
            try:
                hour = ts[11:13] + ":00"  # "14:00" gibi
                hourly[hour] = hourly.get(hour, 0) + 1
            except:
                pass
    
    # Top 10 IP
    top_ips = sorted(ips.items(), key=lambda x: -x[1])[:10]
    
    # Son 24 saat için saatlik dağılım
    hourly_sorted = dict(sorted(hourly.items()))
    
    return {
        "total_threats": len(threats),
        "categories": categories,
        "top_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
        "hourly_distribution": hourly_sorted,
        "severity_distribution": _count_by_field(threats, "severity"),
        "source_distribution": _count_by_field(threats, "source"),
    }


def _count_by_field(threats: List[Dict], field: str) -> Dict[str, int]:
    """Belirli bir alana göre sayım yap."""
    counts = {}
    for t in threats:
        val = t.get(field, "unknown")
        counts[val] = counts.get(val, 0) + 1
    return counts


@app.get("/api/threats")
async def get_threats(
    limit: int = Query(50, ge=1, le=500),
    category: Optional[str] = None,
    severity: Optional[str] = None,
    ip: Optional[str] = None,
):
    """Tehdit listesini döndür (filtrelenebilir)."""
    
    threats = read_threat_data(limit=500)
    
    # Filtrele
    if category:
        threats = [t for t in threats if t.get("category") == category]
    if severity:
        threats = [t for t in threats if t.get("severity") == severity]
    if ip:
        threats = [t for t in threats if t.get("ip") == ip]
    
    return {
        "total": len(threats),
        "threats": threats[:limit]
    }


@app.get("/api/threats/{threat_id}")
async def get_threat_by_id(threat_id: str):
    """Belirli bir tehdidin detayını döndür."""
    
    threats = read_threat_data(limit=1000)
    
    for i, t in enumerate(threats):
        if t.get("rule_id") == threat_id or str(i) == threat_id:
            return t
    
    raise HTTPException(status_code=404, detail="Tehdit bulunamadı")


@app.post("/api/threats/{index}/feedback")
async def submit_feedback(index: int, feedback: str = Query(..., pattern="^(true_positive|false_positive)$")):
    """Tehdit için feedback gönder (true/false positive)."""
    
    threat_file = DATA_DIR / "threat_data.jsonl"
    if not threat_file.exists():
        threat_file = BASE_DIR / "threat_data.jsonl"
    
    if not threat_file.exists():
        raise HTTPException(status_code=404, detail="Threat data dosyası bulunamadı")
    
    # Dosyayı oku, güncelle, yeniden yaz
    try:
        with open(threat_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        
        if index < 0 or index >= len(lines):
            raise HTTPException(status_code=404, detail="Geçersiz index")
        
        threat = json.loads(lines[index])
        threat["feedback"] = feedback
        lines[index] = json.dumps(threat, ensure_ascii=False) + "\n"
        
        with open(threat_file, "w", encoding="utf-8") as f:
            f.writelines(lines)
            
        return {"status": "ok", "feedback": feedback}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/threats/block")
async def block_ip(payload: dict):
    """IP engelleme isteği (Daemon üzerinden)."""
    ip = payload.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="IP adresi gerekli")
        
    if not data_store or not data_store.active_agent:
        raise HTTPException(status_code=503, detail="Active Defense agent aktif değil")
        
    # Agent üzerinden engelle
    success = data_store.active_agent.defender.block_ip(ip, reason="GUI Manuel Engel")
    if success:
        return {"status": "blocked", "ip": ip}
    else:
        return {"status": "failed", "detail": "Engelleme başarısız (Loglara bakınız)"}



@app.get("/api/logs/recent")
async def get_recent_logs(limit: int = Query(100, ge=1, le=500)):
    """Son log satırlarını döndür."""
    
    if data_store:
        logs = data_store.get_recent_logs(limit)
        # Eğer hafızada log varsa bunları dön (zaten dict formatında)
        if logs:
            return {"logs": logs, "source": "live"}
    
    # Data store yoksa veya boşsa dosyadan oku
    log_file = BASE_DIR / "logs/access.log"
    if not log_file.exists():
        # Fallback
        log_file = BASE_DIR / "data/access.log"
    
    file_logs = []
    if log_file.exists():
        try:
            # Dosyadan son N satırı oku
            # Bu basit bir okuma, tail işlemi için dosya boyutu büyükse optimize edilebilir
            # Şimdilik son 2000 byte'ı okuyup satırlara bölelim
            file_size = log_file.stat().st_size
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                if file_size > 50000:
                    f.seek(file_size - 50000)
                lines = f.readlines()
                # Son satırları al
                raw_lines = lines[-limit:]
                
                # Dict formatına çevir (Dosyadan okunanlarda tehdit bilgisi yok)
                for line in raw_lines:
                    line = line.strip()
                    if line:
                        file_logs.append({
                            "content": line,
                            "timestamp": None,
                            "is_threat": False, # Bilmiyoruz
                            "severity": "normal"
                        })
        except Exception as e:
            print(f"Log okuma hatası: {e}")
            return {"logs": file_logs, "source": "file", "error": str(e)} # Corrected return statement
            
    return {"logs": file_logs, "source": "file"}

@app.get("/api/logs/system")
def get_system_logs(limit: int = 50):
    """Sistem/Daemon loglarını getir (GUI için)."""
    if data_store:
        logs = data_store.get_system_logs(limit)
        return {"logs": logs}
    return {"logs": []} # Corrected return statement


@app.websocket("/api/logs/live")
async def websocket_logs(websocket: WebSocket):
    """WebSocket: Real-time log stream."""
    
    await websocket.accept()
    
    if not data_store:
        await websocket.send_json({"error": "Live streaming mevcut değil"})
        await websocket.close()
        return
    
    log_queue = data_store.get_log_queue()
    
    try:
        while True:
            # Queue'dan log al (timeout ile)
            try:
                # asyncio ile blocking queue'u handle et
                loop = asyncio.get_event_loop()
                line = await loop.run_in_executor(None, lambda: log_queue.get(timeout=1))
                
                await websocket.send_json({
                    "type": "log",
                    "data": line,
                    "timestamp": datetime.now().isoformat()
                })
            except:
                # Timeout - heartbeat gönder
                await websocket.send_json({"type": "heartbeat"})
            
    except WebSocketDisconnect:
        # manager.disconnect(websocket)  <-- manager tanımlı değil, zaten disconnect exception
        # print("[WS] Client disconnected")
        pass
    except Exception as e:
        # manager.disconnect(websocket)
        print(f"[WS ERROR] {e}")


@app.get("/api/reports")
async def get_reports():
    """Rapor dosyalarını listele."""
    return {"reports": read_reports()}


@app.get("/api/reports/{filename}")
async def get_report_content(filename: str):
    """Belirli bir raporun içeriğini döndür."""
    
    # Güvenlik: Path traversal engellemek için sadece dosya adı
    safe_name = Path(filename).name
    
    # Önce reports/, sonra base dir'da ara
    for search_dir in [REPORTS_DIR, BASE_DIR]:
        file_path = search_dir / safe_name
        if file_path.exists() and file_path.suffix == ".txt":
            try:
                content = file_path.read_text(encoding="utf-8")
                return {"filename": safe_name, "content": content}
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
    
    raise HTTPException(status_code=404, detail="Rapor bulunamadı")



# ==============================================================================
# CHAT AI ENDPOINT
# ==============================================================================

class ChatRequest(BaseModel):
    message: str
    context: Optional[str] = None

@app.post("/api/chat")
async def chat_with_ai(request: ChatRequest):
    """AI Asistanı ile sohbet et."""
    
    # Client yoksa oluşturmayı dene (bağımsız çalışma durumu)
    global global_ai_client
    if not global_ai_client:
        try:
            global_ai_client = create_ai_client()
        except:
            pass
            
    if not global_ai_client:
        return {"response": "AI Asistanı şu anda aktif değil (API Anahtarı eksik)."}
        
    # Context (Son loglar veya tehditler)
    context_data = request.context
    if not context_data:
        # Otomatik context oluştur: Son 5 tehdit
        try:
            recent_threats = read_threat_data(limit=5)
            context_data = json.dumps(recent_threats, indent=2, ensure_ascii=False)
        except:
            context_data = "No threat data available."
            
    response = ask_security_assistant(global_ai_client, context_data, request.message)
    return {"response": response}

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Log Gözcüsü API Server")
    parser.add_argument("--port", type=int, default=API_PORT, help="Port numarası")
    parser.add_argument("--host", type=str, default=API_HOST, help="Host adresi")
    parser.add_argument("--reload", action="store_true", help="Auto-reload (development)")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("  LOG GÖZCÜSÜ - API SERVER")
    print("=" * 60)
    print(f"  URL: http://{args.host}:{args.port}")
    print(f"  Docs: http://{args.host}:{args.port}/docs")
    print("=" * 60)
    
    uvicorn.run(
        "api:app",
        host=args.host,
        port=args.port,
        reload=args.reload
    )


if __name__ == "__main__":
    main()
