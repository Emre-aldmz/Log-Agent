#!/usr/bin/env python3
import customtkinter as ctk
import tkinter as tk
import requests
import json
import os
import signal
import subprocess
import time
from datetime import datetime
from threading import Thread
from typing import Optional, Dict
from dotenv import load_dotenv, set_key

# ==============================================================================
# CONFIG
# ==============================================================================
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

API_BASE_URL = "http://localhost:8000"
ENV_FILE = ".env"

class ApiClient:
    """Log Gözcüsü API ile iletişim kuran istemci sınıfı."""
    
    @staticmethod
    def get_status() -> Optional[Dict]:
        try:
            response = requests.get(f"{API_BASE_URL}/api/status", timeout=2)
            if response.status_code == 200:
                return response.json()
        except:
            return None
        return None

    @staticmethod
    def get_recent_logs(limit=50) -> list:
        try:
            response = requests.get(f"{API_BASE_URL}/api/logs/recent?limit={limit}", timeout=2)
            if response.status_code == 200:
                return response.json().get("logs", [])
        except:
            return []
        return []

    @staticmethod
    def get_threats(limit=20) -> list:
        try:
            response = requests.get(f"{API_BASE_URL}/api/threats?limit={limit}", timeout=2)
            if response.status_code == 200:
                return response.json().get("threats", [])
        except:
            return []
        return []

    @staticmethod
    def send_feedback(index: int, feedback: str) -> bool:
        try:
            url = f"{API_BASE_URL}/api/threats/{index}/feedback?feedback={feedback}"
            response = requests.post(url, timeout=2)
            return response.status_code == 200
        except:
            return False

    @staticmethod
    def get_system_logs(limit=50) -> list:
        try:
            response = requests.get(f"{API_BASE_URL}/api/logs/system?limit={limit}", timeout=2)
            if response.status_code == 200:
                return response.json().get("logs", [])
        except:
            return []
        return []

    @staticmethod
    def block_ip(ip: str) -> bool:
        try:
            response = requests.post(f"{API_BASE_URL}/api/threats/block", json={"ip": ip}, timeout=5)
            if response.status_code == 200:
                result = response.json()
                return result.get("status") == "blocked"
            return False
        except:
            return False

    @staticmethod
    def ask_ai(message: str, context: Optional[str] = None) -> str:
        try:
            payload = {"message": message, "context": context}
            response = requests.post(f"{API_BASE_URL}/api/chat", json=payload, timeout=30)
            if response.status_code == 200:
                return response.json().get("response", "AI'dan cevap alınamadı.")
            return f"Hata: {response.status_code} - {response.text}"
        except Exception as e:
            return f"Bağlantı hatası: {e}"

class AdminPanel(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("Log Gözcüsü - Yönetim Paneli")
        self.geometry("1100x700")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Assets & State
        self.daemon_pid = self._find_daemon_pid()
        self.api_online = False
        self.running = True
        
        # Load Env
        load_dotenv(ENV_FILE)

        # Sidebar
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(6, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="🛡️ Log Gözcüsü", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        self.subtitle_label = ctk.CTkLabel(self.sidebar_frame, text="Admin Control Panel", font=ctk.CTkFont(size=12))
        self.subtitle_label.grid(row=1, column=0, padx=20, pady=(0, 20))

        # Navigation Buttons
        self.btn_status = self._create_nav_btn("Durum & Kontrol", self.show_status_tab, 2)
        self.btn_logs = self._create_nav_btn("Sistem Kayıtları", self.show_logs_tab, 3)
        self.btn_threats = self._create_nav_btn("Tehdit Yönetimi", self.show_threats_tab, 4)
        self.btn_settings = self._create_nav_btn("⚙️ Ayarlar", self.show_settings_tab, 5)
        
        # Bottom Actions
        self.appearance_mode_label = ctk.CTkLabel(self.sidebar_frame, text="Tema:", anchor="w")
        self.appearance_mode_label.grid(row=7, column=0, padx=20, pady=(10, 0))
        self.appearance_mode_optionemenu = ctk.CTkOptionMenu(self.sidebar_frame, values=["System", "Dark", "Light"],
                                                               command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.grid(row=8, column=0, padx=20, pady=(10, 20))

        # Main Area
        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Tabs
        self.frames = {}
        for F in (StatusTab, LogsTab, ThreatsTab, SettingsTab):
            page_name = F.__name__
            frame = F(parent=self.main_frame, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        # Start with Status Tab
        self.show_status_tab()

        # Background Thread for connectivity check
        Thread(target=self._monitor_system, daemon=True).start()

    def _create_nav_btn(self, text, command, row):
        btn = ctk.CTkButton(self.sidebar_frame, text=text, command=command, fg_color="transparent", 
                            text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"), anchor="w")
        btn.grid(row=row, column=0, padx=20, pady=5, sticky="ew")
        return btn

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()
        if hasattr(frame, "refresh"):
            frame.refresh()

    def show_status_tab(self): self.show_frame("StatusTab")
    def show_logs_tab(self): self.show_frame("LogsTab")
    def show_threats_tab(self): self.show_frame("ThreatsTab")
    def show_settings_tab(self): self.show_frame("SettingsTab")

    def change_appearance_mode_event(self, new_appearance_mode: str):
        ctk.set_appearance_mode(new_appearance_mode)

    def _find_daemon_pid(self):
        try:
            result = subprocess.check_output(["pgrep", "-f", "daemon.py"])
            pids = result.decode().strip().split("\n")
            return int(pids[0]) if pids else None
        except:
            return None

    def _monitor_system(self):
        while self.running:
            self.daemon_pid = self._find_daemon_pid()
            status = ApiClient.get_status()
            self.api_online = status is not None and status.get("api_running", False)
            status_tab = self.frames["StatusTab"]
            status_tab.update_indicators(self.daemon_pid is not None, self.api_online, status)
            time.sleep(2)


class StatusTab(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Header
        self.label_title = ctk.CTkLabel(self, text="Sistem Durumu", font=ctk.CTkFont(size=24, weight="bold"))
        self.label_title.grid(row=0, column=0, columnspan=2, padx=20, pady=(0, 20), sticky="w")

        # Daemon Card
        self.frame_daemon = self._create_status_card(1, "Arka Plan Servisi (Daemon)", "Kontrol ediliyor...")
        self.btn_daemon_start = ctk.CTkButton(self.frame_daemon, text="Başlat", command=self.start_daemon, fg_color="green")
        self.btn_daemon_start.grid(row=2, column=0, padx=10, pady=10)
        self.btn_daemon_stop = ctk.CTkButton(self.frame_daemon, text="Durdur", command=self.stop_daemon, fg_color="red")
        self.btn_daemon_stop.grid(row=2, column=1, padx=10, pady=10)

        # API Card
        self.frame_api = self._create_status_card(2, "Web API & Dashboard", "Kontrol ediliyor...")
        self.lbl_api_url = ctk.CTkLabel(self.frame_api, text="URL: http://localhost:8000")
        self.lbl_api_url.grid(row=2, column=0, columnspan=2, pady=5)
        
        # Threat Counter (Big)
        self.lbl_threat_count = ctk.CTkLabel(self.frame_api, text="Toplam Tehdit: 0", font=ctk.CTkFont(size=18, weight="bold"), text_color="orange")
        self.lbl_threat_count.grid(row=3, column=0, columnspan=2, pady=5)
        
        self.btn_open_web = ctk.CTkButton(self.frame_api, text="Tarayıcıda Aç", command=lambda: subprocess.Popen(["xdg-open", "http://localhost:8000"]))
        self.btn_open_web.grid(row=4, column=0, columnspan=2, pady=10)

        # Info
        self.textbox_log = ctk.CTkTextbox(self, width=400, height=150, state="disabled")
        self.textbox_log.grid(row=3, column=0, columnspan=2, padx=20, pady=20, sticky="nsew")
        self.log("Admin Paneli başlatıldı.")

    def _create_status_card(self, row, title, status):
        frame = ctk.CTkFrame(self)
        frame.grid(row=row, column=0, columnspan=2, padx=20, pady=10, sticky="ew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        
        lbl_title = ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=16, weight="bold"))
        lbl_title.grid(row=0, column=0, columnspan=2, pady=(10, 5))
        
        lbl_status = ctk.CTkLabel(frame, text=status, font=ctk.CTkFont(size=14))
        lbl_status.grid(row=1, column=0, columnspan=2, pady=(0, 10))
        
        frame.status_label = lbl_status
        return frame

    def update_indicators(self, daemon_running, api_running, api_data):
        # Daemon
        daemon_lbl = self.frame_daemon.status_label
        if daemon_running:
            daemon_lbl.configure(text="✅ ÇALIŞIYOR", text_color="green")
            self.btn_daemon_start.configure(state="disabled")
            self.btn_daemon_stop.configure(state="normal")
        else:
            daemon_lbl.configure(text="❌ DURDU", text_color="red")
            self.btn_daemon_start.configure(state="normal")
            self.btn_daemon_stop.configure(state="disabled")
            
        # API
        api_lbl = self.frame_api.status_label
        if api_running:
            api_lbl.configure(text="✅ ONLINE", text_color="green")
            if api_data:
                count = api_data.get('total_threats', 0)
                self.lbl_threat_count.configure(text=f"Toplam Tehdit: {count}")
        else:
            api_lbl.configure(text="❌ OFFLINE", text_color="red")
            self.lbl_threat_count.configure(text="Toplam Tehdit: -")

    def start_daemon(self):
        try:
            subprocess.Popen([".venv/bin/python", "daemon.py"], start_new_session=True)
            self.log("Daemon başlatma komutu verildi...")
            time.sleep(1)
        except Exception as e:
            self.log(f"Başlatma hatası: {e}")

    def stop_daemon(self):
        if self.controller.daemon_pid:
            try:
                os.kill(self.controller.daemon_pid, signal.SIGTERM)
                self.log(f"Daemon durduruldu (PID: {self.controller.daemon_pid})")
            except Exception as e:
                self.log(f"Durdurma hatası: {e}")
        else:
            self.log("Durdurulacak işlem bulunamadı.")

    def log(self, text):
        self.textbox_log.configure(state="normal")
        self.textbox_log.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {text}\n")
        self.textbox_log.see("end")
        self.textbox_log.configure(state="disabled")


class LogsTab(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=20, pady=20, sticky="ew")
        
        ctk.CTkLabel(header_frame, text="Sistem/Daemon Kayıtları", font=ctk.CTkFont(size=24, weight="bold")).pack(side="left")
        
        self.auto_refresh = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(header_frame, text="Otomatik Yenile (3sn)", variable=self.auto_refresh).pack(side="right", padx=10)
        ctk.CTkButton(header_frame, text="Yenile", command=self.refresh).pack(side="right")

        self.textbox = ctk.CTkTextbox(self, font=("Courier", 12), state="disabled")
        self.textbox.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="nsew")
        
        # Right Click Menu
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="🤖 AI ile Açıkla (Explain)", command=self.explain_selection)
        
        self.textbox.bind("<Button-3>", self.show_context_menu)

        
        # Start auto-refresh loop
        self.after(3000, self._auto_refresh_loop)

    def _auto_refresh_loop(self):
        if self.auto_refresh.get() and self.winfo_exists():
            self.refresh()
        self.after(3000, self._auto_refresh_loop)

    def refresh(self):
        if not self.winfo_exists(): return
        
        # Sadece System Logs çek
        system_logs = ApiClient.get_system_logs(limit=100)
        
        # Tarihe göre sırala (varsa)
        def get_sort_key(entry):
            ts = entry.get('timestamp')
            return ts if ts else "0"
            
        system_logs.sort(key=get_sort_key)
        
        self.textbox.configure(state="normal")
        self.textbox.delete("1.0", "end")
        
        if not system_logs:
            self.textbox.insert("end", "-- Sistem kaydı bulunamadı --\n")
        else:
            for entry in system_logs:
                line = entry.get("content", "")
                ts = entry.get("timestamp", "").split("T")[-1][:8] if entry.get("timestamp") else ""
                level = entry.get('level', 'INFO').upper()
                
                self.textbox.insert("end", f"[{ts}] [{level}] {line}\n")
                self.textbox.insert("end", "-" * 100 + "\n") # Ayırıcı Çizgi
        
        self.textbox.configure(state="disabled")

    def show_context_menu(self, event):
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def explain_selection(self):
        try:
            # Seçili metni al
            text = self.textbox.selection_get()
            if not text.strip():
                return
        except:
            return

        # Pop-up aç ve bekle
        popup = ExplanationPopup(self, text)


class ThreatsTab(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=20, pady=20, sticky="ew")
        
        ctk.CTkLabel(header_frame, text="Tehdit Yönetimi", font=ctk.CTkFont(size=24, weight="bold")).pack(side="left")
        ctk.CTkButton(header_frame, text="Yenile", command=self.refresh).pack(side="right")

        self.scroll_frame = ctk.CTkScrollableFrame(self)
        self.scroll_frame.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")

    def refresh(self):
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()

        threats = ApiClient.get_threats(limit=50)
        if not threats:
            ctk.CTkLabel(self.scroll_frame, text="Henüz tehdit tespit edilmedi.").pack(pady=20)
            return

        for idx, threat in enumerate(threats):
            self._create_threat_card(idx, threat)

    def _create_threat_card(self, index, threat):
        card = ctk.CTkFrame(self.scroll_frame)
        card.pack(fill="x", pady=5, padx=5)
        
        # Extract data
        timestamp = threat.get('timestamp', '-')
        category = threat.get('category', 'Unknown')
        rule_id = threat.get('rule_id', '-')
        severity = threat.get('severity', 'UNK')
        ip = threat.get('ip', '-')
        log_line = threat.get('log_entry', '')
        
        # Robust Parsing
        method = "-"
        resource = "-"
        query = "-"
        status = "-"
        ua = "-"
        
        # Try split by quotes first: IP - - [Date] "Request" Status Size "Referer" "UA"
        parts = log_line.split('"')
        if len(parts) >= 6:
            # Request Part (Method URL Protocol)
            req_parts = parts[1].split()
            if len(req_parts) >= 2:
                method = req_parts[0]
                full_url = req_parts[1]
                if '?' in full_url:
                    try:
                        resource, query = full_url.split('?', 1)
                    except:
                        resource = full_url
                else:
                    resource = full_url
            
            # Status Part
            try:
                status = parts[2].strip().split()[0]
            except: pass
            
            # User Agent
            ua = parts[5]

        # Format Text
        try:
             # Clean up query string decoding if needed
             import urllib.parse
             query = urllib.parse.unquote_plus(query)
        except: pass

        report_text = (
            "--------------------------------------------------------------------------------\n"
            f"[{timestamp}] UYARI: {category} tespit edildi! (kural={rule_id}, seviye={severity})\n"
            f"Açıklama : {category} saldırı kalıbı.\n"
            f"IP       : {ip}\n"
            f"Method   : {method}\n"
            f"Kaynak   : {resource}\n"
            f"Sorgu    : {query}\n"
            f"Status   : {status}\n"
            f"User-Ag. : {ua}\n"
            f"Log Satırı: {log_line}\n"
            "--------------------------------------------------------------------------------"
        )

        # Display Text
        text_widget = ctk.CTkTextbox(card, height=180, font=("Courier", 11), wrap="none")
        text_widget.pack(fill="x", padx=5, pady=5)
        text_widget.insert("1.0", report_text)
        text_widget.configure(state="disabled")
        
        # Actions
        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(fill="x", padx=5, pady=5)
        
        fb = threat.get("feedback")
        if fb:
            ctk.CTkLabel(btn_frame, text=f"Geri Bildirim: {fb}", text_color="orange").pack(side="left")
        else:
            ctk.CTkButton(btn_frame, text="✅ Doğru Tespit", width=120, height=24, fg_color="green",
                          command=lambda i=index: self.send_fb(i, "true_positive")).pack(side="left", padx=5)
            ctk.CTkButton(btn_frame, text="⚠️ Yanlış Alarm", width=120, height=24, fg_color="red",
                          command=lambda i=index: self.send_fb(i, "false_positive")).pack(side="left", padx=5)
            
            # Manuel Engelleme Butonu
            ctk.CTkButton(btn_frame, text="🚫 Engelle", width=120, height=24, fg_color="darkred",
                          command=lambda t=threat: self.block_threat(t)).pack(side="left", padx=5)

    def send_fb(self, index, feedback):
        if ApiClient.send_feedback(index, feedback):
            self.refresh()
            
    def block_threat(self, threat):
        """Tehdit kaynağını engellemek için API çağrısı."""
        ip = threat.get('ip')
        if not ip or ip == "-":
            print("[GUI] Geçersiz IP, engellenemez.")
            return

        if ApiClient.block_ip(ip):
            print(f"[GUI] {ip} başarıyla engellendi.")
            # Belki butonu disable edebiliriz ama refresh olunca zaten yeniden çiziliyor
            # Basit bir pop-up veya renk değişimi yapılabilir ama şimdilik konsol/log yeterli.
        else:
            print(f"[GUI] {ip} engellenemedi!")


class SettingsTab(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1) 
        
        # Header
        ctk.CTkLabel(self, text="Ayarlar", font=ctk.CTkFont(size=24, weight="bold")).grid(row=0, column=0, columnspan=2, padx=20, pady=20, sticky="w")

        # --- AI Settings ---
        ai_frame = ctk.CTkFrame(self)
        ai_frame.grid(row=1, column=0, columnspan=2, padx=20, pady=10, sticky="ew")
        
        ctk.CTkLabel(ai_frame, text="Yapay Zeka (AI) Ayarları", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=10, pady=10)
        
        self.entry_ai_key = self._create_input(ai_frame, "OpenRouter API Key:", os.getenv("OPENROUTER_API_KEY", ""))

        # --- Email Settings ---
        email_frame = ctk.CTkFrame(self)
        email_frame.grid(row=2, column=0, columnspan=2, padx=20, pady=10, sticky="ew")
        
        ctk.CTkLabel(email_frame, text="E-posta Bildirim Ayarları (SMTP)", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=10, pady=10)
        
        self.entry_smtp_server = self._create_input(email_frame, "SMTP Sunucusu:", os.getenv("SMTP_SERVER", "smtp.gmail.com"))
        self.entry_smtp_port = self._create_input(email_frame, "SMTP Port:", os.getenv("SMTP_PORT", "587"))
        self.entry_sender = self._create_input(email_frame, "Gönderen E-posta:", os.getenv("SENDER_EMAIL", ""))
        self.entry_password = self._create_input(email_frame, "Gönderen Şifresi:", os.getenv("SENDER_PASSWORD", ""), show="*")
        self.entry_receiver = self._create_input(email_frame, "Alıcı E-posta:", os.getenv("RECEIVER_EMAIL", ""))

        # Actions
        btn_save = ctk.CTkButton(self, text="💾 Ayarları Kaydet", command=self.save_settings, width=200, height=40)
        btn_save.grid(row=3, column=0, columnspan=2, pady=30)
        
        self.lbl_msg = ctk.CTkLabel(self, text="", text_color="green")
        self.lbl_msg.grid(row=4, column=0, columnspan=2)

    def _create_input(self, parent, label_text, default_val, show=None):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(frame, text=label_text, width=150, anchor="w").pack(side="left")
        entry = ctk.CTkEntry(frame, width=300, show=show)
        entry.pack(side="left", padx=10)
        if default_val:
            entry.insert(0, default_val)
        return entry

    def save_settings(self):
        try:
            # AI
            set_key(ENV_FILE, "OPENROUTER_API_KEY", self.entry_ai_key.get())
            
            # Email
            set_key(ENV_FILE, "SMTP_SERVER", self.entry_smtp_server.get())
            set_key(ENV_FILE, "SMTP_PORT", self.entry_smtp_port.get())
            set_key(ENV_FILE, "SENDER_EMAIL", self.entry_sender.get())
            set_key(ENV_FILE, "SENDER_PASSWORD", self.entry_password.get())
            set_key(ENV_FILE, "RECEIVER_EMAIL", self.entry_receiver.get())
            
            self.lbl_msg.configure(text="Ayarlar başarıyla kaydedildi! (Yeniden başlatma gerekebilir)", text_color="green")
        except Exception as e:
            self.lbl_msg.configure(text=f"Hata: {e}", text_color="red")




class ExplanationPopup(ctk.CTkToplevel):
    def __init__(self, parent, log_text):
        super().__init__(parent)
        self.title("AI Log Analizi")
        self.geometry("600x400")
        self.log_text = log_text
        
        # UI
        self.label = ctk.CTkLabel(self, text="AI Analiz Ediyor...", font=ctk.CTkFont(size=16, weight="bold"))
        self.label.pack(pady=10)
        
        self.textbox = ctk.CTkTextbox(self, width=550, height=300)
        self.textbox.pack(pady=10)
        
        # Thread ile sorgu at (GUI donmasın)
        Thread(target=self.fetch_explanation, daemon=True).start()
        
    def fetch_explanation(self):
        response = ApiClient.ask_ai(
            message="Bu log satırını analiz et. Saldırı mı, ne tür bir aktivite? Risk seviyesi nedir? Türkçe açıkla.",
            context=self.log_text
        )
        
        self.textbox.insert("1.0", response)
        self.label.configure(text="Analiz Sonucu")


if __name__ == "__main__":
    app = AdminPanel()
    app.mainloop()