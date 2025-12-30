import sys
import os
import subprocess
import threading
import queue
from pathlib import Path

import customtkinter as ctk
from tkinter.scrolledtext import ScrolledText # Will be replaced by CTkTextbox

# Dashboard için kütüphaneler
try:
    import pandas as pd
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    LIBS_AVAILABLE = True
    LIBS_ERROR_MESSAGE = ""
except ImportError as e:
    LIBS_AVAILABLE = False
    LIBS_ERROR_MESSAGE = (
        f"Gerekli kütüphaneler eksik: {e}\n\n"
        "Dashboard özelliğini kullanmak için lütfen bu kütüphaneleri yükleyin:\n"
        "pip install pandas matplotlib"
    )

class LogGozcusuGUI:
    def __init__(self, root: ctk.CTk):
        self.root = root
        self.root.title("Log Gözcüsü - Ajan Arayüzü")
        self.root.geometry("900x600")
        self.root.minsize(600, 400)

        # Ajan çalıştıracağımız process ve thread objeleri
        self.proc: subprocess.Popen | None = None
        self.reader_thread: threading.Thread | None = None
        self.log_queue: "queue.Queue[str]" = queue.Queue()

        # E-posta adresi için bir değişken
        self.email_to = ctk.StringVar()
        self.api_key_var = ctk.StringVar()

        # Proje klasörü (ajan.py ile aynı dizin)
        self.base_dir = Path(__file__).resolve().parent

        # Ekranlar (frame) oluştur
        self._build_start_screen()
        self._build_main_screen()

        # Başlangıçta sadece start_screen görünsün
        self.start_frame.pack(fill="both", expand=True)
        self.main_frame.pack_forget()

        # Queue'yu periyodik olarak kontrol et
        self.root.after(100, self._poll_log_queue)

        # Pencere kapanırken ajanı da durdur
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # -----------------------------
    # Arayüz kurulum ve stil
    # -----------------------------

    def _build_start_screen(self):
        self.start_frame = ctk.CTkFrame(self.root)
        self.start_frame.pack(fill="both", expand=True)


        title = ctk.CTkLabel(
            self.start_frame,
            text="Log Gözcüsü",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title.pack(pady=40, padx=20)

        desc = ctk.CTkLabel(
            self.start_frame,
            text=(
                "Web sunucusu access.log dosyasını izleyen, kural + AI destekli güvenlik ajanı.\n"
                "Uyarıların gönderileceği e-posta adresini girin ve ajanı başlatın."
            ),
            font=ctk.CTkFont(size=12),
            justify="center"
        )
        desc.pack(pady=(10, 20), padx=20)

        # E-posta giriş alanı
        email_frame = ctk.CTkFrame(self.start_frame, fg_color="transparent")
        email_frame.pack(pady=10, fill='x', padx=100)

        email_label = ctk.CTkLabel(
            email_frame,
            text="Uyarı E-Postası:",
        )
        email_label.pack(side="left", padx=(0, 10))

        email_entry = ctk.CTkEntry(
            email_frame,
            textvariable=self.email_to,
            width=250
        )
        email_entry.pack(side="left", fill="x", expand=True)

        run_button = ctk.CTkButton(
            self.start_frame,
            text="Ajanı Çalıştır",
            command=self.start_from_start_screen,
        )
        run_button.pack(pady=40, ipadx=10, ipady=5)

    def _build_main_screen(self):
        self.main_frame = ctk.CTkFrame(self.root, fg_color="transparent")

        # Üst bar (Durdur/Başlat butonları ve durum etiketi)
        top_bar = ctk.CTkFrame(self.main_frame)
        top_bar.pack(side="top", fill="x", pady=(10, 5), padx=10)

        self.status_label = ctk.CTkLabel(
            top_bar,
            text="Durum: Beklemede",
            font=ctk.CTkFont(size=12, weight="bold")
        )
        self.status_label.pack(side="left", padx=10, pady=5)
        self._update_status_label("Beklemede", "default")

        button_frame = ctk.CTkFrame(top_bar, fg_color="transparent")
        button_frame.pack(side="right")
        
        btn_api = ctk.CTkButton(button_frame, text="API Ayarları", command=self._open_api_window, width=100)
        btn_api.pack(side="right", padx=(10, 0))
        
        btn_stop = ctk.CTkButton(button_frame, text="Durdur", command=self.stop_agent, width=100)
        btn_stop.pack(side="right", padx=(5, 0))

        btn_restart = ctk.CTkButton(button_frame, text="Yeniden Başlat", command=self.restart_agent, width=100)
        btn_restart.pack(side="right", padx=5)

        btn_start = ctk.CTkButton(button_frame, text="Başlat", command=self.start_agent, width=100)
        btn_start.pack(side="right", padx=5)


        # Sekmeli yapı (Notebook)
        self.notebook = ctk.CTkTabview(self.main_frame)
        self.notebook.pack(fill="both", expand=True, pady=5, padx=10)

        self.notebook.add("Dashboard")
        self.notebook.add("Canlı Loglar")

        # Log metin alanını Canlı Loglar sekmesine taşı
        self.log_text = ctk.CTkTextbox(
            self.notebook.tab("Canlı Loglar"),
            wrap="word",
            font=("Consolas", 12),
            state="disabled",
            padx=5,
            pady=5,
        )
        self.log_text.pack(fill="both", expand=True)

        # Dashboard içeriğini oluştur
        self._build_dashboard_tab()

    def _open_api_window(self):
        api_window = ctk.CTkToplevel(self.root)
        api_window.title("API Anahtarı Ayarları")
        api_window.geometry("600x450")
        api_window.transient(self.root) # Ana pencerenin üzerinde kal
        
        main_frame = ctk.CTkFrame(api_window, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Açıklama metni
        tr_text = (
            "Yapay Zeka (AI) Analizi için API Anahtarı\n\n"
            "Bu özellik, kural tabanlı tespitlere ek olarak daha derin bir analiz için OpenRouter.ai servisini kullanır.\n\n"
            "Nasıl Alınır?\n"
            "1. openrouter.ai adresine gidin ve kayıt olun.\n"
            "2. Hesabınıza giriş yaptıktan sonra 'Keys' (Anahtarlar) sayfasına gidin.\n"
            "3. Yeni bir anahtar oluşturun ve aşağıya yapıştırın.\n\n"
            "Not: Bu özellik isteğe bağlıdır. Anahtar girmezseniz, program sadece kural tabanlı çalışır."
        )
        
        en_text = (
            "API Key for Artificial Intelligence (AI) Analysis\n\n"
            "This feature uses the OpenRouter.ai service for deeper analysis in addition to rule-based detection.\n\n"
            "How to Obtain?\n"
            "1. Go to openrouter.ai and sign up.\n"
            "2. After logging into your account, navigate to the 'Keys' page.\n"
            "3. Create a new key and paste it below.\n\n"
            "Note: This feature is optional. If you don't enter a key, the program will run in rule-based only mode."
        )

        # Metinleri sekmeli yapıda göster
        text_notebook = ctk.CTkTabview(main_frame)
        text_notebook.pack(fill="both", pady=10, expand=True)
        
        text_notebook.add("Türkçe")
        text_notebook.add("English")

        tr_label = ctk.CTkLabel(text_notebook.tab("Türkçe"), text=tr_text, wraplength=550, justify="left")
        tr_label.pack(padx=10, pady=10, fill="both", expand=True)
        
        en_label = ctk.CTkLabel(text_notebook.tab("English"), text=en_text, wraplength=550, justify="left")
        en_label.pack(padx=10, pady=10, fill="both", expand=True)

        # API Anahtarı giriş alanı
        entry_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        entry_frame.pack(fill='x', pady=10)
        
        api_label = ctk.CTkLabel(entry_frame, text="OpenRouter API Key:")
        api_label.pack(side="left", padx=(0, 10))
        
        api_entry = ctk.CTkEntry(entry_frame, textvariable=self.api_key_var, width=50, show="*")
        api_entry.pack(side="left", fill="x", expand=True)

        # Butonlar
        button_frame_popup = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame_popup.pack(pady=10)

        def save_and_close():
            self._append_log("[INFO] API anahtarı kaydedildi. Değişikliklerin etkili olması için ajanı yeniden başlatın.\n")
            api_window.destroy()

        save_button = ctk.CTkButton(button_frame_popup, text="Kaydet ve Kapat", command=save_and_close)
        save_button.pack()


    def _build_dashboard_tab(self):
        # Dashboard frame'ini notebook'tan al
        dashboard_tab = self.notebook.tab("Dashboard")

        # Eğer kütüphaneler eksikse, uyarı göster ve çık
        if not LIBS_AVAILABLE:
            error_label = ctk.CTkLabel(
                dashboard_tab,
                text=LIBS_ERROR_MESSAGE,
                justify="center",
                font=ctk.CTkFont(size=12)
            )
            error_label.pack(expand=True, fill="both", padx=20, pady=20)
            return
        
        # Ana dataframe'i saklamak için
        self.df_threats = pd.DataFrame()

        # Dashboard için ana kontrol frame'i
        controls_frame = ctk.CTkFrame(dashboard_tab)
        controls_frame.pack(side="top", fill="x", pady=(5, 10))

        btn_refresh = ctk.CTkButton(controls_frame, text="Verileri Yenile", command=self.refresh_dashboard)
        btn_refresh.pack(side="left", padx=10, pady=10)

        # IP Arama
        ctk.CTkLabel(controls_frame, text="IP Ara:").pack(side="left", padx=(10, 5))
        self.ip_search_var = ctk.StringVar()
        ip_entry = ctk.CTkEntry(controls_frame, textvariable=self.ip_search_var)
        ip_entry.pack(side="left", padx=5)
        btn_ip_search = ctk.CTkButton(controls_frame, text="Ara", command=self._apply_filters_and_redraw, width=50)
        btn_ip_search.pack(side="left", padx=5)

        # Kategori Filtresi
        ctk.CTkLabel(controls_frame, text="Kategori:").pack(side="left", padx=(10, 5))
        self.category_filter_var = ctk.StringVar(value="Tümü")
        # OptionMenu'nün anında güncelleme yapması için trace kullanıyoruz
        self.category_filter_var.trace_add("write", lambda *_: self._apply_filters_and_redraw())
        self.category_filter_menu = ctk.CTkOptionMenu(
            controls_frame, 
            variable=self.category_filter_var, 
            values=["Tümü"]
        )
        self.category_filter_menu.pack(side="left", padx=5)


        # Grafiklerin yer alacağı alan
        self.charts_frame = ctk.CTkFrame(dashboard_tab, fg_color="transparent")
        self.charts_frame.pack(side="bottom", fill="both", expand=True)
    
        # Grafik alanlarını oluştur (Dikey olarak alt alta)
        self.chart1_frame = ctk.CTkFrame(self.charts_frame)
        self.chart1_frame.pack(side="top", fill="both", expand=True, pady=(0,5))
        
        self.chart2_frame = ctk.CTkFrame(self.charts_frame)
        self.chart2_frame.pack(side="top", fill="both", expand=True, pady=5)
        
        self.chart3_frame = ctk.CTkFrame(self.charts_frame)
        self.chart3_frame.pack(side="top", fill="both", expand=True, pady=(5,0))

    def _clear_frame(self, frame: ctk.CTkFrame):
        for widget in frame.winfo_children():
            widget.destroy()

    def refresh_dashboard(self):
        """Ana veri dosyasını yeniden okur ve filtreleri güncelleyip çizim yapar."""
        threat_data_path = self.base_dir / "threat_data.jsonl"
        
        for frame in [self.chart1_frame, self.chart2_frame, self.chart3_frame]:
            self._clear_frame(frame)

        if not threat_data_path.exists():
            error_label = ctk.CTkLabel(self.chart1_frame, text="Veri dosyası (threat_data.jsonl) bulunamadı.")
            error_label.pack(pady=20)
            return

        try:
            self.df_threats = pd.read_json(threat_data_path, lines=True)
            if self.df_threats.empty:
                error_label = ctk.CTkLabel(self.chart1_frame, text="Tehdit verisi bulunamadı.")
                error_label.pack(pady=20)
                return
        except Exception as e:
            self.df_threats = pd.DataFrame()
            error_label = ctk.CTkLabel(self.chart1_frame, text=f"Veri okuma hatası:\n{e}")
            error_label.pack(pady=20)
            return
        
        # Kategori filtresi menüsünü güncelle
        categories = ["Tümü"] + sorted(self.df_threats['category'].unique().tolist())
        self.category_filter_menu.configure(values=categories)
        
        # Filtreleri uygula ve çiz
        self._apply_filters_and_redraw()

    def _apply_filters_and_redraw(self):
        """Mevcut filtreleri DataFrame'e uygular ve grafikleri yeniden çizer."""
        if not hasattr(self, 'df_threats') or self.df_threats.empty:
            return

        for frame in [self.chart1_frame, self.chart2_frame, self.chart3_frame]:
            self._clear_frame(frame)

        filtered_df = self.df_threats.copy()

        # IP filtresi
        ip_search = self.ip_search_var.get()
        if ip_search:
            filtered_df = filtered_df[filtered_df['ip'].str.contains(ip_search, na=False)]

        # Kategori filtresi
        category_filter = self.category_filter_var.get()
        if category_filter != "Tümü":
            filtered_df = filtered_df[filtered_df['category'] == category_filter]
        
        if filtered_df.empty:
            error_label = ctk.CTkLabel(self.chart1_frame, text="Filtre ile eşleşen veri bulunamadı.")
            error_label.pack(pady=20)
            return

        # Grafik oluşturma fonksiyonlarını çağır
        self._draw_threats_by_time_chart(filtered_df, self.chart1_frame)
        self._draw_top_ips_chart(filtered_df, self.chart2_frame)
        self._draw_attack_types_chart(filtered_df, self.chart3_frame)
    
    def _draw_attack_types_chart(self, df: "pd.DataFrame", parent_frame: ctk.CTkFrame):
        """Saldırı türlerini gösteren pasta grafik çizer."""
        attack_types = df['category'].value_counts()
        
        try:
            # Tema renklerini doğru şekilde al
            bg_color_tuple = parent_frame.cget("fg_color")
            current_mode = ctk.get_appearance_mode()
            bg_color = bg_color_tuple[1] if current_mode == "Dark" else bg_color_tuple[0]
            
            text_color = ctk.ThemeManager.theme["CTkLabel"]["text_color"]
        except (KeyError, IndexError):
            # Tema okuma başarısız olursa varsayılan renklere dön
            bg_color = "white"
            text_color = "black"

        
        fig, ax = plt.subplots(figsize=(5, 4), dpi=100)
        fig.patch.set_facecolor(bg_color)
        
        wedges, texts, autotexts = ax.pie(
            attack_types, 
            labels=attack_types.index,
            autopct='%1.1f%%',
            startangle=90,
            pctdistance=0.85,
            textprops={'color': text_color}
        )
        
        for autotext in autotexts:
            autotext.set_color("white")
            autotext.set_fontweight('bold')

        centre_circle = plt.Circle((0,0),0.70,fc=bg_color)
        fig.gca().add_artist(centre_circle)

        ax.axis('equal')
        ax.set_title("Saldırı Türü Dağılımı", color=text_color, pad=20)
        
        plt.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=parent_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)

    def _draw_top_ips_chart(self, df: "pd.DataFrame", parent_frame: ctk.CTkFrame):
        """En çok saldıran IP'leri gösteren çubuk grafik çizer."""
        top_ips = df['ip'].value_counts().nlargest(10).sort_values()

        try:
            # Tema renklerini doğru şekilde al
            bg_color_tuple = parent_frame.cget("fg_color")
            current_mode = ctk.get_appearance_mode()
            bg_color = bg_color_tuple[1] if current_mode == "Dark" else bg_color_tuple[0]
            
            text_color = ctk.ThemeManager.theme["CTkLabel"]["text_color"]
            accent_color = ctk.ThemeManager.theme["CTkButton"]["fg_color"]
        except (KeyError, IndexError):
             # Tema okuma başarısız olursa varsayılan renklere dön
            bg_color = "white"
            text_color = "black"
            accent_color = "#3B8ED0" # Default CTk blue
        
        fig, ax = plt.subplots(figsize=(10, 4), dpi=100)
        fig.patch.set_facecolor(bg_color)
        ax.set_facecolor(bg_color)

        ax.tick_params(axis='x', colors=text_color)
        ax.tick_params(axis='y', colors=text_color)
        for spine in ax.spines.values():
            spine.set_edgecolor(text_color)

        ax.set_title("Top 10 Saldırgan IP Adresi", color=text_color)
        
        top_ips.plot(kind='barh', ax=ax, color=accent_color)
        ax.set_xlabel("Saldırı Sayısı", color=text_color)
        ax.set_ylabel("IP Adresi", color=text_color)
        
        plt.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=parent_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)

    def _draw_threats_by_time_chart(self, df: "pd.DataFrame", parent_frame: ctk.CTkFrame):
        """Günün saatine göre tehdit sayısını gösteren çizgi grafik çizer."""
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        threats_by_hour_of_day = df.groupby(df['timestamp'].dt.hour).size().reindex(range(24), fill_value=0)

        try:
            # Tema renklerini doğru şekilde al
            bg_color_tuple = parent_frame.cget("fg_color")
            current_mode = ctk.get_appearance_mode()
            bg_color = bg_color_tuple[1] if current_mode == "Dark" else bg_color_tuple[0]
            
            text_color = ctk.ThemeManager.theme["CTkLabel"]["text_color"]
            accent_color_tuple = ctk.ThemeManager.theme["CTkButton"]["fg_color"]
            accent_color = accent_color_tuple[1] if current_mode == "Dark" else accent_color_tuple[0]
        except (KeyError, IndexError):
            # Tema okuma başarısız olursa varsayılan renklere dön
            bg_color = "white"
            text_color = "black"
            accent_color = "#3B8ED0" # Default CTk blue
        
        fig, ax = plt.subplots(figsize=(10, 4), dpi=100)
        fig.patch.set_facecolor(bg_color)
        ax.set_facecolor(bg_color)

        ax.tick_params(axis='x', colors=text_color, rotation=0)
        ax.tick_params(axis='y', colors=text_color)
        for spine in ax.spines.values():
            spine.set_edgecolor(text_color)
        
        ax.set_title("Günün Saatlerine Göre Saldırı Yoğunluğu", color=text_color)
        ax.set_ylabel("Toplam Tehdit Sayısı", color=text_color)
        ax.set_xlabel("Günün Saati", color=text_color)
        ax.set_xticks(range(0, 24, 2))
        
        threats_by_hour_of_day.plot(kind='line', ax=ax, color=accent_color, marker='o', markersize=4)
        
        fig.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=parent_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)


    def _update_status_label(self, status_text: str, state: str):
        color_map = {
            "running": "#2CC985", # Yeşil
            "stopped": "#E64444", # Kırmızı
            "error": "#E64444",
            "default": ctk.ThemeManager.theme["CTkLabel"]["text_color"]
        }
        self.status_label.configure(
            text=f"Durum: {status_text}",
            text_color=color_map.get(state, color_map["default"])
        )

    def start_from_start_screen(self):
        self.main_frame.pack(fill="both", expand=True)
        self.start_frame.pack_forget()
        self.start_agent()

    def start_agent(self):
        if self.proc is not None and self.proc.poll() is None:
            self._append_log("[INFO] Ajan zaten çalışıyor.\n")
            return

        # Sanal ortamın python'unu kullan
        python_executable = sys.executable
        if ".venv" in python_executable:
             # Eğer zaten venv'de çalışıyorsa direkt kullan
             pass
        else:
            # Değilse, proje dizinindeki venv'i hedefle
            venv_python_path = self.base_dir / ".venv" / "bin" / "python"
            if venv_python_path.exists():
                python_executable = str(venv_python_path)
            else:
                # venv bulunamazsa sistemdeki default'u kullanmayı dene
                pass


        ajan_path = self.base_dir / "ajan.py"
        if not ajan_path.exists():
            self._append_log("[HATA] ajan.py bu klasörde bulunamadı.\n")
            self._update_status_label("ajan.py bulunamadı", "error")
            return

        env = os.environ.copy()
        
        user_email = self.email_to.get()
        if user_email:
            env["ALERT_EMAIL_TO"] = user_email
            self._append_log(f"[INFO] Uyarı e-postası şu adrese ayarlandı: {user_email}\n")
        else:
            self._append_log("[UYARI] E-posta adresi girilmedi. Mail gönderimi devre dışı.\n")

        gui_api_key = self.api_key_var.get()
        if gui_api_key:
            env["LOG_GOZCUSU_GUI_API_KEY"] = gui_api_key
            self._append_log("[INFO] GUI üzerinden yeni bir API anahtarı ayarlandı.\n")
        else:
            self._append_log("[INFO] GUI'den API anahtarı girilmedi, sistemdeki anahtar kullanılacak (varsa).\n")


        try:
            self.proc = subprocess.Popen(
                [python_executable, "-u", str(ajan_path)],
                cwd=self.base_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',
                env=env
            )
        except Exception as e:
            self._append_log(f"[HATA] Ajan başlatılamadı: {e}\n")
            self._update_status_label("Başlatma hatası", "error")
            self.proc = None
            return

        self._update_status_label("Çalışıyor", "running")
        self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self.reader_thread.start()
        self._append_log("[INFO] Ajan başlatıldı.\n")

    def stop_agent(self):
        if self.proc is None or self.proc.poll() is not None:
            self._append_log("[INFO] Ajan zaten çalışmıyor.\n")
            self._update_status_label("Durduruldu", "stopped")
            return

        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self._append_log("[UYARI] Ajan düzgün sonlandırılamadı, zorla kapatıldı.\n")
        except Exception as e:
            self._append_log(f"[UYARI] Ajan sonlandırılırken hata: {e}\n")

        self.proc = None
        self._update_status_label("Durduruldu", "stopped")
        self._append_log("[INFO] Ajan durduruldu.\n")

    def restart_agent(self):
        self._append_log("\n" + "="*20 + " AJAN YENİDEN BAŞLATILIYOR " + "="*20 + "\n\n")
        self.stop_agent()
        self.root.after(200, self.start_agent)

    def _reader_loop(self):
        if self.proc is None or self.proc.stdout is None:
            return

        for line in iter(self.proc.stdout.readline, ''):
            self.log_queue.put(line)

        self.proc.stdout.close()
        self.log_queue.put("[INFO] Ajan süreci sonlandı.\n")
        self.root.after(0, self._update_status_label, "Süreç sonlandı", "stopped")

    def _poll_log_queue(self):
        try:
            while True:
                line = self.log_queue.get_nowait()
                self._append_log(line)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_log_queue)

    def _append_log(self, text: str):
        self.log_text.tag_config("attack", foreground="#E64444")
        self.log_text.tag_config("warning", foreground="#FFA500")
        self.log_text.tag_config("error", foreground="#E64444")
        self.log_text.tag_config("info", foreground="#2CC985")

        tag = None
        if "!" in text:
            tag = "attack"
        elif "[UYARI]" in text:
            tag = "warning"
        elif "[HATA]" in text:
            tag = "error"
        elif "[INFO]" in text or "[LOG GÖZCÜSÜ]" in text:
            tag = "info"


        self.log_text.configure(state="normal")
        if tag:
            self.log_text.insert("end", text, tag)
        else:
            self.log_text.insert("end", text)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def on_close(self):
        self.stop_agent()
        self.root.destroy()


def main():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    
    root = ctk.CTk()
    app = LogGozcusuGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()