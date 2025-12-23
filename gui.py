import sys
import os
import subprocess
import threading
import queue
from pathlib import Path

import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

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
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Log Gözcüsü - Ajan Arayüzü")
        self.root.geometry("900x600")
        self.root.minsize(600, 400)

        # Ajan çalıştıracağımız process ve thread objeleri
        self.proc: subprocess.Popen | None = None
        self.reader_thread: threading.Thread | None = None
        self.log_queue: "queue.Queue[str]" = queue.Queue()

        # E-posta adresi için bir değişken
        self.email_to = tk.StringVar()
        self.api_key_var = tk.StringVar()

        # Proje klasörü (ajan.py ile aynı dizin)
        self.base_dir = Path(__file__).resolve().parent

        # Arayüz stilini ve renklerini ayarla
        self._setup_style()

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

    def _setup_style(self):
        self.colors = {
            "bg_dark": "#2E2E2E",
            "bg_light": "#3C3C3C",
            "fg_light": "#F0F0F0",
            "accent_green": "#2ECC71",
            "accent_red": "#E74C3C",
        }

        self.root.configure(bg=self.colors["bg_dark"])

        style = ttk.Style()
        # Butonlar hariç diğer widget'ları koyu tema yap
        style.configure("TFrame", background=self.colors["bg_dark"])
        style.configure(
            "TLabel",
            background=self.colors["bg_dark"],
            foreground=self.colors["fg_light"],
            font=("Segoe UI", 10)
        )
        style.configure(
            "Title.TLabel",
            font=("Segoe UI", 24, "bold"),
        )
        style.configure(
            "Desc.TLabel",
            font=("Segoe UI", 11),
        )
        # Entry widget'ı için stil
        style.configure(
            "TEntry",
            fieldbackground=self.colors["bg_light"],
            foreground=self.colors["fg_light"],
            insertcolor=self.colors["fg_light"],
            borderwidth=1,
            relief="solid",
        )

    def _build_start_screen(self):
        self.start_frame = ttk.Frame(self.root, padding=40)

        title = ttk.Label(
            self.start_frame,
            text="Log Gözcüsü",
            style="Title.TLabel"
        )
        title.pack(pady=20)

        desc = ttk.Label(
            self.start_frame,
            text=(
                "Web sunucusu access.log dosyasını izleyen, kural + AI destekli güvenlik ajanı.\n"
                "Uyarıların gönderileceği e-posta adresini girin ve ajanı başlatın."
            ),
            style="Desc.TLabel",
            justify="center"
        )
        desc.pack(pady=(10, 20))

        # E-posta giriş alanı
        email_frame = ttk.Frame(self.start_frame)
        email_frame.pack(pady=10, fill='x', padx=50)

        email_label = ttk.Label(
            email_frame,
            text="Uyarı E-Postası:",
            font=("Segoe UI", 10),
        )
        email_label.pack(side="left", padx=(0, 10))

        email_entry = ttk.Entry(
            email_frame,
            textvariable=self.email_to,
            font=("Segoe UI", 10),
            width=40
        )
        email_entry.pack(side="left", fill="x", expand=True)


        # Orjinal, stilsiz buton
        run_button = ttk.Button(
            self.start_frame,
            text="Ajanı Çalıştır",
            command=self.start_from_start_screen,
        )
        run_button.pack(pady=20, ipadx=10, ipady=5)

    def _build_main_screen(self):
        self.main_frame = ttk.Frame(self.root, padding=10)

        # Üst bar (Durdur/Başlat butonları ve durum etiketi)
        top_bar = ttk.Frame(self.main_frame)
        top_bar.pack(side="top", fill="x", pady=(0, 5))

        self.status_label = ttk.Label(
            top_bar,
            text="Durum: Beklemede",
            font=("Segoe UI", 11, "bold")
        )
        self.status_label.pack(side="left", padx=5, pady=5)
        self._update_status_label("Beklemede", "default")

        button_frame = ttk.Frame(top_bar)
        button_frame.pack(side="right")
        
        btn_api = ttk.Button(button_frame, text="API Ayarları", command=self._open_api_window)
        btn_api.pack(side="right", padx=(10, 0))
        
        btn_stop = ttk.Button(button_frame, text="Durdur", command=self.stop_agent)
        btn_stop.pack(side="right", padx=(5, 0))

        btn_restart = ttk.Button(button_frame, text="Yeniden Başlat", command=self.restart_agent)
        btn_restart.pack(side="right", padx=5)

        btn_start = ttk.Button(button_frame, text="Başlat", command=self.start_agent)
        btn_start.pack(side="right", padx=5)


        # Sekmeli yapı (Notebook)
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill="both", expand=True, pady=5)

        # Dashboard Sekmesi
        self.dashboard_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        
        # Canlı Loglar Sekmesi
        self.logs_frame = ttk.Frame(self.notebook, padding=5)
        self.notebook.add(self.logs_frame, text="Canlı Loglar")

        # Log metin alanını Canlı Loglar sekmesine taşı
        self.log_text = ScrolledText(
            self.logs_frame,
            wrap="word",
            font=("Consolas", 10),
            state="disabled",
            background=self.colors["bg_dark"],
            foreground=self.colors["fg_light"],
            insertbackground=self.colors["fg_light"],
            borderwidth=1,
            relief="solid",
            padx=5,
            pady=5,
        )
        self.log_text.pack(fill="both", expand=True)

        # Dashboard içeriğini oluştur
        self._build_dashboard_tab()

    def _open_api_window(self):
        api_window = tk.Toplevel(self.root)
        api_window.title("API Anahtarı Ayarları")
        api_window.geometry("600x400")
        api_window.configure(bg=self.colors["bg_dark"])
        
        main_frame = ttk.Frame(api_window, padding=20)
        main_frame.pack(fill="both", expand=True)

        # Açıklama metni
        tr_text = (
            "Yapay Zeka (AI) Analizi için API Anahtarı\n\n"
            "Bu özellik, kural tabanlı tespitlere ek olarak daha derin bir analiz için OpenRouter.ai servisini kullanır.\n\n"
            "Nasıl Alınır?\n"
            "1. openrouter.ai adresine gidin ve kayıt olun.\n"
            "2. Hesabınıza giriş yaptıktan sonra 'Keys' (Anahtarlar) sayfasına gidin.\n"
            "3. Yeni bir anahtar oluşturun ve aşağıya yapıştırın.\n\n"
            "Varsayılan Model: deepseek/deepseek-chat\n"
            "Not: Bu özellik isteğe bağlıdır. Anahtar girmezseniz, program sadece kural tabanlı çalışır."
        )
        
        en_text = (
            "API Key for Artificial Intelligence (AI) Analysis\n\n"
            "This feature uses the OpenRouter.ai service for deeper analysis in addition to rule-based detection.\n\n"
            "How to Obtain?\n"
            "1. Go to openrouter.ai and sign up.\n"
            "2. After logging into your account, navigate to the 'Keys' page.\n"
            "3. Create a new key and paste it below.\n\n"
            "Default Model: deepseek/deepseek-chat\n"
            "Note: This feature is optional. If you don't enter a key, the program will run in rule-based only mode."
        )

        # Metinleri sekmeli yapıda göster
        text_notebook = ttk.Notebook(main_frame)
        text_notebook.pack(fill="x", pady=10, expand=True)
        
        tr_frame = ttk.Frame(text_notebook)
        en_frame = ttk.Frame(text_notebook)
        text_notebook.add(tr_frame, text="Türkçe")
        text_notebook.add(en_frame, text="English")

        tr_label = ttk.Label(tr_frame, text=tr_text, wraplength=550, justify="left")
        tr_label.pack(padx=10, pady=10, fill="both", expand=True)
        
        en_label = ttk.Label(en_frame, text=en_text, wraplength=550, justify="left")
        en_label.pack(padx=10, pady=10, fill="both", expand=True)

        # API Anahtarı giriş alanı
        entry_frame = ttk.Frame(main_frame)
        entry_frame.pack(fill='x', pady=10)
        
        api_label = ttk.Label(entry_frame, text="OpenRouter API Key:")
        api_label.pack(side="left", padx=(0, 10))
        
        api_entry = ttk.Entry(entry_frame, textvariable=self.api_key_var, width=50, show="*")
        api_entry.pack(side="left", fill="x", expand=True)

        # Butonlar
        button_frame_popup = ttk.Frame(main_frame)
        button_frame_popup.pack(pady=10)

        def save_and_close():
            self._append_log("[INFO] API anahtarı kaydedildi. Değişikliklerin etkili olması için ajanı yeniden başlatın.\n")
            api_window.destroy()

        save_button = ttk.Button(button_frame_popup, text="Kaydet ve Kapat", command=save_and_close)
        save_button.pack()


    def _build_dashboard_tab(self):
        # Eğer kütüphaneler eksikse, uyarı göster ve çık
        if not LIBS_AVAILABLE:
            error_label = ttk.Label(
                self.dashboard_frame,
                text=LIBS_ERROR_MESSAGE,
                justify="center",
                font=("Segoe UI", 12)
            )
            error_label.pack(expand=True, fill="both", padx=20, pady=20)
            return
        
        # Ana dataframe'i saklamak için
        self.df_threats = pd.DataFrame()

        # Dashboard için ana kontrol frame'i
        controls_frame = ttk.Frame(self.dashboard_frame)
        controls_frame.pack(side="top", fill="x", pady=(0, 10))

        btn_refresh = ttk.Button(controls_frame, text="Verileri Yenile", command=self.refresh_dashboard)
        btn_refresh.pack(side="left", padx=(0, 20))

        # IP Arama
        ttk.Label(controls_frame, text="IP Ara:").pack(side="left", padx=(10, 5))
        self.ip_search_var = tk.StringVar()
        ip_entry = ttk.Entry(controls_frame, textvariable=self.ip_search_var)
        ip_entry.pack(side="left", padx=5)
        btn_ip_search = ttk.Button(controls_frame, text="Ara", command=self._apply_filters_and_redraw)
        btn_ip_search.pack(side="left", padx=5)

        # Kategori Filtresi
        ttk.Label(controls_frame, text="Kategori:").pack(side="left", padx=(10, 5))
        self.category_filter_var = tk.StringVar(value="Tümü")
        # OptionMenu'nün anında güncelleme yapması için trace kullanıyoruz
        self.category_filter_var.trace_add("write", lambda *_: self._apply_filters_and_redraw())
        self.category_filter_menu = ttk.OptionMenu(
            controls_frame, 
            self.category_filter_var, 
            "Tümü"
        )
        self.category_filter_menu.pack(side="left", padx=5)


        # Grafiklerin yer alacağı alan
        self.charts_frame = ttk.Frame(self.dashboard_frame)
        self.charts_frame.pack(side="bottom", fill="both", expand=True)
    
        # Grafik alanlarını oluştur (Dikey olarak alt alta)
        self.chart1_frame = ttk.Frame(self.charts_frame)
        self.chart1_frame.pack(side="top", fill="both", expand=True, pady=5)
        
        self.chart2_frame = ttk.Frame(self.charts_frame)
        self.chart2_frame.pack(side="top", fill="both", expand=True, pady=5)
        
        self.chart3_frame = ttk.Frame(self.charts_frame)
        self.chart3_frame.pack(side="top", fill="both", expand=True, pady=5)

    def _clear_frame(self, frame: ttk.Frame):
        for widget in frame.winfo_children():
            widget.destroy()

    def refresh_dashboard(self):
        """Ana veri dosyasını yeniden okur ve filtreleri güncelleyip çizim yapar."""
        threat_data_path = self.base_dir / "threat_data.jsonl"
        
        for frame in [self.chart1_frame, self.chart2_frame, self.chart3_frame]:
            self._clear_frame(frame)

        if not threat_data_path.exists():
            error_label = ttk.Label(self.chart1_frame, text="Veri dosyası (threat_data.jsonl) bulunamadı.")
            error_label.pack()
            return

        try:
            self.df_threats = pd.read_json(threat_data_path, lines=True)
            if self.df_threats.empty:
                error_label = ttk.Label(self.chart1_frame, text="Tehdit verisi bulunamadı.")
                error_label.pack()
                return
        except Exception as e:
            self.df_threats = pd.DataFrame()
            error_label = ttk.Label(self.chart1_frame, text=f"Veri okuma hatası:\n{e}")
            error_label.pack()
            return
        
        # Kategori filtresi menüsünü güncelle
        menu = self.category_filter_menu["menu"]
        menu.delete(0, "end")
        categories = ["Tümü"] + sorted(self.df_threats['category'].unique().tolist())
        for cat in categories:
            # Komutun doğru değeri yakalaması için lambda'da value=cat kullan
            menu.add_command(label=cat, command=tk._setit(self.category_filter_var, cat))
        
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
            error_label = ttk.Label(self.chart1_frame, text="Filtre ile eşleşen veri bulunamadı.")
            error_label.pack()
            return

        # Grafik oluşturma fonksiyonlarını çağır
        self._draw_threats_by_time_chart(filtered_df, self.chart1_frame)
        self._draw_top_ips_chart(filtered_df, self.chart2_frame)
        self._draw_attack_types_chart(filtered_df, self.chart3_frame)
    
    def _draw_attack_types_chart(self, df: "pd.DataFrame", parent_frame: ttk.Frame):
        """Saldırı türlerini gösteren pasta grafik çizer."""
        attack_types = df['category'].value_counts()

        fig, ax = plt.subplots(figsize=(5, 4), dpi=100)
        fig.patch.set_facecolor(self.colors["bg_light"])
        
        wedges, texts, autotexts = ax.pie(
            attack_types, 
            labels=attack_types.index,
            autopct='%1.1f%%',
            startangle=90,
            pctdistance=0.85,
            textprops={'color': self.colors["fg_light"]}
        )
        
        # Etiketlerin (autotext) rengini ayarla
        for autotext in autotexts:
            autotext.set_color(self.colors["bg_dark"])
            autotext.set_fontweight('bold')

        # Dairenin ortasını boşaltarak donut chart yap
        centre_circle = plt.Circle((0,0),0.70,fc=self.colors["bg_light"])
        fig.gca().add_artist(centre_circle)

        ax.axis('equal')  # Eşit oranlar, pie'nin daire olmasını sağlar
        ax.set_title("Saldırı Türü Dağılımı", color=self.colors["fg_light"], pad=20)
        
        plt.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=parent_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True)

    def _draw_top_ips_chart(self, df: "pd.DataFrame", parent_frame: ttk.Frame):
        """En çok saldıran IP'leri gösteren çubuk grafik çizer."""
        top_ips = df['ip'].value_counts().nlargest(10).sort_values()

        fig, ax = plt.subplots(figsize=(10, 4), dpi=100) # figsize değiştirildi
        fig.patch.set_facecolor(self.colors["bg_light"])
        ax.set_facecolor(self.colors["bg_dark"])

        ax.tick_params(axis='x', colors=self.colors["fg_light"])
        ax.tick_params(axis='y', colors=self.colors["fg_light"])
        ax.spines['left'].set_color(self.colors["fg_light"])
        ax.spines['right'].set_color(self.colors["bg_dark"])
        ax.spines['top'].set_color(self.colors["bg_dark"])
        ax.spines['bottom'].set_color(self.colors["fg_light"])

        ax.set_title("Top 10 Saldırgan IP Adresi", color=self.colors["fg_light"])
        
        top_ips.plot(kind='barh', ax=ax, color=self.colors["accent_red"])
        ax.set_xlabel("Saldırı Sayısı", color=self.colors["fg_light"])
        ax.set_ylabel("IP Adresi", color=self.colors["fg_light"])
        
        plt.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=parent_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True)

    def _draw_threats_by_time_chart(self, df: "pd.DataFrame", parent_frame: ttk.Frame):
        """Günün saatine göre tehdit sayısını gösteren çizgi grafik çizer."""
        
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        # .dt.hour kullanarak günün saatine göre grupla
        threats_by_hour_of_day = df.groupby(df['timestamp'].dt.hour).size()
        # 0-23 arası tüm saatlerin olmasını garantile
        threats_by_hour_of_day = threats_by_hour_of_day.reindex(range(24), fill_value=0)


        # Matplotlib Figürünü oluştur (koyu tema)
        fig, ax = plt.subplots(figsize=(10, 4), dpi=100)
        fig.patch.set_facecolor(self.colors["bg_light"])
        ax.set_facecolor(self.colors["bg_dark"])

        # Eksen ve etiket renkleri
        ax.tick_params(axis='x', colors=self.colors["fg_light"], rotation=0)
        ax.tick_params(axis='y', colors=self.colors["fg_light"])
        ax.spines['left'].set_color(self.colors["fg_light"])
        ax.spines['right'].set_color(self.colors["bg_dark"])
        ax.spines['top'].set_color(self.colors["bg_dark"])
        ax.spines['bottom'].set_color(self.colors["fg_light"])
        
        # Başlık ve etiketler
        ax.set_title("Günün Saatlerine Göre Saldırı Yoğunluğu", color=self.colors["fg_light"])
        ax.set_ylabel("Toplam Tehdit Sayısı", color=self.colors["fg_light"])
        ax.set_xlabel("Günün Saati", color=self.colors["fg_light"])
        ax.set_xticks(range(0, 24, 2)) # X ekseninde her 2 saatte bir etiket göster
        
        # Grafiği çiz
        threats_by_hour_of_day.plot(kind='line', ax=ax, color=self.colors["accent_green"], marker='o', markersize=4)
        
        fig.tight_layout()

        # Tkinter canvas'ına göm
        canvas = FigureCanvasTkAgg(fig, master=parent_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True)


    def _update_status_label(self, status_text: str, state: str):
        color_map = {
            "running": self.colors["accent_green"],
            "stopped": self.colors["accent_red"],
            "error": self.colors["accent_red"],
            "default": self.colors["fg_light"],
        }
        self.status_label.config(
            text=f"Durum: {status_text}",
            foreground=color_map.get(state, self.colors["fg_light"])
        )

    def start_from_start_screen(self):
        self.main_frame.pack(fill="both", expand=True)
        self.start_frame.pack_forget()
        self.start_agent()

    def start_agent(self):
        if self.proc is not None and self.proc.poll() is None:
            self._append_log("[INFO] Ajan zaten çalışıyor.\n")
            return

        ajan_path = self.base_dir / "ajan.py"
        if not ajan_path.exists():
            self._append_log("[HATA] ajan.py bu klasörde bulunamadı.\n")
            self._update_status_label("ajan.py bulunamadı", "error")
            return

        # Ortam değişkenlerini hazırla
        env = os.environ.copy()
        
        # GUI'den girilen E-posta adresini ayarla
        user_email = self.email_to.get()
        if user_email:
            env["ALERT_EMAIL_TO"] = user_email
            self._append_log(f"[INFO] Uyarı e-postası şu adrese ayarlandı: {user_email}\n")
        else:
            self._append_log("[UYARI] E-posta adresi girilmedi. Mail gönderimi devre dışı.\n")

        # GUI'den girilen API anahtarını öncelikli olarak ayarla
        gui_api_key = self.api_key_var.get()
        if gui_api_key:
            env["LOG_GOZCUSU_GUI_API_KEY"] = gui_api_key
            self._append_log("[INFO] GUI üzerinden yeni bir API anahtarı ayarlandı.\n")
        else:
            self._append_log("[INFO] GUI'den API anahtarı girilmedi, sistemdeki anahtar kullanılacak (varsa).\n")


        try:
            self.proc = subprocess.Popen(
                [sys.executable, "-u", str(ajan_path)],
                cwd=self.base_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',
                env=env # Güncellenmiş ortam değişkenlerini kullan
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
        if "!" in text:
            self.log_text.tag_configure("attack", foreground=self.colors["accent_red"], font=("Consolas", 10, "bold"))
            tag = "attack"
        elif "[UYARI]" in text:
            self.log_text.tag_configure("warning", foreground="#FFA500")
            tag = "warning"
        elif "[HATA]" in text:
            self.log_text.tag_configure("error", foreground=self.colors["accent_red"])
            tag = "error"
        else:
            tag = None

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
    root = tk.Tk()
    app = LogGozcusuGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()