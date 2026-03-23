from tkinter import *
from tkinter import messagebox
from tkinter.ttk import *
from os import urandom
import base64
import binascii
import secrets
import string

import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from ..core import validators
from ..core.crypto_engine import AESCryptoEngine, UnsupportedModeError

class EncryptionView:
    """Prezentuje interfejs szyfrowania i deszyfrowania tekstu.

    Argumenty:
        parent: Kontener nadrzędny, do którego dołączany jest widok konfiguracji AES.

    Zwraca:
        EncryptionView: Obiekt inicjalizujący logikę i układ graficzny modułu szyfrowania.
    """

    MODES = ["ECB", "CBC", "CFB", "CTR", "OFB"]
    KEY_SIZES = {
        "128 bitów": 16,
        "192 bity": 24,
        "256 bitów": 32,
    }
    FORMAT_OPTIONS = ["UTF-8", "Heksadecymalny", "Base64"]
    FORMAT_ALIAS_MAP = {
        "UTF-8": "UTF-8",
        "UTF8": "UTF-8",
        "HEX": "HEX",
        "HEKSADECYMALNY": "HEX",
        "BASE64": "BASE64",
    }
    DEFAULT_MODE = "ECB"
    DEFAULT_KEY_SIZE = "128 bitów"
    DEFAULT_INPUT_FORMAT = "UTF-8"
    DEFAULT_OUTPUT_FORMAT = "Heksadecymalny"
    TEXTBOX_HEIGHT = 12
    TEXTBOX_WIDTH = 40 
    INFO_PLACEHOLDER = "—"
    HIST_BG_COLOR = "#F0F0F0"

    def __init__(self, parent):
        self.parent = parent

        # Logika szyfrowania
        self.engine = AESCryptoEngine()
        self.plaintext_bytes = b""

        # Zmienne stanu UI
        self.status_var = StringVar(master=self.parent, value="")
        self.key_size_var = StringVar(master=self.parent, value=self.DEFAULT_KEY_SIZE)
        self.operation_var = StringVar(master=self.parent, value="Szyfrowanie")
        self.input_format_var = StringVar(master=self.parent, value=self.DEFAULT_INPUT_FORMAT)
        self.output_format_var = StringVar(master=self.parent, value=self.DEFAULT_OUTPUT_FORMAT)

        # Zmienne informacyjne
        self.info_mode_var = StringVar(master=self.parent, value=self.INFO_PLACEHOLDER)
        self.info_key_length_var = StringVar(master=self.parent, value=self.INFO_PLACEHOLDER)
        self.info_iv_var = StringVar(master=self.parent, value=self.INFO_PLACEHOLDER)
        self.info_time_var = StringVar(master=self.parent, value=self.INFO_PLACEHOLDER)

        # Referencje do widgetów
        self.plain_text = None
        self.input_format_combo = None
        self.mode = None
        self.key_entry = None
        self.iv_entry = None
        self.iv_button = None
        self.result_text = None
        self.output_format_combo = None
        self.execute_btn = None
        self.input_hist_frame = None
        self.output_hist_frame = None
        self.input_hist_canvas = None
        self.output_hist_canvas = None
        self.input_hist_ax = None
        self.output_hist_ax = None

        self._last_key_hex: str | None = None
        self._last_iv_hex: str | None = None

        self._configure_styles()
        self.build_gui()

    # ------------------------------------------------------------------
    # Budowa interfejsu (POPRAWIONA)
    # ------------------------------------------------------------------
    def _configure_styles(self) -> None:
        """Konfiguruje style i paletę kolorów komponentów ttk.

        Argumenty:
            Brak.

        Zwraca:
            None: Aktualizuje obiekt Style przypisany do widoku.
        """
        base_bg = "#F7F8FA"
        section_bg = "#F7F8FA"
        accent_bg = "#E5E7EB"
        self.style = Style()
        self.style.configure("Panel.TFrame", background=base_bg)
        self.style.configure("Panel.TLabel", background=base_bg)
        self.style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"), background=base_bg, foreground="#111827")
        self.style.configure("Description.TLabel", font=("Segoe UI", 10), foreground="#4B5563", background=base_bg)
        self.style.configure("Section.TLabelframe", background=section_bg)
        self.style.configure("Section.TLabelframe.Label", font=("Segoe UI", 11, "bold"), foreground="#1F2933", background=section_bg)
        self.style.configure("Status.TFrame", background=base_bg, borderwidth=1, relief="solid")
        self.style.configure("Status.TLabel", background=base_bg, foreground="#1F2933")
        self.style.configure("Neutral.TButton", foreground="#111827", background=accent_bg)
        self.style.map("Neutral.TButton", background=[("active", "#E5E7EB"), ("disabled", accent_bg)])

    def build_gui(self) -> None:
        """Tworzy układ formularza w dwóch równoważnych kolumnach.

        Argumenty:
            Brak.

        Zwraca:
            None: Konfiguruje kontener rodzica i rozmieszcza podwidoki.
        """
        self.parent.configure(style="Panel.TFrame")
        self.parent.grid_columnconfigure(0, weight=1, uniform="panels") 
        self.parent.grid_columnconfigure(1, weight=0) 
        self.parent.grid_columnconfigure(2, weight=1, uniform="panels")
        self.parent.grid_rowconfigure(0, weight=1)

        self._build_left_panel()
        self._build_separator()
        self._build_right_panel()

    def _build_left_panel(self) -> None:
        """Buduje panel konfiguracji po lewej stronie układu.

        Argumenty:
            Brak.

        Zwraca:
            None: Inicjalizuje kontrolki wejściowe i rozmieszcza je w siatce.
        """
        left_panel = Frame(self.parent, style="Panel.TFrame", padding=(20, 20))
        left_panel.grid(row=0, column=0, sticky="nsew")
        
        # Konfiguracja siatki wewnątrz lewego panelu
        left_panel.grid_columnconfigure(0, weight=1)
        left_panel.grid_rowconfigure(2, weight=2)
        left_panel.grid_rowconfigure(7, weight=1)

        # 1. Nagłówek informacyjny
        Label(left_panel, text="Dane wejściowe i konfiguracja", style="Header.TLabel").grid(row=0, column=0, sticky="w")
        Label(left_panel, text="Wprowadź swoje dane, wybierz format oraz ustaw parametry.", style="Description.TLabel", wraplength=400).grid(row=1, column=0, sticky="w", pady=(0, 15))

        # 2. Pole tekstowe (wiersz 2 – rozciągany)
        self.plain_text = Text(left_panel, height=self.TEXTBOX_HEIGHT, width=self.TEXTBOX_WIDTH, wrap="word")
        self.plain_text.grid(row=2, column=0, sticky="nsew") # Ustawienie "nsew" wypełnia komórkę siatki

        # 3. Przyciski pod polem tekstowym (wiersz 3)
        input_buttons = Frame(left_panel, style="Panel.TFrame")
        input_buttons.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        input_buttons.grid_columnconfigure((0, 1), weight=1, uniform="btns")
        
        Button(input_buttons, text="Wyczyść pola", command=self.clear_fields).grid(row=0, column=0, sticky="ew", padx=(0, 5))
        Button(input_buttons, text="Losuj tekst jawny (24 bajty)", command=self.generate_random_input).grid(row=0, column=1, sticky="ew", padx=(5, 0))

        # 4. Wybór formatów i operacji (wiersz 4)
        operation_row = Frame(left_panel, style="Panel.TFrame")
        operation_row.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        operation_row.grid_columnconfigure(1, weight=1)

        Label(operation_row, text="Format danych wejściowych:", style="Panel.TLabel").grid(row=0, column=0, sticky="w")
        self.input_format_combo = Combobox(
            operation_row,
            values=self.FORMAT_OPTIONS,
            state="readonly",
            textvariable=self.input_format_var,
            width=17,
        )
        self.input_format_combo.grid(row=0, column=1, sticky="w", padx=(5, 15))

        Label(operation_row, text="Wybierz operację:", style="Panel.TLabel").grid(row=0, column=2, sticky="w")
        self.operation = Combobox(operation_row, values=["Szyfrowanie", "Deszyfrowanie"], state="readonly", textvariable=self.operation_var, width=14)
        self.operation.grid(row=0, column=3, sticky="ew", padx=(5, 0))
        self.operation.bind("<<ComboboxSelected>>", self.on_operation_change)

        # 5. Parametry AES (wiersz 5)
        params_frame = LabelFrame(left_panel, text="Parametry AES", style="Section.TLabelframe", padding=15)
        params_frame.grid(row=5, column=0, sticky="nsew", pady=(15, 0))
        params_frame.grid_columnconfigure(1, weight=1)

        # Konfiguracja trybu pracy
        Label(params_frame, text="Wybierz tryb:", style="Panel.TLabel").grid(row=0, column=0, sticky="w")
        self.mode = Combobox(params_frame, values=self.MODES, state="readonly", width=8)
        self.mode.current(0)
        self.mode.grid(row=0, column=1, sticky="w", padx=10)
        self.mode.bind("<<ComboboxSelected>>", self.on_mode_change)

        # Konfiguracja długości klucza
        Label(params_frame, text="Wybierz długość klucza: ", style="Panel.TLabel").grid(row=1, column=0, sticky="w")
        key_size_frame = Frame(params_frame)
        key_size_frame.grid(row=1, column=1, sticky="w", pady=5)
        for idx, label in enumerate(self.KEY_SIZES):
            Radiobutton(key_size_frame, text=label, value=label, variable=self.key_size_var).grid(row=0, column=idx, padx=(0, 10))
        
        # Pole wprowadzania klucza
        Label(params_frame, text="Klucz (HEX):", style="Panel.TLabel").grid(row=2, column=0, sticky="w")
        key_row = Frame(params_frame)
        key_row.grid(row=2, column=1, sticky="ew", pady=2, padx=(10,0))
        key_row.grid_columnconfigure(0, weight=1)
        self.key_entry = Entry(key_row)
        self.key_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        Button(key_row, text="Generuj", command=self.on_generate_key, width=8).grid(row=0, column=1)

        # Pole wprowadzania IV
        Label(params_frame, text="IV (HEX):", style="Panel.TLabel").grid(row=3, column=0, sticky="w")
        iv_row = Frame(params_frame)
        iv_row.grid(row=3, column=1, sticky="ew", pady=2, padx=(10,0))
        iv_row.grid_columnconfigure(0, weight=1)
        self.iv_entry = Entry(iv_row)
        self.iv_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.iv_button = Button(iv_row, text="Generuj", command=self.on_generate_iv, width=8)
        self.iv_button.grid(row=0, column=1)

        # 6. Przycisk działania (wiersz 6)
        self.execute_btn = Button(left_panel, text="Szyfruj", style="Neutral.TButton", command=self.on_execute, width=20)
        self.execute_btn.grid(row=6, column=0, sticky="", pady=(20, 0))

        self._refresh_iv_state()

        # 7. Analiza statystyczna (wiersz 7 – rozciągany)
        self.input_hist_frame = LabelFrame(
            left_panel,
            text="Analiza statystyczna (Tekst wejściowy)",
            style="Section.TLabelframe",
            padding=10,
        )
        self.input_hist_frame.grid(row=7, column=0, sticky="nsew", pady=(20, 0))
        self._initialize_histogram_canvas(self.input_hist_frame, "input")
        self._draw_text_histogram(self.input_hist_ax, self.input_hist_canvas, None)

    def _build_separator(self) -> None:
        Separator(self.parent, orient=VERTICAL).grid(row=0, column=1, sticky="ns", padx=5, pady=20)

    def _build_right_panel(self) -> None:
        """Buduje panel wyników po prawej stronie układu.

        Argumenty:
            Brak.

        Zwraca:
            None: Tworzy widok prezentujący szyfrogram i metadane operacji.
        """
        right_panel = Frame(self.parent, style="Panel.TFrame", padding=(20, 20))
        right_panel.grid(row=0, column=2, sticky="nsew")
        
        right_panel.grid_columnconfigure(0, weight=1)
        # Wiersz 2 (pole tekstowe) rośnie tak samo jak po lewej stronie
        right_panel.grid_rowconfigure(2, weight=1)
        right_panel.grid_rowconfigure(7, weight=1)

        # 1. Nagłówek (wiersz 0)
        Label(right_panel, text="Dane wyjściowe", style="Header.TLabel").grid(row=0, column=0, sticky="w")
        Label(right_panel, text="Tutaj pojawi się wynik operacji.", style="Description.TLabel", wraplength=400).grid(row=1, column=0, sticky="w", pady=(0, 15))

        # 2. Pole tekstowe (wiersz 2 – rozciągany)
        self.result_text = Text(right_panel, height=self.TEXTBOX_HEIGHT, width=self.TEXTBOX_WIDTH, wrap="word", state="disabled")
        self.result_text.grid(row=2, column=0, sticky="nsew") # "nsew" zapewnia wyrównanie wysokości

        # 3. Kontrolki pod polem tekstowym (wiersz 3, analogiczne jak po lewej)
        right_controls = Frame(right_panel, style="Panel.TFrame")
        right_controls.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        right_controls.grid_columnconfigure(1, weight=1)

        Label(right_controls, text="Format danych wyjściowych:", style="Panel.TLabel").grid(row=0, column=0, sticky="w")
        self.output_format_combo = Combobox(
            right_controls,
            values=self.FORMAT_OPTIONS,
            state="readonly",
            textvariable=self.output_format_var,
            width=17,
        )
        self.output_format_combo.grid(row=0, column=1, sticky="w", padx=(5, 0))
        
        Button(right_controls, text="Kopiuj wynik", command=self.copy_result).grid(row=0, column=2, sticky="e")

        # 4. Parametry wynikowe (wiersz 5 – dopasowany do panelu po lewej)
        info_frame = LabelFrame(right_panel, text="Parametry wynikowe", style="Section.TLabelframe", padding=15)
        info_frame.grid(row=5, column=0, sticky="nsew", pady=(15, 0))
        info_frame.grid_columnconfigure(1, weight=1)

        self._add_info_row(info_frame, 0, "Tryb:", self.info_mode_var)
        self._add_info_row(info_frame, 1, "Klucz:", self.info_key_length_var)
        self._add_info_row(info_frame, 2, "IV:", self.info_iv_var)

        # 5. Pasek statusu (wiersz 6)
        right_panel.grid_rowconfigure(6, weight=0)
        status_frame = Frame(right_panel, style="Status.TFrame", padding=(10, 5))
        status_frame.grid(row=6, column=0, sticky="ew", pady=(20, 0))
        Label(status_frame, textvariable=self.status_var, style="Status.TLabel", anchor="w").pack(fill="x")

        # 6. Analiza statystyczna (wiersz 7 – rozciągany)
        self.output_hist_frame = LabelFrame(
            right_panel,
            text="Analiza statystyczna (Tekst wyjściowy)",
            style="Section.TLabelframe",
            padding=10,
        )
        self.output_hist_frame.grid(row=7, column=0, sticky="nsew", pady=(20, 0))
        self._initialize_histogram_canvas(self.output_hist_frame, "output")
        self._draw_text_histogram(self.output_hist_ax, self.output_hist_canvas, None)

    def _initialize_histogram_canvas(self, frame, kind: str) -> None:
        fig = plt.Figure(figsize=(6, 2.3), dpi=100)
        fig.patch.set_facecolor(self.HIST_BG_COLOR)

        ax = fig.add_subplot(111)
        ax.set_facecolor(self.HIST_BG_COLOR)
        fig.subplots_adjust(left=0.08, right=0.98, top=0.95, bottom=0.20)

        canvas = FigureCanvasTkAgg(fig, master=frame)
        canvas.get_tk_widget().pack(fill="both", expand=True)

        if kind == "input":
            self.input_hist_canvas = canvas
            self.input_hist_ax = ax
        else:
            self.output_hist_canvas = canvas
            self.output_hist_ax = ax

    def _add_info_row(self, parent, row: int, label: str, variable: StringVar) -> None:
        """Dodaje pojedynczy wiersz etykiety w sekcji informacyjnej.

        Argumenty:
            parent: Ramka, w której znajduje się sekcja parametrów wynikowych.
            row: Numer wiersza używany podczas układania w siatce.
            label: Tekst nagłówka opisu parametru.
            variable: Zmienna powiązana z etykietą prezentującą bieżącą wartość.

        Zwraca:
            None: Uzupełnia przekazany kontener o etykietę i wartość.
        """
        Label(parent, text=label, style="Panel.TLabel").grid(row=row, column=0, sticky="w", pady=2)
        Label(parent, textvariable=variable, style="Panel.TLabel", width=35, anchor="e").grid(row=row, column=1, sticky="e", pady=2)
    # ------------------------------------------------------------------
    # Logika UI
    # ------------------------------------------------------------------

    def on_generate_key(self) -> None:
        """Generuje losowy klucz o długości wskazanej w ustawieniach.

        Argumenty:
            Brak.

        Zwraca:
            None: Wstawia świeżo wygenerowany klucz w formacie HEX do pola tekstowego.
        """
        key_label = self.key_size_var.get()
        key_length = self.KEY_SIZES.get(key_label, 16)
        generated_key = urandom(key_length)
        self.key_entry.delete(0, END)
        self.key_entry.insert(0, generated_key.hex().upper())
        self.status_var.set(f"Wygenerowano klucz {key_length * 8} bitów")

    def on_generate_iv(self) -> None:
        """Generuje losowy wektor inicjujący lub nonce i umieszcza go w polu IV.

        Argumenty:
            Brak.

        Zwraca:
            None: Aktualizuje pole IV zgodnie z wymaganą długością dla bieżącego trybu.
        """
        iv_len = self._expected_iv_length()
        iv_value = urandom(iv_len).hex().upper()
        self._set_iv_text(iv_value)
        self.status_var.set("Wygenerowano losowy IV")

    def generate_random_input(self) -> None:
        """Generuje losowe dane wejściowe w formacie wybranym przez użytkownika.

        Argumenty:
            Brak.

        Zwraca:
            None: Uzupełnia pole tekstowe losową wartością i aktualizuje histogram.
        """
        fmt = self._normalize_format_label(self.input_format_var.get(), self.DEFAULT_INPUT_FORMAT)

        try:
            if fmt == "UTF-8":
                alphabet = string.ascii_letters + string.digits + " _-.,;:"
                text = "".join(secrets.choice(alphabet) for _ in range(32))
                data = text.encode("utf-8")
                status = "Wygenerowano losowy tekst UTF-8"
            else:
                data = urandom(32)
                if fmt == "HEX":
                    text = data.hex(" ").upper()
                    status = "Wygenerowano losowy tekst HEX"
                elif fmt == "BASE64":
                    text = base64.b64encode(data).decode("ascii")
                    status = "Wygenerowano losowy tekst Base64"
                else:
                    text = data.hex(" ").upper()
                    status = "Wygenerowano losowe dane"

            self.plain_text.delete("1.0", END)
            self.plain_text.insert("1.0", text)
            self.plaintext_bytes = data
            self._refresh_input_histogram()
            self.status_var.set(status)
        except Exception as exc:
            self.status_var.set(f"Błąd generowania losowych danych: {exc}")

    def on_encrypt(self) -> None:
        """Rozpoczyna proces szyfrowania dla aktualnych danych wejściowych."""
        raw_input = self.plain_text.get("1.0", "end-1c")
        if not raw_input.strip():
            self.status_var.set("Pole wejściowe jest puste")
            return

        try:
            payload = self._decode_input(raw_input, self.input_format_var.get())
        except ValueError as exc:
            self.status_var.set(str(exc))
            return

        result = self._run_crypto("szyfrowanie", payload)
        if not result:
            return

        plain_bytes = payload
        cipher_bytes = result.data

        self.plaintext_bytes = plain_bytes
        if not self._display_result_bytes(cipher_bytes):
            return
        self._update_text_histograms(plain_bytes, cipher_bytes)

    def on_decrypt(self) -> None:
        """Rozpoczyna proces deszyfrowania dla danych z pola wejściowego."""
        raw_input = self.plain_text.get("1.0", "end-1c")
        if not raw_input.strip():
            self.status_var.set("Pole wejściowe jest puste")
            return

        try:
            payload = self._decode_input(raw_input, self.input_format_var.get())
        except ValueError as exc:
            self.status_var.set(str(exc))
            return

        result = self._run_crypto("deszyfrowanie", payload)
        if not result:
            return

        cipher_bytes = payload
        plain_bytes = result.data

        self.plaintext_bytes = cipher_bytes
        if not self._display_result_bytes(plain_bytes):
            return
        self._update_text_histograms(cipher_bytes, plain_bytes)

    def on_execute(self) -> None:
        """Obsługuje kliknięcie przycisku wykonania, wybierając szyfrowanie lub deszyfrowanie.

        Argumenty:
            Brak.

        Zwraca:
            None: Kieruje sterowanie do metody `on_encrypt` lub `on_decrypt` na podstawie wyboru.
        """
        op_label = self.operation.get()
        if "Szyfr" in op_label:
            self.on_encrypt()
        else:
            self.on_decrypt()

    def on_operation_change(self, _event=None) -> None:
        """Aktualizuje etykietę i styl przycisku wykonania po zmianie trybu pracy.

        Argumenty:
            _event: Opcjonalne zdarzenie Tkinter powiązane ze zmianą wyboru.

        Zwraca:
            None: Dopasowuje podpis przycisku i wymusza neutralny styl kolorystyczny.
        """
        op_label = self.operation.get()
        if "Szyfr" in op_label:
            self.execute_btn.config(text="Szyfruj")
            try:
                self.execute_btn.config(style="Neutral.TButton")
            except Exception:
                pass
        else:
            self.execute_btn.config(text="Deszyfruj")
            try:
                self.execute_btn.config(style="Neutral.TButton")
            except Exception:
                pass

    def _run_crypto(self, operation: str, payload: bytes):
        mode = self.mode.get().upper()
        needs_iv = mode != "ECB"

        key_hex = self.key_entry.get().strip().upper()
        try:
            key_len = self.KEY_SIZES[self.key_size_var.get()]
            key_bytes = validators.validate_key_hex(key_hex, key_len)
        except ValueError as exc:
            self.status_var.set(str(exc))
            return None

        if operation == "szyfrowanie" and not self._confirm_reuse(key_hex, self._last_key_hex, "klucza AES"):
            self.status_var.set("Operacja anulowana – wygeneruj nowy klucz lub wklej inny")
            return None

        iv_hex: str | None = None
        iv_bytes: bytes | None = None
        if needs_iv:
            iv_hex = self.iv_entry.get().strip().upper()
            if not iv_hex:
                self.status_var.set("IV/nonce jest wymagany dla wybranego trybu")
                return None

            try:
                iv_bytes = bytes.fromhex(iv_hex)
            except ValueError:
                self.status_var.set("IV musi być zapisany w poprawnym formacie HEX")
                return None

            required_iv_len = self._expected_iv_length(mode_override=mode)
            if len(iv_bytes) != required_iv_len:
                self.status_var.set(
                    f"IV musi mieć dokładnie {required_iv_len} bajtów ({required_iv_len * 2} znaki HEX)"
                )
                return None

            if operation == "szyfrowanie" and not self._confirm_reuse(iv_hex, self._last_iv_hex, "IV/nonce"):
                self.status_var.set("Operacja anulowana – użyj nowego IV/nonce")
                return None

        try:
            if mode == "CBC":
                if not iv_bytes:
                    self.status_var.set("Tryb CBC wymaga podania IV/nonce")
                    return None
                if operation == "szyfrowanie":
                    result = self.engine._encrypt_cbc(key_bytes, payload, iv_bytes)
                else:
                    result = self.engine._decrypt_cbc(key_bytes, payload, iv_bytes)
            else:
                result = self.engine.run(operation, mode, payload, key_bytes, iv_bytes)
        except (ValueError, UnsupportedModeError) as exc:
            self.status_var.set(str(exc))
            return None

        action_label = "Szyfrowanie" if operation == "szyfrowanie" else "Deszyfrowanie"
        self.status_var.set(f"{action_label} zakończone pomyślnie")
        if operation == "szyfrowanie":
            self._last_key_hex = key_hex
            self._last_iv_hex = iv_hex if needs_iv else None
        self._update_info_section(mode, key_bytes, result)
        return result

    def _update_info_section(self, mode: str, key_bytes: bytes, result) -> None:
        """Aktualizuje widoczny panel informacji po zakończonej operacji.

        Argumenty:
            mode: Nazwa trybu AES użytego w ostatnim działaniu.
            key_bytes: Użyty klucz w postaci bajtów w celu ustalenia długości.
            result: Struktura zwrócona przez silnik zawierająca m.in. IV.

        Zwraca:
            None: Ustawia zmienne tekstowe powiązane z sekcją wynikową.
        """
        self.info_mode_var.set(mode.upper())
        self.info_key_length_var.set(f"{len(key_bytes) * 8} bitów")
        self.info_iv_var.set(result.iv.hex().upper() if result.iv else self.INFO_PLACEHOLDER)
        self.info_time_var.set(self.INFO_PLACEHOLDER)

    def _normalize_format_label(self, label: str | None, fallback: str) -> str:
        candidate = (label or "").strip()
        if candidate:
            normalized = self.FORMAT_ALIAS_MAP.get(candidate.upper(), candidate.upper())
            return normalized

        fallback_value = (fallback or "").strip().upper()
        if not fallback_value:
            fallback_value = "UTF-8"
        return self.FORMAT_ALIAS_MAP.get(fallback_value, fallback_value)

    def _decode_input(self, text: str, fmt: str | None) -> bytes:
        stripped = (text or "").strip()
        if not stripped:
            raise ValueError("Pole wejściowe jest puste")

        label = self._normalize_format_label(fmt, self.DEFAULT_INPUT_FORMAT)
        if label == "UTF-8":
            return stripped.encode("utf-8")
        if label == "HEX":
            cleaned = "".join(stripped.split())
            if not cleaned:
                raise ValueError("Brak danych HEX")
            try:
                return bytes.fromhex(cleaned)
            except ValueError as exc:
                raise ValueError("Błędny format HEX. Upewnij się, że ciąg ma parzystą liczbę znaków i zawiera tylko 0-9 oraz A-F.") from exc
        if label == "BASE64":
            compact = "".join(stripped.split())
            if not compact:
                raise ValueError("Brak danych Base64")
            try:
                return base64.b64decode(compact, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ValueError("Błędny format Base64") from exc
        return stripped.encode("utf-8")

    def _encode_output(self, data: bytes, fmt: str | None) -> str:
        label = self._normalize_format_label(fmt, self.DEFAULT_OUTPUT_FORMAT)
        if label == "UTF-8":
            return data.decode("utf-8", errors="replace")
        if label == "HEX":
            return data.hex(" ").upper()
        if label == "BASE64":
            return base64.b64encode(data).decode("ascii")
        return data.hex().upper()

    def _set_output_text(self, text: str) -> None:
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", END)
        if text:
            self.result_text.insert("1.0", text)
        self.result_text.config(state="disabled")

    def _display_result_bytes(self, data: bytes) -> bool:
        try:
            rendered = self._encode_output(data, self.output_format_var.get())
        except ValueError as exc:
            self.status_var.set(str(exc))
            return False
        self._set_output_text(rendered)
        return True

    def clear_fields(self) -> None:
        """Czyści pola wejściowe oraz resetuje wszystkie informacje pomocnicze.

        Argumenty:
            Brak.

        Zwraca:
            None: Przywraca widok do ustawień domyślnych i czyści histogramy.
        """
        self.plain_text.delete("1.0", END)
        self.key_entry.delete(0, END)
        self.iv_entry.config(state="normal")
        self.iv_entry.delete(0, END)
        self.key_size_var.set(self.DEFAULT_KEY_SIZE)
        self.mode.set(self.DEFAULT_MODE)
        self.input_format_var.set(self.DEFAULT_INPUT_FORMAT)
        self.output_format_var.set(self.DEFAULT_OUTPUT_FORMAT)
        self.plaintext_bytes = b""
        self._update_text_histograms(None, None)

        self.result_text.config(state="normal")
        self.result_text.delete("1.0", END)
        self.result_text.config(state="disabled")

        self.status_var.set("Wyczyszczono pola wejściowe")
        self._reset_info_section()
        self._refresh_iv_state()

    def _reset_info_section(self) -> None:
        """Przywraca domyślne wartości w panelu informacyjnym.

        Argumenty:
            Brak.

        Zwraca:
            None: Ustawia symbole zastępcze we wszystkich polach metadanych.
        """
        self.info_mode_var.set(self.INFO_PLACEHOLDER)
        self.info_key_length_var.set(self.INFO_PLACEHOLDER)
        self.info_iv_var.set(self.INFO_PLACEHOLDER)
        self.info_time_var.set(self.INFO_PLACEHOLDER)

    def copy_result(self) -> None:
        """Kopiuje obecny wynik operacji do systemowego schowka.

        Argumenty:
            Brak.

        Zwraca:
            None: Przenosi treść z pola wynikowego do schowka i aktualizuje status.
        """
        self.result_text.config(state="normal")
        result = self.result_text.get("1.0", "end-1c")
        self.result_text.config(state="disabled")

        if not result:
            self.status_var.set("Brak danych do skopiowania")
            return

        self.parent.clipboard_clear()
        self.parent.clipboard_append(result)
        self.status_var.set("Skopiowano wynik do schowka")

    def save_result(self) -> None:
        """Tymczasowe przypomnienie o braku obsługi zapisu wyniku do pliku.

        Argumenty:
            Brak.

        Zwraca:
            None: Informuje użytkownika o niezaimplementowanej funkcjonalności.
        """
        self.status_var.set("Zapis do pliku nie jest jeszcze zaimplementowany")

    def load_example(self) -> None:
        """Tymczasowe przypomnienie o braku przykładowych danych wejściowych.

        Argumenty:
            Brak.

        Zwraca:
            None: Sygnalizuje w statusie, że funkcja nie została jeszcze wdrożona.
        """
        self.status_var.set("Wczytywanie przykładu wymaga implementacji")

    def on_mode_change(self, _event=None) -> None:
        """Aktualizuje dostępność pola IV po zmianie trybu pracy AES.

        Argumenty:
            _event: Obiekt zdarzenia pochodzący z kontrolki wyboru trybu.

        Zwraca:
            None: Przełącza stan pola IV zgodnie z wymaganiami nowego trybu.
        """
        self._refresh_iv_state()

    def _refresh_iv_state(self) -> None:
        """Włącza lub wyłącza pole IV w zależności od bieżącego trybu i operacji.

        Argumenty:
            Brak.

        Zwraca:
            None: Dostosowuje możliwość edycji IV oraz przycisku jego generowania.
        """
        if not self.iv_entry or not self.iv_button:
            return

        mode = self.mode.get() if self.mode else self.DEFAULT_MODE
        requires_iv = mode != "ECB"
        op_label = self.operation.get() if hasattr(self, "operation") and self.operation else self.operation_var.get()
        encrypting = "Szyfr" in op_label

        if not requires_iv:
            self.iv_entry.config(state="disabled")
            self.iv_entry.delete(0, END)
            self.iv_button.config(state="disabled")
            return

        self.iv_entry.config(state="normal")
        if encrypting:
            self.iv_button.config(state="normal")
        else:
            self.iv_button.config(state="disabled")

    def _refresh_input_histogram(self) -> None:
        data = self.plaintext_bytes if getattr(self, "plaintext_bytes", b"") else None
        self._draw_text_histogram(self.input_hist_ax, self.input_hist_canvas, data)

    def _set_iv_text(self, value: str) -> None:
        if not self.iv_entry:
            return
        self.iv_entry.config(state="normal")
        self.iv_entry.delete(0, END)
        self.iv_entry.insert(0, value)
        self._refresh_iv_state()

    def _expected_iv_length(self, mode_override: str | None = None) -> int:
        _ = mode_override  # zachowujemy sygnaturę, ale wszystkie tryby używają długości bloku
        return self.engine.BLOCK_SIZE_BYTES

    def _confirm_reuse(self, current: str, previous: str | None, what: str) -> bool:
        if not previous or current != previous:
            return True
        return messagebox.askyesno(
            "Ostrzeżenie",
            f"Używasz ponownie tego samego {what} co w poprzednim szyfrowaniu. Kontynuować?",
            parent=self.parent,
        )

    def _update_text_histograms(self, input_bytes: bytes | None, output_bytes: bytes | None) -> None:
        self._draw_text_histogram(self.input_hist_ax, self.input_hist_canvas, input_bytes)
        self._draw_text_histogram(self.output_hist_ax, self.output_hist_canvas, output_bytes)

    def _draw_text_histogram(self, ax, canvas, data_bytes: bytes | None) -> None:
        if not ax or not canvas:
            return

        ax.clear()
        ax.set_facecolor(self.HIST_BG_COLOR)

        if not data_bytes:
            ax.set_xticks([])
            ax.set_yticks([])
            for spine in ax.spines.values():
                spine.set_visible(False)
            ax.text(
                0.5,
                0.5,
                "Brak danych do analizy",
                transform=ax.transAxes,
                ha="center",
                va="center",
                fontsize=10,
                color="#4B5563",
            )
            canvas.draw_idle()
            return

        counts = [0] * 256
        for value in data_bytes:
            counts[value] += 1

        ax.bar(range(256), counts, width=1.0, color="#2563EB")
        ax.set_xlim(0, 255)
        ax.set_xlabel("Wartość bajtu", fontsize=8, color="#333333")
        ax.set_ylabel("Liczebność", fontsize=8, color="#333333")
        ax.tick_params(axis="x", labelsize=7, colors="#333333", rotation=0)
        ax.tick_params(axis="y", labelsize=7, colors="#333333")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["left"].set_visible(True)
        ax.spines["bottom"].set_visible(True)
        ax.spines["left"].set_color("#AAAAAA")
        ax.spines["bottom"].set_color("#AAAAAA")

        canvas.draw_idle()

    # ------------------------------------------------------------------