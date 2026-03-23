from __future__ import annotations

import io
from math import ceil
from os import urandom
from pathlib import Path
from typing import Optional
from tkinter import END, Button, Entry, Frame, Label, StringVar, simpledialog, BooleanVar
from tkinter import filedialog, messagebox
from tkinter.ttk import Combobox, LabelFrame, Radiobutton, Frame as TFrame
from tkinter.ttk import Checkbutton

import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from PIL import Image, ImageTk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes



from ..core import validators
from ..core.crypto_engine import AESCryptoEngine
from ..core.image_cipher import (
    ImageCipherError,
    decrypt_bmp_cbc,
    decrypt_bmp_cfb,
    decrypt_bmp_ctr,
    decrypt_bmp_ecb,
    decrypt_bmp_ofb,
    encrypt_bmp_cbc,
    encrypt_bmp_cfb,
    encrypt_bmp_ctr,
    encrypt_bmp_ecb,
    encrypt_bmp_ofb,
    _derive_ctr_nonce,
    _read_bmp_sections,
)


class FileEncryptionView:
    """Interfejs do szyfrowania i deszyfrowania plików z użyciem różnych trybów AES.

    Argumenty:
        parent: Główny kontener Tkinter, w którym osadzany jest widok plikowy.

    Zwraca:
        FileEncryptionView: Skonfigurowany komponent odpowiadający za logikę i UI przetwarzania plików.
    """

    KEY_SIZES = {
        "128 bitów": 16,
        "192 bity": 24,
        "256 bitów": 32,
    }
    DEFAULT_KEY_SIZE = "128 bitów"
    MODES = ["ECB", "CBC", "CFB", "CTR", "OFB"]
    DEFAULT_MODE = "ECB"
    PREVIEW_MAX_DIM = 320
    OPERATION_OPTIONS = [
        "Szyfrowanie (Demo - Pełny cykl)",
        "Deszyfrowanie (Z pliku)",
    ]
    DEFAULT_OPERATION = OPERATION_OPTIONS[0]

    def __init__(self, parent) -> None:
        self.parent = parent
        self.engine = AESCryptoEngine()

        # Stan interfejsu użytkownika
        self.input_path_var = StringVar(master=self.parent, value="")
        self.output_path_var = StringVar(master=self.parent, value="")
        self.mode_var = StringVar(master=self.parent, value=self.DEFAULT_MODE)
        self.key_size_var = StringVar(master=self.parent, value=self.DEFAULT_KEY_SIZE)
        self.status_var = StringVar(master=self.parent, value="Wybierz plik wejściowy")
        self.input_info_var = StringVar(master=self.parent, value="Brak pliku")
        self.output_info_var = StringVar(master=self.parent, value="Brak pliku wynikowego")
        self.simulate_error_var = BooleanVar(master=self.parent, value=False)
        self.operation_var = StringVar(master=self.parent, value=self.DEFAULT_OPERATION)

        self.key_entry = None
        self.key_generate_btn = None
        self.process_button = None
        self.source_frame = None
        self.encrypted_frame = None
        self.decrypted_frame = None
        
        self.source_preview_label = None
        self.encrypted_preview_label = None
        self.decrypted_preview_label = None
        self.hist_original_frame = None
        self.hist_encrypted_frame = None
        self.iv_entry = None
        self.iv_button = None

        self._last_key_hex: str | None = None
        self._last_iv_hex: str | None = None

        self._input_preview_img = None
        self._encrypted_preview_img = None
        self._decrypted_preview_img = None
        self._decrypted_preview_message: str | None = None
        self._has_generated_output = False
        self.encrypted_image_bytes: bytes | None = None
        self._error_simulation_cipher_path: Path | None = None
        self._error_simulation_mode: str | None = None
        self._error_simulation_summary: str | None = None

        self._build_gui()

    # ------------------------------------------------------------------
    # Budowa interfejsu użytkownika
    # ------------------------------------------------------------------
    def _build_gui(self) -> None:
        root = TFrame(self.parent, padding=20)
        root.pack(fill="both", expand=True)
        
        root.grid_columnconfigure(0, weight=1, uniform="main_layout") 
        root.grid_columnconfigure(1, weight=2, uniform="main_layout") 

        root.grid_rowconfigure(0, weight=1)

        left_panel = Frame(root)
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 15))
        left_panel.grid_columnconfigure(0, weight=1)

        right_panel = Frame(root)
        right_panel.grid(row=0, column=1, sticky="nsew")
        right_panel.grid_columnconfigure(0, weight=1)

        self._build_file_panel(left_panel)
        self._build_controls_panel(left_panel)
        self._build_status_panel(left_panel)
        self._build_preview_panel(right_panel)
        self.update_ui_for_mode()

    def _build_file_panel(self, parent: Frame) -> None:
        Label(parent, text="Wybierz plik wejściowy").grid(row=0, column=0, sticky="w")
        input_row = Frame(parent)
        input_row.grid(row=1, column=0, sticky="ew", pady=(2, 8))
        input_row.grid_columnconfigure(0, weight=1)
        Entry(input_row, textvariable=self.input_path_var, state="readonly").grid(
            row=0, column=0, sticky="ew", padx=(0, 6)
        )
        Button(input_row, text="Wybierz...", command=self.on_choose_input).grid(row=0, column=1)
        Label(parent, textvariable=self.input_info_var, foreground="#555555").grid(
            row=2, column=0, sticky="w"
        )

    def _build_controls_panel(self, parent: Frame) -> None:
        controls = LabelFrame(parent, text="Parametry", padding=12)
        controls.grid(row=3, column=0, sticky="ew", pady=(20, 0))
        controls.grid_columnconfigure(1, weight=1)

        Label(controls, text="Tryb").grid(row=0, column=0, sticky="w")
        mode_box = Combobox(
            controls,
            values=self.MODES,
            state="readonly",
            textvariable=self.mode_var,
            width=18,
        )
        mode_box.grid(row=0, column=1, sticky="w")
        mode_box.bind("<<ComboboxSelected>>", self.on_mode_change)

        Label(controls, text="Długość klucza").grid(row=1, column=0, sticky="w", pady=(12, 2))
        key_size_frame = Frame(controls)
        key_size_frame.grid(row=1, column=1, sticky="w", pady=(12, 2))
        for idx, label in enumerate(self.KEY_SIZES):
            Radiobutton(
                key_size_frame,
                text=label,
                value=label,
                variable=self.key_size_var,
            ).grid(row=0, column=idx, padx=(0, 6))

        Label(controls, text="Klucz (HEX)").grid(row=2, column=0, sticky="w", pady=(12, 2))
        key_row = Frame(controls)
        key_row.grid(row=2, column=1, sticky="ew", pady=(0, 6))
        key_row.grid_columnconfigure(0, weight=1)
        self.key_entry = Entry(key_row)
        self.key_entry.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.key_generate_btn = Button(key_row, text="Generuj", command=self.on_generate_key)
        self.key_generate_btn.grid(row=0, column=1)

        Label(controls, text="IV (HEX)").grid(row=3, column=0, sticky="w", pady=(12, 2))
        iv_row = Frame(controls)
        iv_row.grid(row=3, column=1, sticky="ew")
        iv_row.grid_columnconfigure(0, weight=1)
        self.iv_entry = Entry(iv_row)
        self.iv_entry.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.iv_button = Button(iv_row, text="Generuj IV", command=self.on_generate_iv)
        self.iv_button.grid(row=0, column=1, sticky="w")

        Checkbutton(
            controls,
            text="Symuluj błąd transmisji (1 bit)",
            variable=self.simulate_error_var,
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(12, 0))

        # ZMIANA: Podział na dwa przyciski
        btn_frame = Frame(controls)
        btn_frame.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        btn_frame.grid_columnconfigure((0, 1), weight=1)

        self.process_button = Button(
            btn_frame,
            text="Szyfruj",
            command=self.on_process,
        )
        self.process_button.grid(row=0, column=0, sticky="ew", padx=(0, 5))

        self.decrypt_btn = Button(
            btn_frame,
            text="Deszyfruj",
            command=self.on_decrypt_current,
        )
        self.decrypt_btn.grid(row=0, column=1, sticky="ew", padx=(5, 0))

        self._refresh_iv_state()

    def _build_status_panel(self, parent: Frame) -> None:
        status = LabelFrame(parent, text="Status", padding=10)
        status.grid(row=7, column=0, sticky="ew", pady=(20, 0))
        Label(status, textvariable=self.status_var, wraplength=420, justify="left").grid(
            row=0, column=0, sticky="w"
        )

    def _build_preview_panel(self, parent: Frame) -> None:
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        preview = LabelFrame(parent, text="Podgląd obrazu", padding=12)
        preview.grid(row=0, column=0, sticky="nsew")
        
        preview.grid_rowconfigure(0, weight=2)
        preview.grid_rowconfigure(1, weight=1)
        for col in range(3):
            preview.grid_columnconfigure(col, weight=1, uniform="group1")

        self.source_frame = LabelFrame(preview, text="Obraz Oryginalny", padding=8)
        self.source_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.source_frame.grid_columnconfigure(0, weight=1)
        self.source_frame.grid_rowconfigure(0, weight=1)
        self.source_preview_label = Label(
            self.source_frame,
            text="Brak podglądu",
            relief="sunken",
            anchor="center",
        )
        self.source_preview_label.grid(row=0, column=0, sticky="nsew")

        encrypted_frame = LabelFrame(preview, text="Szyfrogram", padding=8)
        encrypted_frame.grid(row=0, column=1, sticky="nsew", padx=4)
        encrypted_frame.grid_columnconfigure(0, weight=1)
        encrypted_frame.grid_rowconfigure(0, weight=1)
        self.encrypted_preview_label = Label(
            encrypted_frame,
            text="Brak podglądu",
            relief="sunken",
            anchor="center",
        )
        self.encrypted_preview_label.grid(row=0, column=0, sticky="nsew")
        self.encrypted_frame = encrypted_frame

        decrypted_frame = LabelFrame(preview, text="Odszyfrowany plik", padding=8)
        decrypted_frame.grid(row=0, column=2, sticky="nsew", padx=(8, 0))
        decrypted_frame.grid_columnconfigure(0, weight=1)
        decrypted_frame.grid_rowconfigure(0, weight=1)
        self.decrypted_preview_label = Label(
            decrypted_frame,
            text="Brak podglądu",
            relief="sunken",
            anchor="center",
        )
        self.decrypted_preview_label.grid(row=0, column=0, sticky="nsew")
        self.decrypted_frame = decrypted_frame

        self.hist_original_frame = LabelFrame(preview, text="Histogram (Oryginał)", padding=8)
        self.hist_original_frame.grid(row=1, column=0, sticky="nsew", pady=(12, 0), padx=(0, 8))

        self.hist_encrypted_frame = LabelFrame(preview, text="Histogram (Szyfrogram)", padding=8)
        self.hist_encrypted_frame.grid(row=1, column=1, sticky="nsew", pady=(12, 0), padx=4)

        status_frame = LabelFrame(preview, text="Status", padding=8)
        status_frame.grid(row=1, column=2, sticky="nsew", pady=(12, 0), padx=(8, 0))
        Label(status_frame, textvariable=self.output_info_var, foreground="#555555", justify="left").pack(
            expand=True, fill="both"
        )

        self._draw_histogram(self.hist_original_frame, None)
        self._draw_histogram(self.hist_encrypted_frame, None)

    # ------------------------------------------------------------------
    # Obsługa zdarzeń
    # ------------------------------------------------------------------
    def update_ui_for_mode(self, _event=None) -> None:
        decrypt_mode = self._is_decryption_mode()

        if decrypt_mode:
            if self.source_frame:
                self.source_frame.configure(text="---")
            if self.source_preview_label:
                self.source_preview_label.configure(image="", text="---")
            if self.encrypted_frame:
                self.encrypted_frame.configure(text="Wczytany Szyfrogram (Wejście)")
            if self.decrypted_frame:
                self.decrypted_frame.configure(text="Odszyfrowany plik")
            self.simulate_error_var.set(False)
        else:
            if self.source_frame:
                self.source_frame.configure(text="Obraz Oryginalny")
            if self.encrypted_frame:
                self.encrypted_frame.configure(text="Szyfrogram")
            if self.decrypted_frame:
                self.decrypted_frame.configure(text="Odszyfrowany plik")

        self._clear_result_previews(refresh=False)
        input_path = Path(self.input_path_var.get()) if self.input_path_var.get() else None
        self._suggest_output_path(input_path)
        self._refresh_iv_state()
        self._refresh_previews()

    def on_choose_input(self) -> None:
        selected = filedialog.askopenfilename(title="Wybierz plik do przetworzenia")
        if not selected:
            return
        path = Path(selected)

        if not self._is_bmp_file(path):
            messagebox.showerror(
                "Nieobsługiwany format",
                "Ten widok obsługuje wyłącznie pliki BMP (*.bmp).",
            )
            return

        # 3. Odśwież układ interfejsu (wygaszenie lewego panelu przy deszyfracji itp.)
        self.update_ui_for_mode()
        # ----------------------------

        self.input_path_var.set(selected)
        self._update_input_info(path)
        self._clear_result_previews(refresh=False)
        self._suggest_output_path(path)
        
        # self.status_var.set(f"Wybrano {path.name}") # Nadpisane przez Smart Handling
        self._refresh_previews()

    def on_mode_change(self, _event=None) -> None:
        input_path = Path(self.input_path_var.get()) if self.input_path_var.get() else None
        

        self._clear_result_previews(refresh=False)
        self.status_var.set("Zmieniono tryb – podglądy wyzerowano")
        
        self._suggest_output_path(input_path)
        self._refresh_iv_state()
        self._refresh_previews()

    def on_generate_key(self) -> None:
        key_len = self.KEY_SIZES.get(self.key_size_var.get(), 16)
        key_bytes = urandom(key_len)
        self.key_entry.delete(0, END)
        self.key_entry.insert(0, key_bytes.hex().upper())
        self.status_var.set(f"Wygenerowano klucz {key_len * 8} bitów")

    def on_generate_iv(self) -> None:
        iv_hex = self._generate_iv_hex()
        self._set_iv_text(iv_hex)
        self.status_var.set("Wygenerowano losowy IV")

    def on_process(self) -> None:
        """Uruchamia proces szyfrowania obrazu (bez automatycznej deszyfracji)."""
        self._clear_decrypted_preview()
        try:
            input_path = self._ensure_input_file()
            if not self._is_bmp_file(input_path):
                raise ImageCipherError("Ten widok obsługuje wyłącznie obrazy BMP (*.bmp).")
            key_hex = self.key_entry.get().strip().upper()
            key_len = self.KEY_SIZES.get(self.key_size_var.get(), 16)
            key_bytes = validators.validate_key_hex(self.key_entry.get(), key_len)
            operation = "encrypt"
            mode = self._selected_mode()
            custom_output = self.output_path_var.get().strip()

            if not self._confirm_reuse(key_hex, self._last_key_hex, "klucza AES"):
                self.status_var.set("Operacja anulowana – wygeneruj nowy klucz lub wklej inny")
                return

            result_path, status = self._process_bmp_image(
                input_path,
                custom_output,
                key_bytes,
                operation,
                mode,
            )
            self.status_var.set(status)
            self.output_path_var.set(str(result_path))

            mutation_note = None
            protected_prefix = self._bmp_header_length(result_path)
            self.encrypted_image_bytes, mutated = self._finalize_encrypted_file(result_path, protected_prefix)
            if mutated:
                self._record_error_simulation(result_path, mode)
                mutation_note = "⚠️ Symulacja błędu aktywna – odszyfruj obraz, aby zobaczyć wpływ"
            else:
                self._clear_error_simulation_tracking()
            self._has_generated_output = True

            self._decrypted_preview_img = None
            self._decrypted_preview_message = None
            self._refresh_previews()

            if mutation_note:
                self._append_status_note(mutation_note)

            # Zapisujemy ostatnio użyty klucz/IV
            self._last_key_hex = key_hex
            if mode != "ECB" and self.iv_entry:
                iv_candidate = self.iv_entry.get().strip().upper()
                self._last_iv_hex = iv_candidate or None
            else:
                self._last_iv_hex = None

        except (FileNotFoundError, ValueError, OSError, ImageCipherError) as exc:
            messagebox.showerror("Błąd", str(exc))
            self.status_var.set(str(exc))

    # ------------------------------------------------------------------
    # Funkcje pomocnicze
    # ------------------------------------------------------------------
    def _draw_histogram(self, parent_frame: Frame, pil_image: Image.Image | None) -> None:
        """Renderuje histogram RGB wraz z opisami osi w zadanej ramce.

        Argumenty:
            parent_frame: Kontener, w którym ma zostać osadzony wykres.
            pil_image: Obraz PIL będący źródłem danych lub None dla pustego miejsca.

        Zwraca:
            None: Aktualizuje zawartość ramki stosownie do dostępnych danych.
        """
        for widget in parent_frame.winfo_children():
            widget.destroy()

        if pil_image is None:
            Label(parent_frame, text="Miejsce na wykres", anchor="center").pack(expand=True, fill="both")
            return

        if pil_image.mode != "RGB":
            pil_image = pil_image.convert("RGB")

        histogram = pil_image.histogram()
        r = histogram[0:256]
        g = histogram[256:512]
        b = histogram[512:768]
        x = range(256)

        fig = plt.Figure(figsize=(5, 2.5), dpi=100)
        bg_color = "#F0F0F0"
        fig.patch.set_facecolor(bg_color)

        ax = fig.add_subplot(111)
        ax.set_facecolor(bg_color)

        ax.fill_between(x, r, color="#FF3333", alpha=0.5, label="R")
        ax.fill_between(x, g, color="#33FF33", alpha=0.5, label="G")
        ax.fill_between(x, b, color="#3333FF", alpha=0.5, label="B")

        ax.set_xlim(0, 255)
        ax.set_xticks([0, 64, 128, 192, 255])
        ax.tick_params(axis="x", labelsize=7, colors="#333333")
        ax.set_xlabel("Wartość piksela", fontsize=8, color="#333333", labelpad=2)

        ax.get_yaxis().set_ticks([])
        ax.set_ylabel("Liczebność", fontsize=8, color="#333333", labelpad=2)

        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["left"].set_visible(True)
        ax.spines["left"].set_color("#AAAAAA")
        ax.spines["bottom"].set_color("#AAAAAA")

        fig.subplots_adjust(left=0.12, right=0.95, top=0.95, bottom=0.20)

        canvas = FigureCanvasTkAgg(fig, master=parent_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)
        parent_frame._hist_canvas = canvas

    def _render_histogram_from_path(self, frame: Frame | None, path: Path | None) -> None:
        if not frame:
            return
        if not path or not path.is_file():
            self._draw_histogram(frame, None)
            return
        try:
            with Image.open(path) as img:
                self._draw_histogram(frame, img.copy())
        except Exception:  # noqa: BLE001
            self._draw_histogram(frame, None)

    def _is_decryption_mode(self) -> bool:
        selected = self.operation_var.get() if self.operation_var else self.DEFAULT_OPERATION
        return selected == self.OPERATION_OPTIONS[1]

    def _selected_mode(self) -> str:
        label = self.mode_var.get().upper()
        return label if label in {"ECB", "CBC", "CFB", "CTR", "OFB"} else "ECB"

    def _ensure_input_file(self) -> Path:
        path_text = self.input_path_var.get()
        if not path_text:
            raise FileNotFoundError("Wybierz plik wejściowy")
        path = Path(path_text)
        if not path.is_file():
            raise FileNotFoundError("Podany plik wejściowy nie istnieje")
        return path

    def _get_output_folder(self, encrypt: bool) -> Path:
        """Zwraca ścieżkę do folderu wyjściowego, tworząc go w razie potrzeby."""
        base_dir = Path.cwd() / "output"
        sub_dir = "encrypted" if encrypt else "decrypted"
        target_dir = base_dir / sub_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        return target_dir

    def _process_bmp_image(
        self,
        input_path: Path,
        custom_output: str,
        key: bytes,
        operation: str,
        mode: str,
    ) -> tuple[Path, str]:
        target = Path(custom_output) if custom_output else self._derive_bmp_output_path(
            input_path,
            encrypt=operation == "encrypt",
        )
        if operation == "encrypt":
            if mode == "ECB":
                path = encrypt_bmp_ecb(input_path, target, key)
            elif mode == "CTR":
                path = encrypt_bmp_ctr(input_path, target, key)
            elif mode == "CBC":
                iv_hex, iv_bytes = self._require_iv_hex_bytes()
                if not self._confirm_reuse(iv_hex, self._last_iv_hex, "IV/nonce"):
                    raise ImageCipherError("Operacja anulowana – użyj nowego IV/nonce")
                path, _ = encrypt_bmp_cbc(input_path, target, key, iv=iv_bytes)
                iv_file = self._store_iv_sidecar(path, iv_hex)
                return path, self._image_status("szyfrowania", mode, f"IV zapisano w {iv_file.name}")
            elif mode == "CFB":
                iv_hex, iv_bytes = self._require_iv_hex_bytes()
                if not self._confirm_reuse(iv_hex, self._last_iv_hex, "IV/nonce"):
                    raise ImageCipherError("Operacja anulowana – użyj nowego IV/nonce")
                path, _ = encrypt_bmp_cfb(input_path, target, key, iv=iv_bytes)
                iv_file = self._store_iv_sidecar(path, iv_hex)
                return path, self._image_status("szyfrowania", mode, f"IV zapisano w {iv_file.name}")
            elif mode == "OFB":
                iv_hex, iv_bytes = self._require_iv_hex_bytes()
                if not self._confirm_reuse(iv_hex, self._last_iv_hex, "IV/nonce"):
                    raise ImageCipherError("Operacja anulowana – użyj nowego IV/nonce")
                path, _ = encrypt_bmp_ofb(input_path, target, key, iv=iv_bytes)
                iv_file = self._store_iv_sidecar(path, iv_hex)
                return path, self._image_status("szyfrowania", mode, f"IV zapisano w {iv_file.name}")
            else:
                raise ImageCipherError(f"Nieobsługiwany tryb {mode} dla BMP")
            return path, self._image_status("szyfrowania", mode)

        if mode == "ECB":
            path = decrypt_bmp_ecb(input_path, target, key)
        elif mode == "CTR":
            path = decrypt_bmp_ctr(input_path, target, key)
        elif mode == "CBC":
            iv_hex = self._load_iv_for_bmp(input_path)
            path = decrypt_bmp_cbc(input_path, target, key, iv_hex)
        elif mode == "CFB":
            iv_hex = self._load_iv_for_bmp(input_path)
            path = decrypt_bmp_cfb(input_path, target, key, iv_hex)
        elif mode == "OFB":
            iv_hex = self._load_iv_for_bmp(input_path)
            path = decrypt_bmp_ofb(input_path, target, key, iv_hex)
        else:
            raise ImageCipherError(f"Nieobsługiwany tryb {mode} dla BMP")
        return path, self._image_status("deszyfrowania", mode)

    def save_result(self) -> None:
        """Tymczasowe przypomnienie o braku obsługi zapisu wyniku do pliku."""
        self.status_var.set("Zapis do pliku nie jest jeszcze zaimplementowany")

    def load_example(self) -> None:
        """Tymczasowe przypomnienie o braku obsługi ładowania przykładowego pliku."""
        self.status_var.set("Ładowanie przykładu nie jest jeszcze zaimplementowane")

    def _derive_bmp_output_path(self, input_path: Path, *, encrypt: bool) -> Path:
        stem = input_path.stem
        if encrypt and stem.endswith("_decrypted"):
            stem = stem[: -len("_decrypted")]
        if not encrypt and stem.endswith("_encrypted"):
            stem = stem[: -len("_encrypted")]
        
        suffix = "_zaszyfrowany.bmp" if encrypt else "_odszyfrowany.bmp"
        
        output_dir = self._get_output_folder(encrypt)
        return output_dir / f"{stem}{suffix}"

    def _iv_sidecar_path(self, bmp_path: Path) -> Path:
        return bmp_path.with_suffix(bmp_path.suffix + ".iv")

    def _store_iv_sidecar(self, bmp_path: Path, iv_hex: str) -> Path:
        iv_path = self._iv_sidecar_path(bmp_path)
        iv_path.write_text(iv_hex.strip(), encoding="utf-8")
        return iv_path

    def _load_iv_for_bmp(self, bmp_path: Path) -> str:
        iv_path = self._iv_sidecar_path(bmp_path)
        if iv_path.exists():
            iv_text = iv_path.read_text(encoding="utf-8").strip()
            if iv_text:
                return iv_text
        iv_hex = simpledialog.askstring(
            "IV wymagany",
            (
                "Wybrany tryb wymaga IV/nonce zapisanego podczas szyfrowania.\n"
                "Podaj wartość w formacie HEX (32 znaki)."
            ),
            parent=self.parent,
        )
        if not iv_hex:
            raise ImageCipherError("IV jest wymagany do odszyfrowania pliku w tym trybie")
        iv_hex = iv_hex.strip()
        if len(iv_hex) != 32:
            raise ImageCipherError("IV musi mieć 32 znaki HEX (16 bajtów)")
        return iv_hex

    def _suggest_output_path(self, input_path: Path | None) -> None:
        if not input_path:
            self.output_path_var.set("")
            return
        default_path = self._default_output_path_for_input(input_path)
        self.output_path_var.set(str(default_path))

    def _default_output_path_for_input(self, input_path: Path) -> Path:
        stem_lower = input_path.stem.lower()
        if stem_lower.endswith("_encrypted"):
            return self._derive_bmp_output_path(input_path, encrypt=False)
        return self._derive_bmp_output_path(input_path, encrypt=True)

    def _is_bmp_file(self, path: Path) -> bool:
        return path.suffix.lower() == ".bmp"

    def _update_input_info(self, path: Path) -> None:
        if not path or not path.is_file():
            self.input_info_var.set("Brak pliku")
            return
        info = f"Rozmiar: {self._format_size(path.stat().st_size)}"
        dims = self._describe_image_dimensions(path)
        if dims:
            info += f" | {dims}"
        self.input_info_var.set(info)

    def _set_output_info(self, path: Path | None) -> None:
        if not path or not path.is_file():
            self.output_info_var.set("Brak pliku wynikowego")
            return
        info = f"Rozmiar: {self._format_size(path.stat().st_size)}"
        dims = self._describe_image_dimensions(path)
        if dims:
            info += f" | {dims}"
        self.output_info_var.set(info)

    def _describe_image_dimensions(self, path: Path) -> Optional[str]:
        try:
            with Image.open(path) as img:
                width, height = img.size
            return f"{width}x{height}px"
        except Exception:
            return None

    def _refresh_previews(self) -> None:
        input_path = Path(self.input_path_var.get()) if self.input_path_var.get() else None
        output_path = Path(self.output_path_var.get()) if self.output_path_var.get() else None
        decrypt_mode = self._is_decryption_mode()

        input_preview = self._load_preview(input_path)
        output_preview = self._load_preview(output_path) if (self._has_generated_output and output_path) else None

        if decrypt_mode:
            self._input_preview_img = None
            self._encrypted_preview_img = input_preview
        else:
            self._input_preview_img = input_preview
            self._encrypted_preview_img = output_preview

        if decrypt_mode:
            self.source_preview_label.configure(image="", text="---")
        elif self._input_preview_img:
            self.source_preview_label.configure(image=self._input_preview_img, text="")
        else:
            self.source_preview_label.configure(
                image="",
                text=self._preview_fallback_text(input_path, is_input=True),
            )

        if self._encrypted_preview_img:
            self.encrypted_preview_label.configure(image=self._encrypted_preview_img, text="")
        else:
            if decrypt_mode:
                fallback_text = self._preview_fallback_text(input_path, is_input=True, label="szyfrogramu")
            else:
                fallback_text = self._preview_fallback_text(
                    output_path,
                    is_input=False,
                    label="zaszyfrowanego",
                )
            self.encrypted_preview_label.configure(
                image="",
                text=fallback_text,
            )

        if self._decrypted_preview_img:
            self.decrypted_preview_label.configure(image=self._decrypted_preview_img, text="")
        else:
            self.decrypted_preview_label.configure(
                image="",
                text=self._decrypted_preview_message
                or self._preview_fallback_text(None, is_input=False, label="odszyfrowanego"),
            )

        self._set_output_info(output_path)
        if decrypt_mode:
            self._render_histogram_from_path(self.hist_original_frame, None)
            self._render_histogram_from_path(self.hist_encrypted_frame, input_path)
        else:
            self._render_histogram_from_path(self.hist_original_frame, input_path)
            hist_path = output_path if self._has_generated_output else None
            self._render_histogram_from_path(self.hist_encrypted_frame, hist_path)

    def _clear_decrypted_preview(self) -> None:
        self._decrypted_preview_img = None
        self._decrypted_preview_message = None

    def _clear_result_previews(self, *, refresh: bool = True) -> None:
        self.output_path_var.set("")
        self._encrypted_preview_img = None
        self._has_generated_output = False
        self.encrypted_image_bytes = None
        self._clear_error_simulation_tracking()
        self._clear_decrypted_preview()
        if self.encrypted_preview_label:
            if self._is_decryption_mode():
                self.encrypted_preview_label.configure(image="", text="Brak szyfrogramu")
            else:
                self.encrypted_preview_label.configure(
                    image="",
                    text=self._preview_fallback_text(None, is_input=False, label="zaszyfrowanego"),
                )
        if self.decrypted_preview_label:
            self.decrypted_preview_label.configure(
                image="",
                text=self._preview_fallback_text(None, is_input=False, label="odszyfrowanego"),
            )
        if self._is_decryption_mode() and self.source_preview_label:
            self.source_preview_label.configure(image="", text="---")
        self._set_output_info(None)
        if refresh:
            self._refresh_previews()

    def _load_preview(self, path: Path | None) -> ImageTk.PhotoImage | None:
        if not path or not path.is_file():
            return None
        try:
            with Image.open(path) as pil_image:
                preview = self._prepare_preview_image(pil_image)
            return ImageTk.PhotoImage(preview)
        except Exception:
            return None

    def _generate_decrypted_preview(
        self,
        encrypted_path: Path,
        mode: str,
        key: bytes,
        iv_hex: str | None,
    ) -> ImageTk.PhotoImage | None:
        self._decrypted_preview_message = None
        if not encrypted_path.exists():
            self._decrypted_preview_message = "Brak pliku wynikowego"
            return None

        try:
            if not self._is_bmp_file(encrypted_path):
                self._decrypted_preview_message = "Podgląd dostępny tylko dla obrazów BMP"
                return None

            pil_image = self._build_bmp_preview_image(encrypted_path, mode, key, iv_hex)

            if not pil_image:
                self._decrypted_preview_message = "Nie udało się utworzyć podglądu"
                return None

            preview_image = self._prepare_preview_image(pil_image)
            return ImageTk.PhotoImage(preview_image)
        except (ImageCipherError, ValueError) as exc:
            self._decrypted_preview_message = str(exc)
        except Exception:
            self._decrypted_preview_message = "Nie udało się wygenerować podglądu odszyfrowanego obrazu"
        return None

    def _build_bmp_preview_image(
        self,
        encrypted_path: Path,
        mode: str,
        key: bytes,
        iv_hex: str | None,
    ) -> Image.Image | None:
        header, encrypted_pixels = _read_bmp_sections(encrypted_path)

        if mode == "ECB":
            cipher = Cipher(algorithms.AES(key), modes.ECB())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(encrypted_pixels) + decryptor.finalize()
        elif mode == "CTR":
            nonce = _derive_ctr_nonce(header, key)
            plaintext = self.engine.run("decrypt", "CTR", encrypted_pixels, key, nonce).data
        elif mode in {"CBC", "CFB", "OFB"}:
            if not iv_hex:
                raise ImageCipherError("Podgląd w tym trybie wymaga IV/nonce")
            try:
                iv_bytes = bytes.fromhex(iv_hex.strip())
            except ValueError as exc:
                raise ImageCipherError("IV musi być zapisany w formacie HEX") from exc
            plaintext = self.engine.run("decrypt", mode, encrypted_pixels, key, iv_bytes).data
        else:
            raise ImageCipherError(f"Nieobsługiwany tryb {mode} dla BMP")

        buffer = io.BytesIO(header + plaintext)
        with Image.open(buffer) as preview:
            return preview.copy()

    def _prepare_preview_image(self, image: Image.Image) -> Image.Image:
        preview = image.copy()
        scale = max(preview.width / self.PREVIEW_MAX_DIM, preview.height / self.PREVIEW_MAX_DIM, 1)
        if scale > 1:
            new_size = (
                max(1, int(preview.width / scale)),
                max(1, int(preview.height / scale)),
            )
            preview = preview.resize(new_size, Image.LANCZOS)
        return preview

    def _preview_fallback_text(self, path: Path | None, *, is_input: bool, label: str | None = None) -> str:
        if label:
            missing = f"Brak pliku {label}"
        else:
            missing = "Brak pliku wejściowego" if is_input else "Brak pliku wynikowego"
        if not path:
            return missing
        if not path.exists():
            return "Plik nie istnieje"
        return "Podgląd niedostępny (format nieobsługiwany)"

    def _finalize_encrypted_file(self, path: Path, protected_prefix: int) -> tuple[bytes, bool]:
        try:
            raw_bytes = path.read_bytes()
        except OSError as exc:
            raise ImageCipherError(f"Nie udało się odczytać szyfrogramu: {path.name}") from exc

        final_bytes, mutated = self._maybe_inject_transmission_error(raw_bytes, protected_prefix=protected_prefix)
        if mutated:
            try:
                path.write_bytes(final_bytes)
            except OSError as exc:
                raise ImageCipherError(f"Nie udało się zapisać zasymulowanego błędu: {path.name}") from exc
        return final_bytes, mutated

    def _maybe_inject_transmission_error(
        self,
        payload: bytes,
        *,
        protected_prefix: int = 0,
    ) -> tuple[bytes, bool]:
        if not payload:
            return payload, False
        if not self.simulate_error_var.get():
            return payload, False

        safe_prefix = max(0, min(protected_prefix, len(payload)))
        body_len = len(payload) - safe_prefix
        if body_len <= 0:
            return payload, False

        # Wybieramy bajt w środku sekcji danych (poza nagłówkiem)
        flip_index = safe_prefix + body_len // 2
        mutated = bytearray(payload)
        mutated[flip_index] ^= 0x80
        return bytes(mutated), True

    def _bmp_header_length(self, path: Path) -> int:
        try:
            header, _ = _read_bmp_sections(path)
            return len(header)
        except ImageCipherError:
            return 0

    def _append_status_note(self, note: str) -> None:
        existing = (self.status_var.get() or "").strip()
        self.status_var.set(f"{existing}\n{note}" if existing else note)

    def _record_error_simulation(self, cipher_path: Path, mode: str) -> str:
        summary = self._error_simulation_effect_description(mode)
        self._error_simulation_cipher_path = self._normalize_path(cipher_path)
        self._error_simulation_mode = mode
        self._error_simulation_summary = summary
        return summary

    def _clear_error_simulation_tracking(self) -> None:
        self._error_simulation_cipher_path = None
        self._error_simulation_mode = None
        self._error_simulation_summary = None

    def _maybe_report_error_effect(self, ciphertext_path: Path) -> None:
        if not self._error_simulation_cipher_path or not self._error_simulation_summary:
            return
        normalized = self._normalize_path(ciphertext_path)
        if normalized != self._error_simulation_cipher_path:
            return
        mode = self._error_simulation_mode or self._selected_mode()
        self._append_status_note(f"Analiza błędu ({mode}): {self._error_simulation_summary}")
        self._clear_error_simulation_tracking()

    def _error_simulation_effect_description(self, mode: str) -> str:
        effects = {
            "ECB": "Cały blok (16 bajtów/pikseli) jest aktualnie losowy.",
            "CBC": "Cały zmodyfikowany blok pozostaje zniekształcony, a ta sama pozycja w kolejnym bloku ma odwrócony bit.",
            "CFB": "Pojedyncza pozycja w bieżącym bloku oraz cały następny blok właśnie się zmieniły.",
            "CTR": "Zmieniła się dokładnie jedna pozycja (piksel) w bieżącym bloku.",
            "OFB": "Zmieniła się dokładnie jedna pozycja (piksel) w bieżącym bloku.",
        }
        effect = effects.get(
            mode,
            "Zmieniła się pojedyncza pozycja danych w bieżącym bloku.",
        )
        return (
            f"{effect} W celu weryfikacji zaleca się użycie edytora graficznego i powiększenie (zoom > 300%)"
            " w miejscu wystąpienia błędu."
        )

    def _normalize_path(self, path: Path) -> Path:
        try:
            return path.resolve()
        except OSError:
            return path

    def _image_status(self, action: str, mode: str, extra: str | None = None) -> str:
        base = f"Wykonano poprawnie operację {action} obrazu przy użyciu trybu: {mode}"
        if extra:
            return f"{base}. {extra}"
        return base

    def _refresh_iv_state(self) -> None:
        if not self.iv_entry or not self.iv_button:
            return

        mode = self._selected_mode()
        requires_iv = mode != "ECB"
        encrypting = not self._is_decryption_mode()

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

    def _set_iv_text(self, value: str) -> None:
        if not self.iv_entry:
            return
        self.iv_entry.config(state="normal")
        self.iv_entry.delete(0, END)
        self.iv_entry.insert(0, value)
        self._refresh_iv_state()

    def _generate_iv_hex(self) -> str:
        return urandom(self._current_iv_length()).hex().upper()

    def _require_iv_hex_bytes(self) -> tuple[str, bytes]:
        if not self.iv_entry:
            raise ValueError("Pole IV jest niedostępne")
        iv_hex = self.iv_entry.get().strip().upper()
        if not iv_hex:
            raise ValueError("IV jest wymagany dla wybranego trybu")
        expected_len = self._current_iv_length()
        if len(iv_hex) != expected_len * 2:
            raise ValueError(
                f"IV musi mieć {expected_len * 2} znaki HEX ({expected_len} bajtów)"
            )
        try:
            iv_bytes = bytes.fromhex(iv_hex)
        except ValueError as exc:
            raise ValueError("IV musi być zapisany w prawidłowym formacie HEX") from exc
        return iv_hex, iv_bytes

    def _current_iv_length(self) -> int:
        return self.engine.BLOCK_SIZE_BYTES

    def _confirm_reuse(self, current: str | None, previous: str | None, what: str) -> bool:
        if not current or not previous or current != previous:
            return True
        return messagebox.askyesno(
            "Ostrzeżenie",
            f"Używasz ponownie tego samego {what} co w poprzednim szyfrowaniu. Kontynuować?",
            parent=self.parent,
        )

    def _format_size(self, size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        if size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        return f"{size_bytes / (1024 * 1024):.2f} MB"

    def on_decrypt_current(self) -> None:
        """Próbuje odszyfrować aktualnie wygenerowany szyfrogram LUB wczytany plik przy użyciu OBECNEGO klucza z UI.
        
        Służy do demonstracji efektu lawinowego oraz ręcznej deszyfracji wgranych plików.
        """
        current_ciphertext = self.output_path_var.get()
        if not current_ciphertext:
            current_ciphertext = self.input_path_var.get()

        if not current_ciphertext:
            messagebox.showwarning("Brak danych", "Najpierw zaszyfruj obraz lub wybierz plik szyfrogramu.")
            return
        
        ciphertext_path = Path(current_ciphertext)
        if not ciphertext_path.exists():
            messagebox.showerror("Błąd", f"Plik szyfrogramu nie istnieje: {ciphertext_path.name}")
            return
        if not self._is_bmp_file(ciphertext_path):
            messagebox.showerror(
                "Nieobsługiwany format",
                "Ten widok obsługuje tylko obrazy BMP (*.bmp).",
            )
            return

        self._clear_decrypted_preview()
        
        try:
            key_len = self.KEY_SIZES.get(self.key_size_var.get(), 16)
            key_bytes = validators.validate_key_hex(self.key_entry.get(), key_len)
            mode = self._selected_mode()
            
            custom_output = str(ciphertext_path.with_name(f"{ciphertext_path.stem}_odszyfrowany.bmp"))

            result_path, status = self._process_bmp_image(
                ciphertext_path, custom_output, key_bytes, "decrypt", mode
            )

            self.status_var.set(f"{status} (Klucz z UI)")
            self._decrypted_preview_img = self._load_preview(result_path)
            self._decrypted_preview_message = None
            self._refresh_previews()
            self._maybe_report_error_effect(ciphertext_path)

        except Exception as exc:
            error_msg = str(exc)
            if "padding" in error_msg.lower() or "pad" in error_msg.lower():
                self.status_var.set("Błąd Paddingu! (Zły klucz w trybie blokowym)")
                self._decrypted_preview_message = "BŁĄD PADDINGU\n\nDla trybów ECB/CBC zły klucz uniemożliwia poprawne usunięcie dopełnienia"
            else:
                self.status_var.set(f"Błąd deszyfracji: {exc}")
                self._decrypted_preview_message = f"BŁĄD:\n{exc}"
