"""Widok Tkinter prezentujący efekt lawinowy."""
from __future__ import annotations

import os
import random
from typing import Dict, List

from tkinter import END, Text, StringVar, DoubleVar
from tkinter.ttk import Button, Combobox, Entry, Frame, Label, LabelFrame, Radiobutton, Progressbar

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE_BYTES = 16
BLOCK_SIZE_BITS = BLOCK_SIZE_BYTES * 8
MODE_CHOICES = ("ECB", "CBC", "CFB", "CTR", "OFB")
KEY_SIZES = {
    "128 bitów": 16,
    "192 bity": 24,
    "256 bitów": 32,
}
MODE_IV_SPECS: Dict[str, tuple[str, int]] = {
    "CBC": ("IV (CBC)", BLOCK_SIZE_BYTES),
    "CFB": ("IV (CFB)", BLOCK_SIZE_BYTES),
    "CTR": ("Nonce (CTR)", BLOCK_SIZE_BYTES),
    "OFB": ("IV (OFB)", BLOCK_SIZE_BYTES),
}
STREAM_LIKE_MODES = {"CTR", "CFB", "OFB"}


class AvalancheEffectFrame(Frame):
    """Widok efektu lawinowego w układzie analogicznym do zakładki tekstowej.

    Argumenty:
        parent: Kontener nadrzędny przekazywany przez główne GUI aplikacji.

    Zwraca:
        AvalancheEffectFrame: Nowy widok służący do analizy efektu lawinowego.
    """

    def __init__(self, parent):
        super().__init__(parent, style="Panel.TFrame", padding=(20, 20))

        Label(self, text="Efekt lawinowy AES", style="Header.TLabel").grid(row=0, column=0, sticky="w")
        Label(
            self,
            text=(
                "Modyfikuj pojedyncze bity tekstu lub klucza, aby sprawdzić wpływ na szyfrogram"
                " w wybranym trybie AES."
            ),
            style="Description.TLabel",
            wraplength=900,
        ).grid(row=1, column=0, sticky="w", pady=(0, 20))

        self.mode_var = StringVar(value=MODE_CHOICES[0])
        self.key_size_var = StringVar(value="256 bitów")
        self.status_var = StringVar(value="Wprowadź dane lub wygeneruj losowe wartości.")
        self.avalanche_label_var = StringVar(value="Współczynnik lawinowy: —")
        self.iv_status_var = StringVar(value=self._iv_hint_text(self.mode_var.get()))
        self.iv_title_var = StringVar(value="IV (CBC) – 16 bajtów (HEX)")
        self.progress_var = DoubleVar(value=0.0)

        self.key_original_entry: Text | None = None
        self.key_modified_entry: Text | None = None
        self.iv_frame: LabelFrame | None = None
        self.iv_entry: Entry | None = None
        self.plaintext_original: Text | None = None
        self.plaintext_modified: Text | None = None
        self.ciphertext_original: Text | None = None
        self.ciphertext_modified: Text | None = None

        self.current_iv: bytes | None = None

        self._build_layout()
        self._update_iv_visibility()

    # ------------------------------------------------------------------
    # Budowanie interfejsu
    # ------------------------------------------------------------------
    def _build_layout(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        settings_frame = LabelFrame(self, text="Parametry AES", style="Section.TLabelframe", padding=(15, 15))
        settings_frame.grid(row=2, column=0, sticky="ew")
        settings_frame.grid_columnconfigure(1, weight=1)
        settings_frame.grid_columnconfigure(2, weight=1)

        Label(settings_frame, text="Tryb", style="Panel.TLabel").grid(row=0, column=0, sticky="w")
        mode_combo = Combobox(settings_frame, values=MODE_CHOICES, textvariable=self.mode_var, state="readonly", width=8)
        mode_combo.grid(row=0, column=1, sticky="w")
        mode_combo.bind("<<ComboboxSelected>>", self._on_mode_change)

        Label(settings_frame, text="Długość klucza", style="Panel.TLabel").grid(row=1, column=0, sticky="nw", pady=(10, 0))
        key_size_row = Frame(settings_frame, style="Panel.TFrame")
        key_size_row.grid(row=1, column=1, sticky="w", pady=(6, 0))
        for idx, label in enumerate(KEY_SIZES):
            Radiobutton(key_size_row, text=label, value=label, variable=self.key_size_var).grid(row=0, column=idx, padx=(0, 10))

        self.iv_frame = Frame(settings_frame, style="Panel.TFrame")
        self.iv_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        self.iv_frame.grid_columnconfigure(1, weight=1)

        Label(self.iv_frame, textvariable=self.iv_title_var, style="Panel.TLabel").grid(row=0, column=0, sticky="w", columnspan=2)

        iv_row = Frame(self.iv_frame, style="Panel.TFrame")
        iv_row.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(4, 0))
        iv_row.grid_columnconfigure(0, weight=1)
        self.iv_entry = Entry(iv_row, font=("Consolas", 10))
        self.iv_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        Button(iv_row, text="Generuj IV", command=self._generate_iv).grid(row=0, column=1)
        Label(
            self.iv_frame,
            textvariable=self.iv_status_var,
            style="Description.TLabel",
            wraplength=900,
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(8, 0))

        comparison = Frame(self, style="Panel.TFrame")
        comparison.grid(row=4, column=0, sticky="nsew", pady=(15, 10))
        comparison.grid_columnconfigure((0, 1), weight=1, uniform="compare")
        comparison.grid_rowconfigure(0, weight=1)

        original_frame = LabelFrame(comparison, text="Stan Początkowy", style="Section.TLabelframe", padding=(15, 15))
        original_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        original_frame.grid_columnconfigure(0, weight=1)
        original_frame.grid_rowconfigure(3, weight=1)

        Label(original_frame, text="Klucz (HEX)", style="Panel.TLabel").grid(row=0, column=0, sticky="w")
        self.key_original_entry = Text(original_frame, height=1, wrap="none", font=("Consolas", 10))
        self.key_original_entry.grid(row=1, column=0, sticky="ew", pady=(4, 12))
        self.key_original_entry.tag_configure("diff", background="#FFF3BF")

        Label(original_frame, text="Tekst jawny (HEX)", style="Panel.TLabel").grid(row=2, column=0, sticky="w")
        self.plaintext_original = Text(original_frame, height=4, wrap="word", font=("Consolas", 10))
        self.plaintext_original.grid(row=3, column=0, sticky="nsew", pady=(4, 0))
        self.plaintext_original.tag_configure("diff", background="#FFF3BF")

        modified_frame = LabelFrame(comparison, text="Stan po Zmianie", style="Section.TLabelframe", padding=(15, 15))
        modified_frame.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        modified_frame.grid_columnconfigure(0, weight=1)
        modified_frame.grid_rowconfigure(3, weight=1)

        Label(modified_frame, text="Klucz (HEX)", style="Panel.TLabel").grid(row=0, column=0, sticky="w")
        self.key_modified_entry = Text(modified_frame, height=1, wrap="none", font=("Consolas", 10))
        self.key_modified_entry.grid(row=1, column=0, sticky="ew", pady=(4, 12))
        self.key_modified_entry.tag_configure("diff", background="#FFF3BF")

        Label(modified_frame, text="Tekst jawny (HEX)", style="Panel.TLabel").grid(row=2, column=0, sticky="w")
        self.plaintext_modified = Text(modified_frame, height=4, wrap="word", font=("Consolas", 10))
        self.plaintext_modified.grid(row=3, column=0, sticky="nsew", pady=(4, 0))
        self.plaintext_modified.tag_configure("diff", background="#FFF3BF")

        controls = Frame(self, style="Panel.TFrame")
        controls.grid(row=5, column=0, sticky="ew", pady=(10, 0))
        controls.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="controls")
        Button(controls, text="Generuj losowy Tekst jawny i Klucz", command=self._generate_random_data).grid(row=0, column=0, padx=4, sticky="ew")
        Button(controls, text="Zmień 1 bit w Tekście jawnym", command=self._flip_plaintext_bit).grid(row=0, column=1, padx=4, sticky="ew")
        Button(controls, text="Zmień 1 bit w Kluczu", command=self._flip_key_bit).grid(row=0, column=2, padx=4, sticky="ew")
        Button(controls, text="Oblicz / Szyfruj", command=self._run_compare).grid(row=0, column=3, padx=4, sticky="ew")

        outputs = Frame(self, style="Panel.TFrame")
        outputs.grid(row=6, column=0, sticky="ew", pady=(15, 0))
        outputs.grid_columnconfigure((0, 1), weight=1, uniform="outputs")

        left_output = LabelFrame(outputs, text="Szyfrogram 1 (HEX)", style="Section.TLabelframe", padding=(10, 10))
        left_output.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left_output.grid_columnconfigure(0, weight=1)
        self.ciphertext_original = Text(left_output, height=5, wrap="word", font=("Consolas", 10), state="disabled")
        self.ciphertext_original.grid(row=0, column=0, sticky="nsew")

        right_output = LabelFrame(outputs, text="Szyfrogram 2 (HEX)", style="Section.TLabelframe", padding=(10, 10))
        right_output.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        right_output.grid_columnconfigure(0, weight=1)
        self.ciphertext_modified = Text(right_output, height=5, wrap="word", font=("Consolas", 10), state="disabled")
        self.ciphertext_modified.grid(row=0, column=0, sticky="nsew")

        visual = Frame(self, style="Panel.TFrame")
        visual.grid(row=7, column=0, sticky="ew", pady=(20, 0))
        visual.grid_columnconfigure(0, weight=1)
        Label(visual, textvariable=self.avalanche_label_var, font=("Segoe UI", 12, "bold"), foreground="#0B5ED7").grid(
            row=0, column=0, sticky="w", pady=(0, 6)
        )
        Progressbar(visual, variable=self.progress_var, maximum=100).grid(row=1, column=0, sticky="ew")

        Label(self, textvariable=self.status_var, style="Panel.TLabel").grid(row=8, column=0, sticky="w", pady=(12, 0))

    # ------------------------------------------------------------------
    # Operacje na danych
    # ------------------------------------------------------------------
    def _generate_key(self, silent: bool = False) -> None:
        key_len = KEY_SIZES.get(self.key_size_var.get(), 32)
        random_key = os.urandom(key_len)
        hex_key = _bytes_to_hex(random_key)
        self._set_text(self.key_original_entry, hex_key)
        self._set_text(self.key_modified_entry, hex_key)
        self._clear_key_highlight()
        self._clear_outputs()
        if not silent:
            self.status_var.set("Wygenerowano losowy klucz.")

    def _generate_random_data(self) -> None:
        block = _bytes_to_hex(os.urandom(BLOCK_SIZE_BYTES))
        self._set_text(self.plaintext_original, block)
        self._set_text(self.plaintext_modified, block)
        self._clear_plaintext_highlight()
        self._generate_key(silent=True)
        self._clear_key_highlight()
        self._clear_outputs()
        self._clear_iv_entry()
        self.current_iv = None
        self.iv_status_var.set(self._iv_hint_text())
        self.status_var.set("Wygenerowano losowe dane wejściowe.")

    def _flip_plaintext_bit(self) -> None:
        try:
            value = _hex_to_bytes(self._read_text(self.plaintext_modified), BLOCK_SIZE_BYTES, "Tekst jawny")
        except ValueError as exc:
            self.status_var.set(str(exc))
            return
        mutated = _flip_random_bit(value)
        self._set_text(self.plaintext_modified, _bytes_to_hex(mutated))
        self._highlight_plaintext_diff()
        self._clear_outputs()
        self.status_var.set("Zmieniono losowy bit w tekście jawnym.")

    def _flip_key_bit(self) -> None:
        expected_len = KEY_SIZES.get(self.key_size_var.get(), 32)
        try:
            value = _hex_to_bytes(self._read_text(self.key_modified_entry), expected_len, "Klucz zmieniony")
        except ValueError as exc:
            self.status_var.set(str(exc))
            return
        mutated = _flip_random_bit(value)
        self._set_text(self.key_modified_entry, _bytes_to_hex(mutated))
        self._highlight_key_diff()
        self._clear_outputs()
        self.status_var.set("Zmieniono losowy bit w kluczu.")

    def _run_compare(self) -> None:
        key_len = KEY_SIZES.get(self.key_size_var.get(), 32)
        try:
            pt_original = _hex_to_bytes(self._read_text(self.plaintext_original), BLOCK_SIZE_BYTES, "Tekst jawny – oryginał")
            pt_modified = _hex_to_bytes(self._read_text(self.plaintext_modified), BLOCK_SIZE_BYTES, "Tekst jawny – zmieniony")
            key_original = _hex_to_bytes(self._read_text(self.key_original_entry), key_len, "Klucz oryginalny")
            key_modified = _hex_to_bytes(self._read_text(self.key_modified_entry), key_len, "Klucz zmieniony")
        except ValueError as exc:
            self.status_var.set(str(exc))
            return

        mode = self.mode_var.get()
        if mode == "ECB":
            iv = None
        else:
            try:
                iv = self._resolve_iv_input()
            except ValueError as exc:
                self.status_var.set(str(exc))
                return
        self.current_iv = iv
        self._update_iv_visibility()

        try:
            cipher1 = _encrypt_block(mode, key_original, pt_original, iv)
            cipher2 = _encrypt_block(mode, key_modified, pt_modified, iv)
        except ValueError as exc:
            self.status_var.set(str(exc))
            return

        self._set_text(self.ciphertext_original, _bytes_to_hex(cipher1), readonly=True)
        self._set_text(self.ciphertext_modified, _bytes_to_hex(cipher2), readonly=True)

        diff_bits = _hamming_distance(cipher1, cipher2)
        diff_percent = (diff_bits / BLOCK_SIZE_BITS) * 100
        self.avalanche_label_var.set(f"Współczynnik lawinowy: {diff_percent:.2f}% ({diff_bits} bitów)")
        self.progress_var.set(diff_percent)
        self.status_var.set(f"Porównanie ukończone dla trybu {mode}.")

    # ------------------------------------------------------------------
    # Obsługa IV oraz pomoce
    # ------------------------------------------------------------------
    def _on_mode_change(self, _event=None) -> None:
        self.current_iv = None
        self._clear_iv_entry()
        self.iv_status_var.set(self._iv_hint_text())
        self._clear_outputs()
        self.status_var.set(f"Wybrano tryb {self.mode_var.get()}.")
        self._update_iv_visibility()

    def _update_iv_visibility(self) -> None:
        if not self.iv_frame:
            return
        mode = self.mode_var.get()
        if mode == "ECB":
            self.iv_frame.grid_remove()
            self.iv_title_var.set("IV niedostępny dla ECB")
            self.iv_status_var.set("Tryb ECB nie korzysta z IV/nonce.")
        else:
            self.iv_frame.grid()
            label, length = MODE_IV_SPECS.get(mode, ("IV", BLOCK_SIZE_BYTES))
            self.iv_title_var.set(f"{label} – {length} bajtów (HEX)")
            if self._read_iv_text():
                self.iv_status_var.set("Użyj podanego ciągu lub kliknij 'Generuj IV'.")
            else:
                self.iv_status_var.set(self._iv_hint_text(mode))

    def _generate_iv(self) -> None:
        if self.mode_var.get() == "ECB":
            self.iv_status_var.set("Tryb ECB nie korzysta z IV/nonce.")
            return
        mode = self.mode_var.get()
        _, iv_length = MODE_IV_SPECS.get(mode, ("IV", BLOCK_SIZE_BYTES))
        iv_bytes = os.urandom(iv_length)
        self.current_iv = iv_bytes
        self._set_iv_text(iv_bytes.hex().upper())
        self.iv_status_var.set("Wygenerowano losowy IV/nonce.")
        self.status_var.set("Wygenerowano losowy IV/nonce.")

    def _resolve_iv_input(self) -> bytes:
        mode = self.mode_var.get()
        spec = MODE_IV_SPECS.get(mode)
        if spec is None:
            raise ValueError("Tryb ECB nie korzysta z IV/nonce.")
        label, iv_length = spec
        raw = self._read_iv_text()
        if raw:
            iv_bytes = _hex_to_bytes(raw, iv_length, label)
            self.iv_status_var.set("Użyto ręcznie podanego IV/nonce.")
            return iv_bytes
        iv_bytes = os.urandom(iv_length)
        self._set_iv_text(iv_bytes.hex().upper())
        self.iv_status_var.set("Brak danych – wygenerowano losowy IV/nonce.")
        return iv_bytes

    def _set_iv_text(self, value: str) -> None:
        if not self.iv_entry:
            return
        self.iv_entry.delete(0, END)
        if value:
            self.iv_entry.insert(0, value)

    def _read_iv_text(self) -> str:
        if not self.iv_entry:
            return ""
        return "".join(self.iv_entry.get().split()).upper()

    def _clear_iv_entry(self) -> None:
        self._set_iv_text("")

    def _iv_hint_text(self, mode: str | None = None) -> str:
        if mode is None:
            mode = self.mode_var.get()
        spec = MODE_IV_SPECS.get(mode)
        if not spec:
            return "Tryb ECB nie korzysta z IV/nonce."
        _, iv_length = spec
        return _build_iv_hint(iv_length)

    # ------------------------------------------------------------------
    # Wspólne pomoce UI
    # ------------------------------------------------------------------
    def _set_text(self, widget: Text | None, value: str, readonly: bool = False) -> None:
        if widget is None:
            return
        widget.config(state="normal")
        widget.delete("1.0", END)
        widget.insert("1.0", value)
        if readonly:
            widget.config(state="disabled")

    def _read_text(self, widget: Text | None) -> str:
        if widget is None:
            return ""
        return _sanitize_hex(widget.get("1.0", "end-1c"))

    def _set_entry_value(self, widget: Entry | None, value: str) -> None:
        if widget is None:
            return
        widget.delete(0, END)
        if value:
            widget.insert(0, value)

    def _read_entry_value(self, widget: Entry | None) -> str:
        if widget is None:
            return ""
        return _sanitize_hex(widget.get())

    def _clear_outputs(self) -> None:
        self._set_text(self.ciphertext_original, "", readonly=True)
        self._set_text(self.ciphertext_modified, "", readonly=True)
        self.avalanche_label_var.set("Współczynnik lawinowy: —")
        self.progress_var.set(0.0)

    def _clear_plaintext_highlight(self) -> None:
        if not self.plaintext_original or not self.plaintext_modified:
            return
        for widget in (self.plaintext_original, self.plaintext_modified):
            widget.tag_remove("diff", "1.0", END)

    def _highlight_plaintext_diff(self) -> None:
        if not self.plaintext_original or not self.plaintext_modified:
            return
        self._clear_plaintext_highlight()
        original_text = self._read_text(self.plaintext_original)
        modified_text = self._read_text(self.plaintext_modified)
        limit = min(len(original_text), len(modified_text))
        
        for idx in range(limit):
            if original_text[idx] != modified_text[idx]:
                start = f"1.0 + {idx} chars"
                end = f"1.0 + {idx + 1} chars"
                self.plaintext_original.tag_add("diff", start, end)
                self.plaintext_modified.tag_add("diff", start, end)

    def _clear_key_highlight(self) -> None:
        if not self.key_original_entry or not self.key_modified_entry:
            return
        for widget in (self.key_original_entry, self.key_modified_entry):
            widget.tag_remove("diff", "1.0", END)

    def _highlight_key_diff(self) -> None:
        if not self.key_original_entry or not self.key_modified_entry:
            return
        self._clear_key_highlight()
        original_text = self._read_text(self.key_original_entry)
        modified_text = self._read_text(self.key_modified_entry)
        limit = min(len(original_text), len(modified_text))
        
        for idx in range(limit):
            if original_text[idx] != modified_text[idx]:
                start = f"1.0 + {idx} chars"
                end = f"1.0 + {idx + 1} chars"
                self.key_original_entry.tag_add("diff", start, end)
                self.key_modified_entry.tag_add("diff", start, end)


def _build_iv_hint(iv_length: int) -> str:
    return f"Podaj {iv_length * 2} znaki HEX ({iv_length} bajtów) lub kliknij 'Generuj IV'."


def _iv_length_for_mode(mode: str) -> int | None:
    spec = MODE_IV_SPECS.get(mode)
    return spec[1] if spec else None


def _sanitize_hex(value: str) -> str:
    return "".join(value.split()).upper()


def _hex_to_bytes(value: str, expected_bytes: int, field_label: str) -> bytes:
    if not value:
        raise ValueError(f"{field_label} nie może być puste")
    if len(value) != expected_bytes * 2:
        raise ValueError(f"{field_label}: podaj dokładnie {expected_bytes * 2} znaków HEX ({expected_bytes} bajtów)")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{field_label}: niepoprawny format HEX") from exc


def _bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def _flip_random_bit(data: bytes) -> bytes:
    bit_length = len(data) * 8
    mask = 1 << random.randrange(bit_length)
    mutated = int.from_bytes(data, "big") ^ mask
    return mutated.to_bytes(len(data), "big")


def _hamming_distance(a: bytes, b: bytes) -> int:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).bit_count()


def _encrypt_block(mode: str, key: bytes, block: bytes, iv: bytes | None) -> bytes:
    cipher: Cipher
    if mode == "ECB":
        cipher = Cipher(algorithms.AES(key), modes.ECB())
    elif mode == "CBC":
        if iv is None:
            raise ValueError("IV jest wymagany w trybie CBC")
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    elif mode == "CFB":
        if iv is None:
            raise ValueError("IV jest wymagany w trybie CFB")
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    elif mode == "CTR":
        if iv is None:
            raise ValueError("Nonce jest wymagany w trybie CTR")
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    elif mode == "OFB":
        if iv is None:
            raise ValueError("IV jest wymagany w trybie OFB")
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
    else:
        raise ValueError(f"Nieobsługiwany tryb: {mode}")

    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()

class AvalancheView:
    """Adapter używany przez główny notatnik GUI.

    Argumenty:
        parent: Kontener, w którym osadzany jest widok efektu lawinowego.

    Zwraca:
        AvalancheView: Instancja przygotowująca ramkę AvalancheEffectFrame.
    """

    def __init__(self, parent):
        frame = AvalancheEffectFrame(parent)
        frame.pack(fill="both", expand=True)
