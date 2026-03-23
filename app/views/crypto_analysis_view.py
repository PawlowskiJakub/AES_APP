from __future__ import annotations

import os
import threading
import time
from typing import Optional

from tkinter import DoubleVar, IntVar, StringVar
from tkinter.ttk import Button, Entry, Frame, Label, LabelFrame, Progressbar, Spinbox

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class CryptoAnalysisView:
    """Zakładka prezentująca edukacyjny atak brute-force na ograniczoną przestrzeń klucza AES.

    Argumenty:
        parent: Kontener głównego interfejsu, w którym osadzana jest zakładka.

    Zwraca:
        CryptoAnalysisView: Obiekt odpowiedzialny za konfigurację i obsługę widoku.
    """

    def __init__(self, parent):
        self.parent = parent
        self.attack_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.total_candidates = 0
        self.checked_candidates = 0

        self.root: Frame | None = None
        self.start_button: Button | None = None
        self.stop_button: Button | None = None
        self.progress_bar: Progressbar | None = None
        self.missing_spin: Spinbox | None = None

        self.partial_key_var: StringVar | None = None
        self.cipher_var: StringVar | None = None
        self.expected_plaintext_var: StringVar | None = None
        self.progress_var: DoubleVar | None = None
        self.status_var: StringVar | None = None
        self.result_var: StringVar | None = None
        self.missing_bytes_var: IntVar | None = None

        self._build_gui()

    # ------------------------------------------------------------------
    # Interfejs użytkownika
    # ------------------------------------------------------------------
    def _build_gui(self) -> None:
        self.root = Frame(self.parent, style="Panel.TFrame", padding=(20, 20))
        self.root.pack(fill="both", expand=True)

        Label(
            self.root,
            text="Symulacja ataku na ograniczoną przestrzeń 128-bitowego klucza AES",
            style="Header.TLabel",
        ).pack(anchor="w")

        Label(
            self.root,
            text="Symulacja wykonywana jest w trybie ECB.",
            style="Description.TLabel",
            wraplength=900,
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

        self.partial_key_var = StringVar(master=self.root, value="")
        self.cipher_var = StringVar(master=self.root, value="")
        self.expected_plaintext_var = StringVar(master=self.root, value="")
        self.progress_var = DoubleVar(master=self.root, value=0.0)
        self.status_var = StringVar(master=self.root, value="Wprowadź dane lub użyj przycisku scenariusza testowego.")
        self.result_var = StringVar(master=self.root, value="Brak wyników.")
        self.missing_bytes_var = IntVar(master=self.root, value=2)

        scenario_frame = Frame(self.root, style="Panel.TFrame")
        scenario_frame.pack(fill="x", pady=(15, 0))
        scenario_frame.columnconfigure(2, weight=1)

        Label(scenario_frame, text="Brakujące bajty:", style="Panel.TLabel").grid(row=0, column=0, sticky="w")
        self.missing_spin = Spinbox(
            scenario_frame,
            values=(1, 2, 3),
            textvariable=self.missing_bytes_var,
            width=5,
            state="readonly",
            justify="center",
        )
        self.missing_spin.grid(row=0, column=1, sticky="w", padx=(8, 20))
        Button(scenario_frame, text="Wczytaj Scenariusz Testowy", command=self.generate_scenario).grid(
            row=0,
            column=2,
            sticky="w", 
            padx=10
        )

        input_frame = LabelFrame(self.root, text="Parametry wejściowe", padding=(15, 15), style="Section.TLabelframe")
        input_frame.pack(fill="x", pady=(20, 0))
        input_frame.columnconfigure(1, weight=1)

        Label(input_frame, text="Znana część klucza (HEX)", style="Panel.TLabel").grid(row=0, column=0, sticky="w")
        Entry(input_frame, textvariable=self.partial_key_var, font=("Consolas", 10)).grid(row=0, column=1, sticky="ew", padx=(10, 0))

        Label(input_frame, text="Docelowy szyfrogram (HEX)", style="Panel.TLabel").grid(row=1, column=0, sticky="w", pady=(10, 0))
        Entry(input_frame, textvariable=self.cipher_var, font=("Consolas", 10)).grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=(10, 0))

        Label(input_frame, text="Spodziewany tekst jawny (UTF-8)", style="Panel.TLabel").grid(row=2, column=0, sticky="w", pady=(10, 0))
        Entry(input_frame, textvariable=self.expected_plaintext_var).grid(row=2, column=1, sticky="ew", padx=(10, 0), pady=(10, 0))

        controls = Frame(self.root, style="Panel.TFrame")
        controls.pack(fill="x", pady=(20, 0))
        controls.columnconfigure((0, 1), weight=1, uniform="controls")

        self.start_button = Button(controls, text="Rozpocznij Atak", command=self.start_attack, width=20)
        self.start_button.grid(row=0, column=0, sticky="e", padx=(0, 10))

        self.stop_button = Button(controls, text="Stop", command=self.stop_attack, state="disabled", width=20)
        self.stop_button.grid(row=0, column=1, sticky="w")

        progress_frame = Frame(self.root, style="Panel.TFrame")
        progress_frame.pack(fill="x", pady=(20, 0))

        self.progress_bar = Progressbar(progress_frame, variable=self.progress_var, maximum=1)
        self.progress_bar.pack(fill="x")

        Label(progress_frame, textvariable=self.status_var, style="Description.TLabel").pack(anchor="w", pady=(8, 0))

        result_frame = LabelFrame(self.root, text="Wynik", padding=(15, 15), style="Section.TLabelframe")
        result_frame.pack(fill="x", pady=(20, 0))

        Label(
            result_frame,
            textvariable=self.result_var,
            style="Header.TLabel",
            wraplength=900,
            justify="left",
        ).pack(anchor="w")

    # ------------------------------------------------------------------
    # Kontrola ataku
    # ------------------------------------------------------------------
    def start_attack(self) -> None:
        if not self.root or not self.partial_key_var or not self.cipher_var or not self.expected_plaintext_var:
            return
        if self.attack_thread and self.attack_thread.is_alive():
            return

        try:
            known_key = bytes.fromhex(self.partial_key_var.get().strip())
        except ValueError:
            self._set_status("Niepoprawny HEX klucza.")
            return

        if len(known_key) >= 16:
            self._set_status("Znana część nie może mieć 16 bajtów.")
            return

        missing_bytes = 16 - len(known_key)
        selected_missing = self._selected_missing_bytes()
        if selected_missing is None:
            self._set_status("Wybierz liczbę brakujących bajtów (1-3).")
            return
        if missing_bytes != selected_missing:
            self._set_status(
                f"Klucz zawiera {len(known_key)} bajtów. Ustaw brakujące {missing_bytes} bajty w selektorze."
            )
            return
        if missing_bytes not in (1, 2, 3):
            self._set_status("Demonstracja obsługuje jedynie brakujące 1-3 bajty.")
            return

        try:
            ciphertext = bytes.fromhex(self.cipher_var.get().strip())
        except ValueError:
            self._set_status("Niepoprawny HEX szyfrogramu.")
            return

        if not ciphertext or len(ciphertext) % 16 != 0:
            self._set_status("Szyfrogram musi mieć wielokrotność 16 bajtów.")
            return

        expected = self.expected_plaintext_var.get().encode("utf-8")
        if not expected:
            self._set_status("Wprowadź oczekiwany tekst jawny.")
            return

        self.stop_event.clear()
        self.total_candidates = 256 ** missing_bytes
        self.checked_candidates = 0
        self._set_status("Rozpoczynam brute-force...")
        if self.progress_bar:
            self.progress_bar.config(maximum=self.total_candidates)
        if self.progress_var:
            self.progress_var.set(0)
        if self.result_var:
            self.result_var.set("Brak wyników.")
        if self.start_button:
            self.start_button.config(state="disabled")
        if self.stop_button:
            self.stop_button.config(state="normal")

        self.attack_thread = threading.Thread(
            target=self._attack_worker,
            args=(known_key, ciphertext, expected, missing_bytes),
            daemon=True,
        )
        self.attack_thread.start()

    def stop_attack(self) -> None:
        self.stop_event.set()
        self._set_status("Przerywam atak...")

    def generate_scenario(self) -> None:
        if not self.partial_key_var or not self.cipher_var or not self.expected_plaintext_var:
            return
        missing_bytes = self._selected_missing_bytes()
        if missing_bytes is None or missing_bytes not in (1, 2, 3):
            self._set_status("Wybierz liczbę brakujących bajtów (1-3).")
            return

        full_key = os.urandom(16)
        plaintext = b"AlaMaKotaAKotAle"
        cipher = Cipher(algorithms.AES(full_key), modes.ECB())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        known_part = full_key[:-missing_bytes]
        self.partial_key_var.set(known_part.hex().upper())
        self.cipher_var.set(ciphertext.hex().upper())
        self.expected_plaintext_var.set(plaintext.decode("utf-8"))
        self._set_status(
            f"Przygotowano scenariusz. Brakujące bajty: {missing_bytes}. Kliknij 'Rozpocznij Atak'."
        )
        if self.result_var:
            self.result_var.set("Brak wyników.")

    # ------------------------------------------------------------------
    # Logika ataku
    # ------------------------------------------------------------------
    def _attack_worker(self, known_key: bytes, ciphertext: bytes, expected: bytes, missing_bytes: int) -> None:
        start = time.perf_counter()
        total = self.total_candidates or 1
        update_step = 1000
        checked = 0

        for suffix in range(total):
            if self.stop_event.is_set():
                break

            candidate_key = known_key + suffix.to_bytes(missing_bytes, "big")
            checked = suffix + 1
            if self._matches(candidate_key, ciphertext, expected):
                elapsed = time.perf_counter() - start
                self._finish(success=True, key_hex=candidate_key.hex().upper(), elapsed=elapsed, checked=checked)
                return

            if checked % update_step == 0:
                self._update_progress(checked)

        elapsed = time.perf_counter() - start
        if checked and checked % update_step != 0:
            self._update_progress(checked)
        if not self.stop_event.is_set():
            self._finish(success=False, key_hex="", elapsed=elapsed, checked=checked or total)
        else:
            self._finish(success=False, key_hex="", elapsed=elapsed, checked=checked)

    def _matches(self, key: bytes, ciphertext: bytes, expected: bytes) -> bool:
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.startswith(expected)

    # ------------------------------------------------------------------
    # Aktualizacje UI (wykonywane w wątku głównym)
    # ------------------------------------------------------------------
    def _update_progress(self, checked: int) -> None:
        self.checked_candidates = checked
        if self.root:
            self.root.after(0, self._apply_progress, checked)

    def _apply_progress(self, checked: int) -> None:
        if self.progress_var:
            self.progress_var.set(checked)
        total = self.total_candidates or 1
        self._set_status(f"Sprawdzono {checked:,} / {total:,} kluczy...")

    def _finish(self, success: bool, key_hex: str, elapsed: float, checked: int) -> None:
        if not self.root:
            return
        self.root.after(0, self._apply_finish, success, key_hex, elapsed, checked)

    def _apply_finish(self, success: bool, key_hex: str, elapsed: float, checked: int) -> None:
        if self.progress_var:
            self.progress_var.set(min(checked, self.total_candidates or checked))
        if self.start_button:
            self.start_button.config(state="normal")
        if self.stop_button:
            self.stop_button.config(state="disabled")
        if success and self.result_var:
            self.result_var.set(f"Znaleziono klucz: {key_hex}\nCzas: {elapsed:.2f}s po {checked:,} próbach.")
            self._set_status("Sukces! Klucz został odnaleziony.")
        elif self.stop_event.is_set():
            if self.result_var:
                self.result_var.set("Atak przerwany przez użytkownika.")
            self._set_status(f"Zatrzymano po {checked:,} próbach.")
        else:
            if self.result_var:
                self.result_var.set("Nie znaleziono dopasowania w przeszukiwanej przestrzeni.")
            self._set_status(f"Zakończono. Sprawdzono {checked:,} kluczy.")
        self.checked_candidates = checked

    def _set_status(self, message: str) -> None:
        if self.status_var:
            self.status_var.set(message)

    def _selected_missing_bytes(self) -> Optional[int]:
        if not self.missing_bytes_var:
            return None
        try:
            value = int(self.missing_bytes_var.get())
        except (TypeError, ValueError):
            return None
        if value not in (1, 2, 3):
            return None
        return value