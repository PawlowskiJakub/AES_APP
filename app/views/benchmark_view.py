"""Widok Tkinter prezentujący benchmark wydajności trybów AES."""
from __future__ import annotations

import os
import time
from typing import Dict

from tkinter import StringVar
from tkinter.ttk import Button, Combobox, Frame, Label, Radiobutton

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE_BYTES = 16

class PerformanceBenchmarkView:
    """Samodzielny widok benchmarku wydajności trybów AES.

    Argumenty:
        parent: Kontener, do którego dodawany jest widok benchmarku.

    Zwraca:
        PerformanceBenchmarkView: Obiekt odpowiedzialny za layout i logikę testu.
    """

    KEY_SIZES = {
        "128 bitów": 16,
        "192 bity": 24,
        "256 bitów": 32,
    }

    def __init__(self, parent):
        self.root = Frame(parent, style="Panel.TFrame", padding=(20, 20))
        self.root.pack(fill="both", expand=True)

        self.benchmark_canvas: FigureCanvasTkAgg | None = None
        self.benchmark_ax = None
        self.benchmark_status_var = StringVar(value="Uruchom test, aby zobaczyć wyniki.")
        self.key_size_var = StringVar(value="128 bitów")
        self.benchmark_button: Button | None = None
        self.size_combo: Combobox | None = None
        self.benchmark_modes = ["ECB", "CBC", "CFB", "CTR", "OFB"]

        self._build_layout()

    def _build_layout(self) -> None:
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)

        controls_frame = Frame(self.root, style="Panel.TFrame")
        controls_frame.grid(row=0, column=0, sticky="ew")

        Label(controls_frame, text="Wielkość pliku:", style="Panel.TLabel").pack(side="left", padx=(0, 5))

        self.size_combo = Combobox(
            controls_frame,
            values=["1 MB", "2 MB", "5 MB", "10 MB", "20 MB", "50 MB"],
            state="readonly",
            width=10,
        )
        self.size_combo.current(3)  # 10 MB
        self.size_combo.pack(side="left", padx=(0, 10))

        Label(controls_frame, text="|", style="Panel.TLabel").pack(side="left", padx=5)

        Label(controls_frame, text="Wybierz długość klucza:", style="Panel.TLabel").pack(side="left", padx=(5, 5))
        for label in ["128 bitów", "192 bity", "256 bitów"]:
            Radiobutton(
                controls_frame,
                text=label,
                value=label,
                variable=self.key_size_var
            ).pack(side="left", padx=2)

        self.benchmark_button = Button(
            controls_frame,
            text="Uruchom test",
            command=self.run_benchmark,
            width=20,
        )
        self.benchmark_button.pack(side="left", padx=(15, 0))

        plot_frame = Frame(self.root, style="Panel.TFrame")
        plot_frame.grid(row=1, column=0, sticky="nsew", pady=20)
        plot_frame.grid_columnconfigure(0, weight=1)
        plot_frame.grid_rowconfigure(0, weight=1)

        figure = Figure(figsize=(6, 4), dpi=100)
        self.benchmark_ax = figure.add_subplot(111)
        self.benchmark_ax.set_title("Czas szyfrowania (wybierz rozmiar)")
        self.benchmark_ax.set_xlabel("Tryb pracy")
        self.benchmark_ax.set_ylabel("Czas [s]")
        for spine in ("top", "right"):
            self.benchmark_ax.spines[spine].set_visible(False)

        self.benchmark_canvas = FigureCanvasTkAgg(figure, master=plot_frame)
        self.benchmark_canvas.draw()
        self.benchmark_canvas.get_tk_widget().pack(fill="both", expand=True)

        Label(
            self.root,
            textvariable=self.benchmark_status_var,
            wraplength=900,
            style="Panel.TLabel",
        ).grid(row=2, column=0, sticky="ew")

    def run_benchmark(self) -> None:
        """Wykonuje pomiar czasów szyfrowania dla kilku trybów AES.

        Argumenty:
            Brak.

        Zwraca:
            None: Aktualizuje wykres oraz opisy statusu w interfejsie.
        """

        if not self.benchmark_button:
            return

        size_str = self.size_combo.get() if self.size_combo else "10 MB"
        try:
            size_int = int(size_str.split()[0])
        except ValueError:
            size_int = 10

        key_label = self.key_size_var.get()
        key_len = self.KEY_SIZES.get(key_label, 16)

        self.benchmark_button.config(state="disabled")
        self.benchmark_status_var.set(f"Trwa test wydajności ({size_int}MB, AES-{key_len*8})...")
        self.root.update_idletasks()

        payload_size = size_int * 1024 * 1024
        payload = os.urandom(payload_size)
        results: Dict[str, float | None] = {}

        for mode in self.benchmark_modes:
            key = os.urandom(key_len)
            iv = None
            if mode != "ECB":
                iv = os.urandom(BLOCK_SIZE_BYTES)
            try:
                cipher = self._build_benchmark_cipher(mode, key, iv)
                encryptor = cipher.encryptor()
                start = time.perf_counter()
                encryptor.update(payload)
                encryptor.finalize()
                results[mode] = time.perf_counter() - start
            except Exception:
                results[mode] = None

        self._render_benchmark_plot(results, size_int, key_label)

        summary_parts = []
        for mode in self.benchmark_modes:
            duration = results.get(mode)
            if duration is None:
                summary_parts.append(f"{mode}: błąd")
            else:
                summary_parts.append(f"{mode}: {duration:.4f} s")
        self.benchmark_status_var.set(" | ".join(summary_parts) or "Brak wyników.")

        self.benchmark_button.config(state="normal")

    def _build_benchmark_cipher(self, mode: str, key: bytes, iv: bytes | None) -> Cipher:
        """Zwraca obiekt Cipher odpowiedni do wskazanego trybu.

        Argumenty:
            mode: Nazwa trybu AES używanego w benchmarku.
            key: Losowo wygenerowany klucz o długości bloku.
            iv: Opcjonalny wektor inicjujący lub nonce, zależny od trybu.

        Zwraca:
            Cipher: Obiekt kryptograficzny przygotowany do szyfrowania testowego.
        """

        if mode == "ECB":
            return Cipher(algorithms.AES(key), modes.ECB())
        if mode == "CBC":
            if iv is None:
                raise ValueError("IV jest wymagany dla trybu CBC")
            return Cipher(algorithms.AES(key), modes.CBC(iv))
        if mode == "CFB":
            if iv is None:
                raise ValueError("IV jest wymagany dla trybu CFB")
            return Cipher(algorithms.AES(key), modes.CFB(iv))
        if mode == "CTR":
            if iv is None:
                raise ValueError("Nonce jest wymagany dla trybu CTR")
            return Cipher(algorithms.AES(key), modes.CTR(iv))
        if mode == "OFB":
            if iv is None:
                raise ValueError("IV jest wymagany dla trybu OFB")
            return Cipher(algorithms.AES(key), modes.OFB(iv))
        raise ValueError(f"Nieobsługiwany tryb benchmarku: {mode}")

    def _render_benchmark_plot(self, results: Dict[str, float | None], size_mb: int = 10, key_info: str = "128 bitów") -> None:
        """Aktualizuje wykres słupkowy z najnowszymi wynikami.

        Argumenty:
            results: Mapowanie trybów AES na zmierzone czasy szyfrowania lub błąd.
            size_mb: Rozmiar danych w MB użyty w teście.
            key_info: Informacja tekstowa o długości użytego klucza.

        Zwraca:
            None: Odświeża komponent Matplotlib osadzony w interfejsie.
        """

        if not self.benchmark_canvas or self.benchmark_ax is None:
            return

        self.benchmark_ax.clear()

        modes_order = self.benchmark_modes
        values = [results.get(mode) for mode in modes_order]
        plotted_values = [value if value is not None else 0.0 for value in values]

        valid_results = {mode: value for mode, value in zip(modes_order, values) if value is not None}
        fastest_mode = min(valid_results, key=valid_results.get) if valid_results else None

        colors = []
        for mode in modes_order:
            if fastest_mode and mode == fastest_mode:
                colors.append("#90EE90")
            else:
                colors.append("#87CEEB")

        bars = self.benchmark_ax.bar(modes_order, plotted_values, color=colors)

        max_value = max(plotted_values) if plotted_values else 0.0
        label_offset = max(0.01, max_value * 0.05)
        for idx, bar in enumerate(bars):
            duration = values[idx]
            label = "ERR" if duration is None else f"{duration:.3f}s"
            height = bar.get_height()
            self.benchmark_ax.text(
                bar.get_x() + bar.get_width() / 2,
                height + label_offset,
                label,
                ha="center",
                va="bottom",
                fontsize=9,
                color="#333333",
            )

        upper_limit = max_value + label_offset * 2
        if upper_limit <= 0:
            upper_limit = 0.1

        self.benchmark_ax.set_title(f"Czas szyfrowania {size_mb}MB danych (klucz {key_info})")
        self.benchmark_ax.set_xlabel("Tryb pracy")
        self.benchmark_ax.set_ylabel("Czas [s]")
        self.benchmark_ax.set_ylim(0, upper_limit)
        for spine in ("top", "right"):
            self.benchmark_ax.spines[spine].set_visible(False)

        self.benchmark_canvas.draw_idle()
