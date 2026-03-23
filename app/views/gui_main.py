from tkinter import *
from tkinter.ttk import *
from .encryption_view import EncryptionView
from .file_encryption_view import FileEncryptionView
from .avalanche_view import AvalancheView
from .benchmark_view import PerformanceBenchmarkView
from .crypto_analysis_view import CryptoAnalysisView

class AES_APP:
    def __init__(self, root): # Inicjalizacja aplikacji AES z głównym oknem Tkinter
        self.root = root
        self.root.title("Aplikacja demonstrująca szyfrowanie AES")
        self.root.geometry("1920x1080")
        self.build_gui()

    def build_gui(self):
        main_frame = Frame(self.root)
        main_frame.pack(fill="both", expand=True)

        self.notebook = Notebook(main_frame)
        self.notebook.pack(fill="both", expand=True)

        # Konfiguracja zakładek interfejsu
        self.encryption_tab = Frame(self.notebook)
        self.file_tab = Frame(self.notebook)
        self.avalanche_tab = Frame(self.notebook)
        self.performance_tab = Frame(self.notebook)
        self.analysis_tab = Frame(self.notebook)

        # Dodawanie przygotowanych zakładek do kontrolki Notebook
        self.notebook.add(self.encryption_tab, text="Tekst - Szyfrowanie/Deszyfrowanie")
        self.notebook.add(self.file_tab, text="Obraz - Szyfrowanie/Deszyfrowanie")
        self.notebook.add(self.avalanche_tab, text="Efekt lawinowy")
        self.notebook.add(self.performance_tab, text="Analiza wydajności trybów")
        self.notebook.add(self.analysis_tab, text="Kryptoanaliza")

        # Inicjalizacja widoków odpowiadających poszczególnym funkcjom aplikacji
        EncryptionView(self.encryption_tab)
        FileEncryptionView(self.file_tab)
        AvalancheView(self.avalanche_tab)
        PerformanceBenchmarkView(self.performance_tab)
        CryptoAnalysisView(self.analysis_tab)

    def run(self):
        self.root.mainloop()