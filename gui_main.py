from tkinter import Tk
from app.views.gui_main import AES_APP

if __name__ == "__main__":
    try:
        print("Uruchamianie aplikacji...")
        root = Tk()
        print("Utworzono główne okno")
        print(f"Rozmiar ekranu: {root.winfo_screenwidth()}x{root.winfo_screenheight()}")
        app = AES_APP(root)
        print("Utworzono aplikację")
        print("Uruchamianie głównej pętli...")
        app.run()
    except Exception as e:
        print(f"Błąd podczas uruchamiania aplikacji: {str(e)}")
