from tkinter import Tk
from views.gui_main import AES_APP

if __name__ == "__main__":
    print("Uruchamianie aplikacji...")
    root = Tk()
    print("Utworzono główne okno")
    app = AES_APP(root)
    print("Utworzono aplikację")
    app.run()