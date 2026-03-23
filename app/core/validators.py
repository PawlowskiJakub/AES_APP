"""Pomocnicze walidatory wejścia wykorzystywane w widoku szyfrowania."""
from __future__ import annotations

from typing import Optional

from . import converters


def validate_key_hex(key_hex: str, expected_length: int) -> bytes:
    """Waliduje klucz AES w formacie HEX i zwraca jego reprezentację bajtową.

    Argumenty:
        key_hex: Klucz podany przez użytkownika jako tekst HEX.
        expected_length: Oczekiwana długość klucza w bajtach.

    Zwraca:
        bytes: Klucz zakodowany w postaci bajtów.
    """
    cleaned = (key_hex or "").strip()
    if not cleaned:
        raise ValueError("Wprowadź klucz w formacie HEX")

    try:
        key_bytes = bytes.fromhex("".join(cleaned.split()))
    except ValueError as exc:
        raise ValueError("Klucz musi być poprawnym ciągiem heksadecymalnym") from exc

    if len(key_bytes) != expected_length:
        raise ValueError(f"Klucz musi mieć dokładnie {expected_length * 8} bitów")

    return key_bytes


def validate_iv_hex(iv_hex: str, required_length: int = 16, *, required: bool = False) -> Optional[bytes]:
    """Waliduje wektor inicjujący w formacie HEX i zwraca go jako bajty.

    Argumenty:
        iv_hex: Ciąg znaków zawierający IV zakodowany w HEX.
        required_length: Wymagana długość IV w bajtach.
        required: Jeżeli True, brak wartości powoduje zgłoszenie błędu.

    Zwraca:
        Optional[bytes]: Wektor inicjujący jako bajty lub None, gdy parametr nie jest wymagany.
    """
    cleaned = (iv_hex or "").strip()

    if not cleaned:
        if required:
            raise ValueError("Wprowadź wektor inicjalizacyjny (IV) w formacie HEX")
        return None

    try:
        iv_bytes = bytes.fromhex("".join(cleaned.split()))
    except ValueError as exc:
        raise ValueError("IV musi być poprawnym ciągiem heksadecymalnym") from exc

    if len(iv_bytes) != required_length:
        raise ValueError(f"IV musi mieć dokładnie {required_length * 8} bitów")

    return iv_bytes
