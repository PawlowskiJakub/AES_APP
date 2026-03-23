"""Narzędzia do konwersji pomiędzy reprezentacjami tekstowymi a danymi bajtowymi."""
from __future__ import annotations

import binascii
import codecs
from typing import Callable

# Obsługiwane etykiety formatów są zgodne z wartościami w kontrolce UI.
TEXT_FORMAT_UTF8 = "Tekst(UTF-8)"
TEXT_FORMAT_HEX = "Heksadecymalny"
TEXT_FORMAT_BASE64 = "Base64"
OUTPUT_FORMAT_UTF8 = "UTF-8"
OUTPUT_FORMAT_HEX = "HEX"
OUTPUT_FORMAT_BASE64 = "Base64"


def _normalize_hex(text: str) -> str:
    """Usuwa typowe separatory z ciągu heksadecymalnego.

    Argumenty:
        text: Wejściowy ciąg heksadecymalny może zawierać spacje lub znaki nowej linii.

    Zwraca:
        str: Ciąg heksadecymalny bez separatorów zapisany małymi literami.
    """
    return "".join(text.split()).lower()


def plaintext_to_bytes(text: str) -> bytes:
    """Koduje tekst jawny w UTF-8, pozostawiając pusty ciąg jako puste bajty.

    Argumenty:
        text: Tekst jawny w formie łańcucha znaków.

    Zwraca:
        bytes: Zakodowane bajty UTF-8 lub pusty ciąg bajtów.
    """
    return text.encode("utf-8") if text else b""


def to_bytes(value: str, fmt: str) -> bytes:
    """Konwertuje tekst użytkownika na bajty w zadanym formacie.

    Argumenty:
        value: Źródłowy tekst wprowadzony przez użytkownika.
        fmt: Nazwa formatu określająca sposób konwersji.

    Zwraca:
        bytes: Wynikowe dane bajtowe.

    Wyjątki:
        ValueError: Gdy dostarczony ciąg nie odpowiada wybranemu formatowi.
    """
    if not value:
        return b""

    if fmt == TEXT_FORMAT_UTF8:
        return value.encode("utf-8")

    if fmt == TEXT_FORMAT_HEX:
        try:
            return bytes.fromhex(_normalize_hex(value))
        except ValueError as exc:
            raise ValueError("Niepoprawny ciąg heksadecymalny") from exc

    if fmt == TEXT_FORMAT_BASE64:
        try:
            return codecs.decode(value.encode("utf-8"), "base64")
        except Exception as exc:
            raise ValueError("Niepoprawny ciąg Base64") from exc

    raise ValueError(f"Nieobsługiwany format wejściowy: {fmt}")


def bytes_to_format(data: bytes, fmt: str) -> str:
    """Reprezentuje dane bajtowe w formacie wybranym w UI.

    Argumenty:
        data: Dane bajtowe do zserializowania.
        fmt: Docelowy format tekstowy.

    Zwraca:
        str: Tekstowa reprezentacja danych.

    Wyjątki:
        ValueError: Jeśli bajty nie mogą zostać przedstawione w zadanym formacie.
    """
    if data is None:
        return ""

    if fmt in (TEXT_FORMAT_UTF8, OUTPUT_FORMAT_UTF8):
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Wynik nie jest prawidłowym tekstem UTF-8") from exc

    if fmt in (TEXT_FORMAT_HEX, OUTPUT_FORMAT_HEX):
        return " ".join(f"{byte:02X}" for byte in data)

    if fmt in (TEXT_FORMAT_BASE64, OUTPUT_FORMAT_BASE64):
        return codecs.encode(data, "base64").decode("utf-8").rstrip("\n")

    raise ValueError(f"Nieobsługiwany format wyjściowy: {fmt}")


def bytes_to_preview(data: bytes, fmt: str) -> str:
    """Zwraca tekst podglądu, a w razie błędu przełącza się na format HEX.

    Argumenty:
        data: Dane bajtowe do wyświetlenia.
        fmt: Preferowany format podglądu.

    Zwraca:
        str: Podgląd tekstowy danych.
    """
    try:
        return bytes_to_format(data, fmt)
    except ValueError:
        return bytes_to_format(data, OUTPUT_FORMAT_HEX)
