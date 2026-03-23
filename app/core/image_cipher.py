"""Narzędzia do szyfrowania i deszyfrowania obrazów bitmapowych w celu wizualizacji efektów AES."""
from __future__ import annotations

import base64
import json
import hashlib
from os import urandom
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image, PngImagePlugin, UnidentifiedImageError

from .crypto_engine import AESCryptoEngine

_METADATA_TAG = "AES_APP_IMAGE_ECB"


class ImageCipherError(RuntimeError):
    """Zgłaszany, gdy obraz nie może zostać przetworzony przez moduł szyfrowania."""


class ImageCipher:
    """Szyfruje i deszyfruje obrazy RGB/RGBA blok po bloku na potrzeby wizualizacji."""

    def __init__(self, engine: Optional[AESCryptoEngine] = None) -> None:
        self.engine = engine or AESCryptoEngine()

    # ------------------------------------------------------------------
    # Publiczne metody pomocnicze
    # ------------------------------------------------------------------
    def is_supported_image(self, path: Path) -> bool:
        """Sprawdza, czy wskazany plik może zostać otwarty jako obraz.

        Argumenty:
            path: Ścieżka do pliku graficznego.

        Zwraca:
            bool: True, jeśli Pillow poprawnie odczyta obraz.
        """
        try:
            with Image.open(path):
                return True
        except (FileNotFoundError, UnidentifiedImageError, OSError):
            return False

    def is_encrypted_image(self, path: Path) -> bool:
        """Weryfikuje, czy plik został zaszyfrowany przez moduł obrazów AES.

        Argumenty:
            path: Ścieżka do analizowanego pliku.

        Zwraca:
            bool: True, jeśli w metadanych znajdują się informacje szyfrowania.
        """
        return self.describe_encrypted_image(path) is not None

    def describe_encrypted_image(self, path: Path) -> Optional[dict]:
        """Pobiera metadane osadzone w zaszyfrowanym pliku PNG.

        Argumenty:
            path: Ścieżka do pliku PNG.

        Zwraca:
            Optional[dict]: Słownik metadanych lub None, gdy brak danych.
        """
        try:
            with Image.open(path) as img:
                return self._extract_metadata(img)
        except (FileNotFoundError, UnidentifiedImageError, OSError):
            return None

    def encrypt_ecb(self, input_path: Path, output_path: Path, key: bytes) -> Path:
        """Szyfruje obraz i zapisuje szyfrogram pikseli jako PNG wraz z metadanymi.

        Argumenty:
            input_path: Ścieżka źródłowego obrazu.
            output_path: Lokalizacja docelowego pliku PNG.
            key: Klucz AES w bajtach.

        Zwraca:
            Path: Ścieżka do zaszyfrowanego pliku PNG.
        """

        image = self._open_image(input_path)
        original_format = image.format or (input_path.suffix[1:].upper() if input_path.suffix else "PNG")
        prepared = self._prepare_mode(image)
        mode = prepared.mode
        width, height = prepared.size
        pixel_bytes = prepared.tobytes()

        ciphertext = self.engine._encrypt_ecb(key, pixel_bytes)
        used_length = len(pixel_bytes)
        cipher_pixels = ciphertext[:used_length]
        tail = ciphertext[used_length:]

        metadata = {
            "mode": mode,
            "size": [width, height],
            "format": original_format,
            "cipher": "ECB",
            "tail": base64.b64encode(tail).decode("ascii"),
            "nonce": "",
        }

        pnginfo = PngImagePlugin.PngInfo()
        pnginfo.add_text(_METADATA_TAG, json.dumps(metadata))

        encrypted_image = Image.frombytes(mode, (width, height), cipher_pixels)
        output_path = output_path.with_suffix(".png")
        encrypted_image.save(output_path, format="PNG", pnginfo=pnginfo)
        return output_path

    def decrypt_ecb(self, input_path: Path, output_path: Path, key: bytes) -> Path:
        """Odtwarza ``encrypt_ecb`` korzystając z zapisanych metadanych.

        Argumenty:
            input_path: Ścieżka do zaszyfrowanego obrazu PNG.
            output_path: Żądana lokalizacja pliku wynikowego.
            key: Klucz AES użyty do szyfrowania.

        Zwraca:
            Path: Ścieżka do odszyfrowanego obrazu.
        """

        image = self._open_image(input_path)
        metadata = self._read_required_metadata(image)
        if metadata.get("cipher", "ECB").upper() != "ECB":
            raise ImageCipherError("Plik nie zawiera danych w trybie ECB")
        mode = metadata["mode"]
        width, height = metadata["size"]
        tail = base64.b64decode(metadata["tail"]) if metadata.get("tail") else b""
        target_format = metadata.get("format", "PNG")

        cipher_pixels = self._ensure_mode(image, mode).tobytes()
        ciphertext = cipher_pixels + tail
        plaintext = self.engine._decrypt_ecb(key, ciphertext)

        restored = Image.frombytes(mode, (width, height), plaintext)
        output_path = output_path.with_suffix(f".{target_format.lower()}")
        restored.save(output_path, format=target_format)
        return output_path

    def encrypt_ctr(self, input_path: Path, output_path: Path, key: bytes) -> Path:
        """Szyfruje obraz w trybie CTR, zapisując nonce w metadanych PNG.

        Argumenty:
            input_path: Ścieżka do oryginalnego obrazu.
            output_path: Lokalizacja docelowego pliku PNG.
            key: Klucz AES.

        Zwraca:
            Path: Ścieżka do zaszyfrowanego obrazu PNG.
        """

        image = self._open_image(input_path)
        original_format = image.format or (input_path.suffix[1:].upper() if input_path.suffix else "PNG")
        prepared = self._prepare_mode(image)
        mode = prepared.mode
        width, height = prepared.size
        pixel_bytes = prepared.tobytes()

        result = self.engine.run("encrypt", "CTR", pixel_bytes, key)
        nonce = result.iv
        if not nonce:
            raise ImageCipherError("Tryb CTR nie zwrócił nonce")

        metadata = {
            "mode": mode,
            "size": [width, height],
            "format": original_format,
            "cipher": "CTR",
            "tail": "",
            "nonce": base64.b64encode(nonce).decode("ascii"),
        }

        pnginfo = PngImagePlugin.PngInfo()
        pnginfo.add_text(_METADATA_TAG, json.dumps(metadata))
        encrypted_image = Image.frombytes(mode, (width, height), result.data)
        output_path = output_path.with_suffix(".png")
        encrypted_image.save(output_path, format="PNG", pnginfo=pnginfo)
        return output_path

    def decrypt_ctr(self, input_path: Path, output_path: Path, key: bytes) -> Path:
        """Deszyfruje obraz zaszyfrowany przy użyciu ``encrypt_ctr``.

        Argumenty:
            input_path: Ścieżka do zaszyfrowanego obrazu PNG.
            output_path: Lokalizacja pliku wynikowego.
            key: Klucz AES wykorzystywany podczas szyfrowania.

        Zwraca:
            Path: Ścieżka do odszyfrowanego obrazu.
        """

        image = self._open_image(input_path)
        metadata = self._read_required_metadata(image)
        if metadata.get("cipher", "ECB").upper() != "CTR":
            raise ImageCipherError("Plik nie został zaszyfrowany w trybie CTR")

        mode = metadata["mode"]
        width, height = metadata["size"]
        target_format = metadata.get("format", "PNG")
        nonce_b64 = metadata.get("nonce")
        if not nonce_b64:
            raise ImageCipherError("Metadane CTR nie zawierają nonce")
        nonce = base64.b64decode(nonce_b64)

        cipher_pixels = self._ensure_mode(image, mode).tobytes()
        result = self.engine.run("decrypt", "CTR", cipher_pixels, key, nonce)

        restored = Image.frombytes(mode, (width, height), result.data)
        output_path = output_path.with_suffix(f".{target_format.lower()}")
        restored.save(output_path, format=target_format)
        return output_path

    def encrypt_ofb(self, input_path: Path, output_path: Path, key: bytes) -> Path:
        """Szyfruje obraz w trybie OFB, zapisując wektor inicjujący w metadanych PNG.

        Argumenty:
            input_path: Ścieżka do wejściowego obrazu.
            output_path: Lokalizacja zapisu wynikowego PNG.
            key: Klucz AES.

        Zwraca:
            Path: Ścieżka do pliku z zaszyfrowanym obrazem.
        """

        image = self._open_image(input_path)
        original_format = image.format or (input_path.suffix[1:].upper() if input_path.suffix else "PNG")
        prepared = self._prepare_mode(image)
        mode = prepared.mode
        width, height = prepared.size
        pixel_bytes = prepared.tobytes()

        result = self.engine.run("encrypt", "OFB", pixel_bytes, key)
        if not result.iv:
            raise ImageCipherError("Tryb OFB nie zwrócił IV")

        metadata = {
            "mode": mode,
            "size": [width, height],
            "format": original_format,
            "cipher": "OFB",
            "tail": "",
            "nonce": base64.b64encode(result.iv).decode("ascii"),
        }

        pnginfo = PngImagePlugin.PngInfo()
        pnginfo.add_text(_METADATA_TAG, json.dumps(metadata))
        encrypted_image = Image.frombytes(mode, (width, height), result.data)
        output_path = output_path.with_suffix(".png")
        encrypted_image.save(output_path, format="PNG", pnginfo=pnginfo)
        return output_path

    def decrypt_ofb(self, input_path: Path, output_path: Path, key: bytes) -> Path:
        """Odszyfrowuje obraz utworzony przez :meth:`encrypt_ofb`.

        Argumenty:
            input_path: Ścieżka do zaszyfrowanego obrazu PNG.
            output_path: Lokalizacja pliku wynikowego.
            key: Klucz AES użyty przy szyfrowaniu.

        Zwraca:
            Path: Ścieżka do odszyfrowanego obrazu.
        """

        image = self._open_image(input_path)
        metadata = self._read_required_metadata(image)
        if metadata.get("cipher", "ECB").upper() != "OFB":
            raise ImageCipherError("Plik nie został zaszyfrowany w trybie OFB")

        mode = metadata["mode"]
        width, height = metadata["size"]
        target_format = metadata.get("format", "PNG")
        nonce_b64 = metadata.get("nonce")
        if not nonce_b64:
            raise ImageCipherError("Metadane OFB nie zawierają IV")
        iv = base64.b64decode(nonce_b64)

        cipher_pixels = self._ensure_mode(image, mode).tobytes()
        result = self.engine.run("decrypt", "OFB", cipher_pixels, key, iv)

        restored = Image.frombytes(mode, (width, height), result.data)
        output_path = output_path.with_suffix(f".{target_format.lower()}")
        restored.save(output_path, format=target_format)
        return output_path

    def encrypt_cfb(self, input_path: Path, output_path: Path, key: bytes) -> Path:
        """Szyfruje obraz w trybie CFB, zapisując wektor inicjujący w metadanych PNG.

        Argumenty:
            input_path: Ścieżka do wejściowego obrazu.
            output_path: Lokalizacja zapisu wynikowego PNG.
            key: Klucz AES.

        Zwraca:
            Path: Ścieżka do pliku z zaszyfrowanym obrazem.
        """

        image = self._open_image(input_path)
        original_format = image.format or (input_path.suffix[1:].upper() if input_path.suffix else "PNG")
        prepared = self._prepare_mode(image)
        mode = prepared.mode
        width, height = prepared.size
        pixel_bytes = prepared.tobytes()

        result = self.engine.run("encrypt", "CFB", pixel_bytes, key)
        if not result.iv:
            raise ImageCipherError("Tryb CFB nie zwrócił IV")

        metadata = {
            "mode": mode,
            "size": [width, height],
            "format": original_format,
            "cipher": "CFB",
            "tail": "",
            "nonce": base64.b64encode(result.iv).decode("ascii"),
        }

        pnginfo = PngImagePlugin.PngInfo()
        pnginfo.add_text(_METADATA_TAG, json.dumps(metadata))
        encrypted_image = Image.frombytes(mode, (width, height), result.data)
        output_path = output_path.with_suffix(".png")
        encrypted_image.save(output_path, format="PNG", pnginfo=pnginfo)
        return output_path

    def decrypt_cfb(self, input_path: Path, output_path: Path, key: bytes) -> Path:
        """Odszyfrowuje obraz zaszyfrowany metodą :meth:`encrypt_cfb`.

        Argumenty:
            input_path: Ścieżka do zaszyfrowanego obrazu.
            output_path: Ścieżka docelowa zapisu wyniku.
            key: Klucz AES.

        Zwraca:
            Path: Ścieżka do odszyfrowanego obrazu.
        """

        image = self._open_image(input_path)
        metadata = self._read_required_metadata(image)
        if metadata.get("cipher", "ECB").upper() != "CFB":
            raise ImageCipherError("Plik nie został zaszyfrowany w trybie CFB")

        mode = metadata["mode"]
        width, height = metadata["size"]
        target_format = metadata.get("format", "PNG")
        nonce_b64 = metadata.get("nonce")
        if not nonce_b64:
            raise ImageCipherError("Metadane CFB nie zawierają IV")
        iv = base64.b64decode(nonce_b64)

        cipher_pixels = self._ensure_mode(image, mode).tobytes()
        result = self.engine.run("decrypt", "CFB", cipher_pixels, key, iv)

        restored = Image.frombytes(mode, (width, height), result.data)
        output_path = output_path.with_suffix(f".{target_format.lower()}")
        restored.save(output_path, format=target_format)
        return output_path

    # ------------------------------------------------------------------
    # Wewnętrzne metody pomocnicze
    # ------------------------------------------------------------------
    def _open_image(self, path: Path) -> Image.Image:
        try:
            return Image.open(path)
        except (FileNotFoundError, UnidentifiedImageError, OSError) as exc:
            raise ImageCipherError(f"Nie można otworzyć pliku graficznego: {path.name}") from exc

    def _prepare_mode(self, image: Image.Image) -> Image.Image:
        if image.mode in ("RGB", "RGBA"):
            return image.copy()
        if "A" in image.mode:
            return image.convert("RGBA")
        return image.convert("RGB")

    def _ensure_mode(self, image: Image.Image, mode: str) -> Image.Image:
        if image.mode == mode:
            return image
        return image.convert(mode)

    def _extract_metadata(self, image: Image.Image) -> Optional[dict]:
        metadata_raw = image.info.get(_METADATA_TAG)
        if not metadata_raw and hasattr(image, "text"):
            metadata_raw = image.text.get(_METADATA_TAG)
        if not metadata_raw:
            return None
        try:
            metadata = json.loads(metadata_raw)
        except json.JSONDecodeError:
            return None
        return metadata

    def _read_required_metadata(self, image: Image.Image) -> dict:
        metadata = self._extract_metadata(image)
        if not metadata:
            raise ImageCipherError("Brak metadanych umożliwiających odszyfrowanie obrazu")
        required = {"mode", "size", "format"}
        if not required.issubset(metadata):
            raise ImageCipherError("Metadane obrazu są niekompletne")
        metadata.setdefault("tail", "")
        metadata.setdefault("nonce", "")
        metadata["size"] = tuple(metadata["size"])
        return metadata

def encrypt_bmp_ecb(input_path: Path | str, output_path: Path | str, key: bytes) -> Path:
    """Szyfruje obraz BMP zachowując nagłówek, aby pokazać słabości trybu ECB.

    Argumenty:
        input_path: Ścieżka do wejściowego pliku BMP.
        output_path: Lokalizacja, w której zostanie zapisany wynik.
        key: Klucz AES o długości 16/24/32 bajtów.

    Zwraca:
        Path: Ścieżka do zaszyfrowanego pliku BMP.
    """

    input_path = Path(input_path)
    output_path = Path(output_path)

    if len(key) not in (16, 24, 32):
        raise ImageCipherError("Klucz AES musi mieć 16/24/32 bajty")

    header, pixel_data = _read_bmp_sections(input_path)
    if len(pixel_data) % 16:
        raise ImageCipherError("Dane pikseli BMP muszą mieć długość będącą wielokrotnością 16 bajtów")

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    encrypted_pixels = encryptor.update(pixel_data) + encryptor.finalize()

    output_path = output_path.with_suffix(".bmp")
    output_path.write_bytes(header + encrypted_pixels)
    return output_path


def decrypt_bmp_ecb(input_path: Path | str, output_path: Path | str, key: bytes) -> Path:
    """Odszyfrowuje BMP wygenerowany przez ``encrypt_bmp_ecb`` z zachowaniem formatu bitmapy.

    Argumenty:
        input_path: Ścieżka do zaszyfrowanego pliku BMP.
        output_path: Lokalizacja zapisu odszyfrowanej wersji.
        key: Klucz AES użyty podczas szyfrowania.

    Zwraca:
        Path: Ścieżka do odszyfrowanego obrazu BMP.
    """

    input_path = Path(input_path)
    output_path = Path(output_path)

    if len(key) not in (16, 24, 32):
        raise ImageCipherError("Klucz AES musi mieć 16/24/32 bajty")

    header, pixel_data = _read_bmp_sections(input_path)
    if len(pixel_data) % 16:
        raise ImageCipherError("Dane pikseli BMP muszą mieć długość będącą wielokrotnością 16 bajtów")

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    decrypted_pixels = decryptor.update(pixel_data) + decryptor.finalize()

    output_path = output_path.with_suffix(".bmp")
    output_path.write_bytes(header + decrypted_pixels)
    return output_path


def encrypt_bmp_ctr(input_path: Path | str, output_path: Path | str, key: bytes) -> Path:
    """Szyfruje dane pikseli BMP w trybie CTR wykorzystując pochodny nonce.

    Argumenty:
        input_path: Wejściowy plik BMP.
        output_path: Ścieżka zapisu pliku wynikowego.
        key: Klucz AES.

    Zwraca:
        Path: Ścieżka do zaszyfrowanego pliku BMP.
    """

    input_path = Path(input_path)
    output_path = Path(output_path)

    if len(key) not in (16, 24, 32):
        raise ImageCipherError("Klucz AES musi mieć 16/24/32 bajty")

    header, pixel_data = _read_bmp_sections(input_path)
    nonce = _derive_ctr_nonce(header, key)

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    encrypted_pixels = encryptor.update(pixel_data) + encryptor.finalize()

    output_path = output_path.with_suffix(".bmp")
    output_path.write_bytes(header + encrypted_pixels)
    return output_path


def decrypt_bmp_ctr(input_path: Path | str, output_path: Path | str, key: bytes) -> Path:
    """Odszyfrowuje szyfrogram BMP wygenerowany przez ``encrypt_bmp_ctr``.

    Argumenty:
        input_path: Plik BMP zaszyfrowany w trybie CTR.
        output_path: Lokalizacja zapisania odszyfrowanej wersji.
        key: Klucz AES.

    Zwraca:
        Path: Ścieżka do odszyfrowanego obrazu BMP.
    """

    input_path = Path(input_path)
    output_path = Path(output_path)

    if len(key) not in (16, 24, 32):
        raise ImageCipherError("Klucz AES musi mieć 16/24/32 bajty")

    header, pixel_data = _read_bmp_sections(input_path)
    nonce = _derive_ctr_nonce(header, key)

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    decrypted_pixels = decryptor.update(pixel_data) + decryptor.finalize()

    output_path = output_path.with_suffix(".bmp")
    output_path.write_bytes(header + decrypted_pixels)
    return output_path


def _read_bmp_sections(path: Path) -> tuple[bytes, bytes]:
    data = path.read_bytes()
    if path.suffix.lower() != ".bmp":
        raise ImageCipherError("Plik wejściowy musi mieć rozszerzenie .bmp")
    if len(data) < 14:
        raise ImageCipherError("Plik BMP jest zbyt mały lub uszkodzony")

    offset_bytes = data[10:14]
    if len(offset_bytes) != 4:
        raise ImageCipherError("Nie można odczytać offsetu danych pikseli BMP")
    pixel_data_offset = int.from_bytes(offset_bytes, byteorder="little")
    if pixel_data_offset <= 0 or pixel_data_offset > len(data):
        raise ImageCipherError("Offset danych pikseli BMP jest nieprawidłowy")

    header = data[:pixel_data_offset]
    pixel_data = data[pixel_data_offset:]
    if not pixel_data:
        raise ImageCipherError("Plik BMP nie zawiera danych pikseli")
    return header, pixel_data


def _derive_ctr_nonce(header: bytes, key: bytes) -> bytes:
    digest = hashlib.sha256(key + header).digest()
    return digest[:16]


def encrypt_bmp_cbc(
    input_path: Path | str,
    output_path: Path | str,
    key: bytes,
    iv: bytes | None = None,
) -> tuple[Path, str]:
    """Szyfruje dane pikseli BMP w trybie CBC i zwraca wektor inicjujący jako hex.

    Argumenty:
        input_path: Ścieżka do obrazu BMP.
        output_path: Lokalizacja zapisu zaszyfrowanego pliku.
        key: Klucz AES.
        iv: Opcjonalny wektor inicjujący.

    Zwraca:
        tuple[Path, str]: Ścieżka do pliku BMP oraz IV zakodowany w hex.
    """

    input_path = Path(input_path)
    output_path = Path(output_path)

    if len(key) not in (16, 24, 32):
        raise ImageCipherError("Klucz AES musi mieć 16/24/32 bajty")

    header, pixel_data = _read_bmp_sections(input_path)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(pixel_data) + padder.finalize()
    iv_to_use = iv or urandom(16)
    if len(iv_to_use) != 16:
        raise ImageCipherError("IV dla trybu CBC musi mieć 16 bajtów")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv_to_use))
    encryptor = cipher.encryptor()
    encrypted_pixels = encryptor.update(padded) + encryptor.finalize()

    output_path = output_path.with_suffix(".bmp")
    output_path.write_bytes(header + encrypted_pixels)
    return output_path, iv_to_use.hex()


def decrypt_bmp_cbc(
    input_path: Path | str,
    output_path: Path | str,
    key: bytes,
    iv: str | bytes,
) -> Path:
    """Odszyfrowuje dane BMP stworzone przez ``encrypt_bmp_cbc`` z użyciem dostarczonego IV.

    Argumenty:
        input_path: Ścieżka do zaszyfrowanego BMP.
        output_path: Lokalizacja pliku wynikowego.
        key: Klucz AES.
        iv: Wektor inicjujący w postaci bajtów lub hex.

    Zwraca:
        Path: Ścieżka do odszyfrowanego obrazu BMP.
    """

    input_path = Path(input_path)
    output_path = Path(output_path)

    if len(key) not in (16, 24, 32):
        raise ImageCipherError("Klucz AES musi mieć 16/24/32 bajty")

    if isinstance(iv, str):
        try:
            iv_bytes = bytes.fromhex(iv.strip())
        except ValueError as exc:
            raise ImageCipherError("IV dla trybu CBC musi być zakodowany w HEX") from exc
    else:
        iv_bytes = iv
    if len(iv_bytes) != 16:
        raise ImageCipherError("IV dla trybu CBC musi mieć 16 bajtów")

    header, encrypted_pixels = _read_bmp_sections(input_path)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv_bytes))
    decryptor = cipher.decryptor()
    padded_plain = decryptor.update(encrypted_pixels) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    pixel_data = unpadder.update(padded_plain) + unpadder.finalize()

    output_path = output_path.with_suffix(".bmp")
    output_path.write_bytes(header + pixel_data)
    return output_path


def encrypt_bmp_ofb(
    input_path: Path | str,
    output_path: Path | str,
    key: bytes,
    iv: bytes | None = None,
) -> tuple[Path, str]:
    """Szyfruje dane pikseli BMP w trybie OFB i zwraca IV w postaci hex.

    Argumenty:
        input_path: Ścieżka do wejściowego obrazu BMP.
        output_path: Lokalizacja zapisu zaszyfrowanego pliku.
        key: Klucz AES.
        iv: Opcjonalny wektor inicjujący.

    Zwraca:
        tuple[Path, str]: Ścieżka do pliku BMP i IV zapisany w hex.
    """

    input_path = Path(input_path)
    output_path = Path(output_path)

    if len(key) not in (16, 24, 32):
        raise ImageCipherError("Klucz AES musi mieć 16/24/32 bajty")

    header, pixel_data = _read_bmp_sections(input_path)
    iv_to_use = iv or urandom(16)
    if len(iv_to_use) != 16:
        raise ImageCipherError("IV dla trybu OFB musi mieć 16 bajtów")

    cipher = Cipher(algorithms.AES(key), modes.OFB(iv_to_use))
    encryptor = cipher.encryptor()
    encrypted_pixels = encryptor.update(pixel_data) + encryptor.finalize()

    output_path = output_path.with_suffix(".bmp")
    output_path.write_bytes(header + encrypted_pixels)
    return output_path, iv_to_use.hex()


def decrypt_bmp_ofb(
    input_path: Path | str,
    output_path: Path | str,
    key: bytes,
    iv: str | bytes,
) -> Path:
    """Odszyfrowuje dane BMP uzyskane w :func:`encrypt_bmp_ofb`.

    Argumenty:
        input_path: Plik BMP zaszyfrowany trybem OFB.
        output_path: Ścieżka docelowa zapisu.
        key: Klucz AES.
        iv: Wektor inicjujący w bajtach lub hex.

    Zwraca:
        Path: Ścieżka do odszyfrowanego obrazu BMP.
    """

    input_path = Path(input_path)
    output_path = Path(output_path)

    if len(key) not in (16, 24, 32):
        raise ImageCipherError("Klucz AES musi mieć 16/24/32 bajty")

    if isinstance(iv, str):
        try:
            iv_bytes = bytes.fromhex(iv.strip())
        except ValueError as exc:
            raise ImageCipherError("IV dla trybu OFB musi być zapisany w HEX") from exc
    else:
        iv_bytes = iv
    if len(iv_bytes) != 16:
        raise ImageCipherError("IV dla trybu OFB musi mieć 16 bajtów")

    header, encrypted_pixels = _read_bmp_sections(input_path)
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv_bytes))
    decryptor = cipher.decryptor()
    pixel_data = decryptor.update(encrypted_pixels) + decryptor.finalize()

    output_path = output_path.with_suffix(".bmp")
    output_path.write_bytes(header + pixel_data)
    return output_path


def encrypt_bmp_cfb(
    input_path: Path | str,
    output_path: Path | str,
    key: bytes,
    iv: bytes | None = None,
) -> tuple[Path, str]:
    """Szyfruje dane pikseli BMP w trybie CFB i zwraca IV w formacie hex.

    Argumenty:
        input_path: Plik BMP do zaszyfrowania.
        output_path: Docelowa lokalizacja pliku wynikowego.
        key: Klucz AES.
        iv: Opcjonalny wektor inicjujący.

    Zwraca:
        tuple[Path, str]: Ścieżka do pliku BMP oraz IV jako ciąg hex.
    """

    input_path = Path(input_path)
    output_path = Path(output_path)

    if len(key) not in (16, 24, 32):
        raise ImageCipherError("Klucz AES musi mieć 16/24/32 bajty")

    header, pixel_data = _read_bmp_sections(input_path)
    iv_to_use = iv or urandom(16)
    if len(iv_to_use) != 16:
        raise ImageCipherError("IV dla trybu CFB musi mieć 16 bajtów")

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv_to_use))
    encryptor = cipher.encryptor()
    encrypted_pixels = encryptor.update(pixel_data) + encryptor.finalize()

    output_path = output_path.with_suffix(".bmp")
    output_path.write_bytes(header + encrypted_pixels)
    return output_path, iv_to_use.hex()


def decrypt_bmp_cfb(
    input_path: Path | str,
    output_path: Path | str,
    key: bytes,
    iv: str | bytes,
) -> Path:
    """Odszyfrowuje dane BMP powstałe w :func:`encrypt_bmp_cfb`.

    Argumenty:
        input_path: Plik BMP zaszyfrowany trybem CFB.
        output_path: Ścieżka zapisu odszyfrowanego pliku.
        key: Klucz AES.
        iv: Wektor inicjujący w bajtach lub hex.

    Zwraca:
        Path: Ścieżka do odszyfrowanego obrazu BMP.
    """

    input_path = Path(input_path)
    output_path = Path(output_path)

    if len(key) not in (16, 24, 32):
        raise ImageCipherError("Klucz AES musi mieć 16/24/32 bajty")

    if isinstance(iv, str):
        try:
            iv_bytes = bytes.fromhex(iv.strip())
        except ValueError as exc:
            raise ImageCipherError("IV dla trybu CFB musi być zapisany w HEX") from exc
    else:
        iv_bytes = iv
    if len(iv_bytes) != 16:
        raise ImageCipherError("IV dla trybu CFB musi mieć 16 bajtów")

    header, encrypted_pixels = _read_bmp_sections(input_path)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv_bytes))
    decryptor = cipher.decryptor()
    pixel_data = decryptor.update(encrypted_pixels) + decryptor.finalize()

    output_path = output_path.with_suffix(".bmp")
    output_path.write_bytes(header + pixel_data)
    return output_path