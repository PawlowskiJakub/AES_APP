"""Enkapsułuje operacje AES wykorzystywane w warstwie interfejsu graficznego."""
from __future__ import annotations

from dataclasses import dataclass
from os import urandom
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class UnsupportedModeError(ValueError):
    """Sygnalizuje wybór trybu AES, który nie został jeszcze zaimplementowany."""


@dataclass(frozen=True)
class CryptoResult:
    """Kontener na wynik operacji kryptograficznej.

    Argumenty:
        data: Surowy wynik (szyfrogram lub tekst jawny) uzyskany z operacji.
        iv: Wektor inicjujący lub nonce użyty podczas szyfrowania strumieniowego.
        tag: Tag uwierzytelniający zwracany przez tryb GCM.

    Zwraca:
        CryptoResult: Obiekt przechowujący dane oraz metadane (IV i tag).
    """

    data: bytes
    iv: Optional[bytes] = None
    tag: Optional[bytes] = None


class AESCryptoEngine:
    """Udostępnia wysokopoziomowe pomocnicze operacje AES na potrzeby widoku Tkinter."""

    BLOCK_SIZE_BYTES = 16
    _BACKEND = default_backend()

    def __init__(self) -> None:
        self._padder_factory = padding.PKCS7(self.BLOCK_SIZE_BYTES * 8)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def run(
        self,
        operation: str,
        mode: str,
        data: bytes,
        key: bytes,
        iv: Optional[bytes] = None,
    ) -> CryptoResult:
        """Wykonuje wskazaną operację AES w wybranym trybie.

        Argumenty:
            operation: Nazwa operacji (np. ``szyfrowanie`` lub ``deszyfrowanie``).
            mode: Nazwa trybu AES (ECB, CBC, CTR, GCM, OFB, CFB).
            data: Dane wejściowe w postaci bajtów.
            key: Klucz AES w bajtach.
            iv: Opcjonalny wektor inicjujący lub nonce.

        Zwraca:
            CryptoResult: Wynik operacji wraz z ewentualnym IV i tagiem.
        """
        op = operation.lower()
        mode_name = mode.upper()

        if mode_name == "ECB":
            if op == "szyfrowanie" or op == "encrypt":
                return CryptoResult(self._encrypt_ecb(key, data))
            if op == "deszyfrowanie" or op == "decrypt":
                return CryptoResult(self._decrypt_ecb(key, data))
            raise ValueError(f"Nieznana operacja: {operation}")

        if mode_name == "CBC":
            if op == "szyfrowanie" or op == "encrypt":
                return self._encrypt_cbc(key, data, iv)
            if op == "deszyfrowanie" or op == "decrypt":
                return self._decrypt_cbc(key, data, iv)
            raise ValueError(f"Nieznana operacja: {operation}")

        if mode_name == "CTR":
            if op == "szyfrowanie" or op == "encrypt":
                return self._encrypt_ctr(key, data, iv)
            if op == "deszyfrowanie" or op == "decrypt":
                return self._decrypt_ctr(key, data, iv)
            raise ValueError(f"Nieznana operacja: {operation}")

        if mode_name == "GCM":
            if op == "szyfrowanie" or op == "encrypt":
                return self._encrypt_gcm(key, data, iv)
            if op == "deszyfrowanie" or op == "decrypt":
                return self._decrypt_gcm(key, data, iv)
            raise ValueError(f"Nieznana operacja: {operation}")

        if mode_name == "OFB":
            if op == "szyfrowanie" or op == "encrypt":
                return self._encrypt_ofb(key, data, iv)
            if op == "deszyfrowanie" or op == "decrypt":
                return self._decrypt_ofb(key, data, iv)
            raise ValueError(f"Nieznana operacja: {operation}")

        if mode_name == "CFB":
            if op == "szyfrowanie" or op == "encrypt":
                return self._encrypt_cfb(key, data, iv)
            if op == "deszyfrowanie" or op == "decrypt":
                return self._decrypt_cfb(key, data, iv)
            raise ValueError(f"Nieznana operacja: {operation}")

        raise UnsupportedModeError(f"Tryb {mode} nie jest jeszcze zaimplementowany")

    def encrypt_ofb(self, data: bytes, key: bytes) -> bytes:
        """Szyfruje dane w trybie OFB i zwraca złączenie ``IV || szyfrogram``.

        Argumenty:
            data: Dane wejściowe do zaszyfrowania.
            key: Klucz AES wykorzystywany przy szyfrowaniu.

        Zwraca:
            bytes: Połączony wektor inicjujący oraz szyfrogram.
        """

        result = self._encrypt_ofb(key, data)
        if not result.iv:
            raise ValueError("Tryb OFB wymaga IV")
        return result.iv + result.data

    def decrypt_ofb(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Odszyfrowuje wynik wygenerowany przez :meth:`encrypt_ofb`.

        Argumenty:
            encrypted_data: Ciąg ``IV || szyfrogram``.
            key: Klucz AES użyty do odszyfrowania.

        Zwraca:
            bytes: Odtworzony tekst jawny.
        """

        if len(encrypted_data) < self.BLOCK_SIZE_BYTES:
            raise ValueError("Zaszyfrowane dane są zbyt krótkie – brak IV")
        iv = encrypted_data[: self.BLOCK_SIZE_BYTES]
        ciphertext = encrypted_data[self.BLOCK_SIZE_BYTES :]
        return self._decrypt_ofb(key, ciphertext, iv).data

    def encrypt_file_gcm(self, data: bytes, key: bytes) -> bytes:
        """Szyfruje dowolne bajty w trybie AES-GCM zwracając ``IV || szyfrogram || tag``.

        Argumenty:
            data: Dane pliku do zaszyfrowania.
            key: Klucz AES 128/192/256 bit.

        Zwraca:
            bytes: Połączony wektor inicjujący, szyfrogram oraz tag GCM.
        """

        iv = urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self._BACKEND)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv + ciphertext + encryptor.tag

    def decrypt_file_gcm(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Odszyfrowuje dane z :meth:`encrypt_file_gcm`, weryfikując integralność tagu.

        Argumenty:
            encrypted_data: Ciąg ``IV || szyfrogram || tag``.
            key: Klucz AES użyty przy szyfrowaniu.

        Zwraca:
            bytes: Odszyfrowane dane.
        """

        if len(encrypted_data) < 28:  # minimalnie 12-bajtowy IV i 16-bajtowy tag
            raise ValueError("Zaszyfrowane dane są zbyt krótkie dla GCM")

        iv = encrypted_data[:12]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[12:-16]

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=self._BACKEND)
        decryptor = cipher.decryptor()
        try:
            return decryptor.update(ciphertext) + decryptor.finalize()
        except InvalidTag as exc:
            raise ValueError("Naruszenie integralności pliku (błędny tag GCM)!") from exc

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _encrypt_ecb(self, key: bytes, plaintext: bytes) -> bytes:
        padded = self._pad(plaintext)
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self._BACKEND)
        encryptor = cipher.encryptor()
        return encryptor.update(padded) + encryptor.finalize()

    def _decrypt_ecb(self, key: bytes, ciphertext: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self._BACKEND)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return self._unpad(padded_plaintext)

    def _encrypt_cbc(self, key: bytes, plaintext: bytes, iv: Optional[bytes]) -> CryptoResult:
        iv_to_use = iv or urandom(self.BLOCK_SIZE_BYTES)
        padded = self._pad(plaintext)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv_to_use), backend=self._BACKEND)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return CryptoResult(ciphertext, iv_to_use)

    def _decrypt_cbc(self, key: bytes, ciphertext: bytes, iv: Optional[bytes]) -> CryptoResult:
        if not iv:
            raise ValueError("Tryb CBC wymaga podania wektora inicjalizacyjnego (IV)")
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self._BACKEND)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = self._unpad(padded_plaintext)
        return CryptoResult(plaintext, iv)

    def _encrypt_ctr(self, key: bytes, plaintext: bytes, nonce: Optional[bytes]) -> CryptoResult:
        """Szyfruje dane w trybie CTR.

        Nadawca **musi** zagwarantować, że nonce nie jest ponownie używany z tym samym kluczem,
        w przeciwnym razie tryb CTR ujawnia strumień klucza. Gdy ``nonce`` ma wartość ``None``,
        generowany jest nowy losowy 16-bajtowy wektor.

        Argumenty:
            key: Klucz AES wykorzystywany w operacji.
            plaintext: Tekst jawny do zaszyfrowania.
            nonce: Opcjonalny 16-bajtowy licznik/nonce.

        Zwraca:
            CryptoResult: Szyfrogram wraz z nonce użytym podczas operacji.
        """

        nonce_to_use = nonce or urandom(self.BLOCK_SIZE_BYTES)
        if len(nonce_to_use) != self.BLOCK_SIZE_BYTES:
            raise ValueError("Tryb CTR wymaga 16-bajtowego nonce")
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce_to_use), backend=self._BACKEND)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return CryptoResult(ciphertext, nonce_to_use)

    def _decrypt_ctr(self, key: bytes, ciphertext: bytes, nonce: Optional[bytes]) -> CryptoResult:
        if not nonce:
            raise ValueError("Tryb CTR wymaga podania nonce")
        if len(nonce) != self.BLOCK_SIZE_BYTES:
            raise ValueError("Tryb CTR wymaga 16-bajtowego nonce")
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=self._BACKEND)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return CryptoResult(plaintext, nonce)

    def _encrypt_gcm(self, key: bytes, plaintext: bytes, iv: Optional[bytes]) -> CryptoResult:
        default_len = 12
        iv_to_use = iv or urandom(default_len)
        if len(iv_to_use) not in (default_len, self.BLOCK_SIZE_BYTES):
            raise ValueError("Tryb GCM wymaga 12-bajtowego IV/nonce")
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv_to_use), backend=self._BACKEND)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return CryptoResult(ciphertext + encryptor.tag, iv_to_use, encryptor.tag)

    def _decrypt_gcm(self, key: bytes, ciphertext_with_tag: bytes, iv: Optional[bytes]) -> CryptoResult:
        if not iv:
            raise ValueError("Tryb GCM wymaga podania IV/nonce")
        if len(iv) not in (12, self.BLOCK_SIZE_BYTES):
            raise ValueError("Tryb GCM wymaga 12-bajtowego IV/nonce")
        if len(ciphertext_with_tag) < 16:
            raise ValueError("Dane GCM muszą zawierać przynajmniej tag (16 bajtów)")
        tag = ciphertext_with_tag[-16:]
        ciphertext = ciphertext_with_tag[:-16]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=self._BACKEND)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return CryptoResult(plaintext, iv, tag)

    def _encrypt_ofb(self, key: bytes, plaintext: bytes, iv: Optional[bytes]) -> CryptoResult:
        iv_to_use = iv or urandom(self.BLOCK_SIZE_BYTES)
        if len(iv_to_use) != self.BLOCK_SIZE_BYTES:
            raise ValueError("Tryb OFB wymaga 16-bajtowego IV")
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv_to_use), backend=self._BACKEND)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return CryptoResult(ciphertext, iv_to_use)

    def _decrypt_ofb(self, key: bytes, ciphertext: bytes, iv: Optional[bytes]) -> CryptoResult:
        if not iv:
            raise ValueError("Tryb OFB wymaga podania IV")
        if len(iv) != self.BLOCK_SIZE_BYTES:
            raise ValueError("Tryb OFB wymaga 16-bajtowego IV")
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=self._BACKEND)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return CryptoResult(plaintext, iv)

    def _encrypt_cfb(self, key: bytes, plaintext: bytes, iv: Optional[bytes]) -> CryptoResult:
        iv_to_use = iv or urandom(self.BLOCK_SIZE_BYTES)
        if len(iv_to_use) != self.BLOCK_SIZE_BYTES:
            raise ValueError("Tryb CFB wymaga 16-bajtowego IV")
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv_to_use), backend=self._BACKEND)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return CryptoResult(ciphertext, iv_to_use)

    def _decrypt_cfb(self, key: bytes, ciphertext: bytes, iv: Optional[bytes]) -> CryptoResult:
        if not iv:
            raise ValueError("Tryb CFB wymaga podania IV")
        if len(iv) != self.BLOCK_SIZE_BYTES:
            raise ValueError("Tryb CFB wymaga 16-bajtowego IV")
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=self._BACKEND)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return CryptoResult(plaintext, iv)

    def _pad(self, data: bytes) -> bytes:
        padder = self._padder_factory.padder()
        return padder.update(data) + padder.finalize()

    def _unpad(self, data: bytes) -> bytes:
        unpadder = self._padder_factory.unpadder()
        try:
            return unpadder.update(data) + unpadder.finalize()
        except ValueError:
            # Błąd paddingu, zwróć surowe dane
            return data
