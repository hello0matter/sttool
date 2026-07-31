from __future__ import annotations

import ctypes
import os
import tempfile
from pathlib import Path
from ctypes import wintypes


CRYPTPROTECT_UI_FORBIDDEN = 0x1
ENTROPY = b"STTool AI settings v1"


class SecretStoreError(RuntimeError):
    pass


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("size", wintypes.DWORD),
        ("data", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _blob(value: bytes) -> tuple[_DataBlob, ctypes.Array]:
    buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
    return _DataBlob(len(value), buffer), buffer


def _protect(value: bytes) -> bytes:
    if os.name != "nt":
        raise SecretStoreError("DPAPI is only available on Windows")
    source, source_buffer = _blob(value)
    entropy, entropy_buffer = _blob(ENTROPY)
    output = _DataBlob()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    success = crypt32.CryptProtectData(
        ctypes.byref(source),
        "STTool AI API Key",
        ctypes.byref(entropy),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(output),
    )
    _ = source_buffer, entropy_buffer
    if not success:
        raise SecretStoreError(f"DPAPI encryption failed: {ctypes.get_last_error()}")
    try:
        return ctypes.string_at(output.data, output.size)
    finally:
        kernel32.LocalFree(output.data)


def _unprotect(value: bytes) -> bytes:
    if os.name != "nt":
        raise SecretStoreError("DPAPI is only available on Windows")
    source, source_buffer = _blob(value)
    entropy, entropy_buffer = _blob(ENTROPY)
    output = _DataBlob()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    success = crypt32.CryptUnprotectData(
        ctypes.byref(source),
        None,
        ctypes.byref(entropy),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(output),
    )
    _ = source_buffer, entropy_buffer
    if not success:
        raise SecretStoreError(f"DPAPI decryption failed: {ctypes.get_last_error()}")
    try:
        return ctypes.string_at(output.data, output.size)
    finally:
        kernel32.LocalFree(output.data)


def load_api_key(path: Path) -> str:
    try:
        encrypted = path.read_bytes()
    except FileNotFoundError:
        return ""
    except OSError as exc:
        raise SecretStoreError(f"Unable to read encrypted API Key: {exc}") from exc
    try:
        return _unprotect(encrypted).decode("utf-8")
    except (UnicodeDecodeError, OSError) as exc:
        raise SecretStoreError(f"Unable to decrypt API Key: {exc}") from exc


def save_api_key(path: Path, api_key: str) -> None:
    value = api_key.strip()
    if not value:
        path.unlink(missing_ok=True)
        return
    encrypted = _protect(value.encode("utf-8"))
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encrypted)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
