from __future__ import annotations

import ctypes
import json
import os
import tempfile
import time
from ctypes import wintypes
from pathlib import Path


CRYPTPROTECT_UI_FORBIDDEN = 0x1
ENTROPY = b"STTool AI settings v1"
SECRET_SCHEMA_VERSION = 2


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
        "STTool encrypted settings",
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


def _read_plaintext(path: Path) -> str:
    try:
        encrypted = path.read_bytes()
    except FileNotFoundError:
        return ""
    except OSError as exc:
        raise SecretStoreError(f"Unable to read encrypted settings: {exc}") from exc
    try:
        return _unprotect(encrypted).decode("utf-8")
    except (UnicodeDecodeError, OSError) as exc:
        raise SecretStoreError(f"Unable to decrypt settings: {exc}") from exc


def load_secret_values(path: Path) -> dict[str, str]:
    plaintext = _read_plaintext(path)
    if not plaintext:
        return {}
    try:
        payload = json.loads(plaintext)
    except json.JSONDecodeError:
        return {"shared_ai_api_key": plaintext}
    if not isinstance(payload, dict):
        return {}
    values = payload.get("values")
    if not isinstance(values, dict):
        return {}
    return {
        str(key): str(value)
        for key, value in values.items()
        if str(key).strip() and str(value).strip()
    }


def save_secret_values(path: Path, values: dict[str, str]) -> None:
    cleaned = {
        str(key): str(value).strip()
        for key, value in values.items()
        if str(key).strip() and str(value).strip()
    }
    if not cleaned:
        path.unlink(missing_ok=True)
        return
    plaintext = json.dumps(
        {"schema_version": SECRET_SCHEMA_VERSION, "values": cleaned},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    encrypted = _protect(plaintext)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encrypted)
            handle.flush()
            os.fsync(handle.fileno())
        for attempt, delay in enumerate((0.0, 0.01, 0.03, 0.1, 0.25)):
            if delay:
                time.sleep(delay)
            try:
                os.replace(temporary, path)
                break
            except PermissionError:
                if attempt == 4:
                    raise
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def load_api_key(path: Path) -> str:
    return load_secret_values(path).get("shared_ai_api_key", "")


def save_api_key(path: Path, api_key: str) -> None:
    values = load_secret_values(path)
    key = api_key.strip()
    if key:
        values["shared_ai_api_key"] = key
    else:
        values.pop("shared_ai_api_key", None)
    save_secret_values(path, values)
