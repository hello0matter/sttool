from __future__ import annotations

import ctypes
import os
from ctypes import wintypes


TH32CS_SNAPPROCESS = 0x00000002
SW_RESTORE = 9
SW_SHOW = 5


class _ProcessEntry(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


def collect_process_tree(
    root_pid: int, process_pairs: list[tuple[int, int]]
) -> set[int]:
    process_ids = {root_pid}
    while True:
        children = {
            pid
            for pid, parent_pid in process_pairs
            if parent_pid in process_ids and pid not in process_ids
        }
        if not children:
            return process_ids
        process_ids.update(children)


def _process_tree(root_pid: int) -> set[int]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        return {root_pid}
    pairs: list[tuple[int, int]] = []
    try:
        entry = _ProcessEntry()
        entry.dwSize = ctypes.sizeof(entry)
        success = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while success:
            pairs.append((int(entry.th32ProcessID), int(entry.th32ParentProcessID)))
            success = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return collect_process_tree(root_pid, pairs)


def _visible_windows(process_ids: set[int]) -> list[int]:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    handles: list[int] = []
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def visit(window: int, _parameter: int) -> bool:
        process_id = wintypes.DWORD()
        user32.GetWindowThreadProcessId(window, ctypes.byref(process_id))
        if (
            int(process_id.value) in process_ids
            and user32.IsWindowVisible(window)
            and user32.GetWindowTextLengthW(window) > 0
        ):
            handles.append(int(window))
        return True

    user32.EnumWindows(callback_type(visit), 0)
    return handles


def focus_process_window(root_pid: int) -> tuple[bool, str]:
    if os.name != "nt":
        return False, "当前系统不支持 Windows 工具面板置前"
    try:
        process_ids = _process_tree(root_pid)
        handles = _visible_windows(process_ids)
        if not handles:
            return False, f"PID {root_pid} 及其子进程没有可见工具窗口"
        window = handles[0]
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.ShowWindow(window, SW_RESTORE if user32.IsIconic(window) else SW_SHOW)
        user32.BringWindowToTop(window)
        user32.SetForegroundWindow(window)
        return True, "工具面板已置前"
    except OSError as exc:
        return False, f"无法打开工具面板: {exc}"
