"""Windows owner-only creation; loaded only on Windows."""

import ctypes
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from ctypes import wintypes
from pathlib import Path
from typing import cast

from .errors import _storage_error


def _api(name: str) -> ctypes.CDLL:
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise _storage_error("failed_precondition")
    return cast(ctypes.CDLL, loader(name, use_last_error=True))


class _Attributes(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.DWORD),
        ("descriptor", ctypes.c_void_p),
        ("inherit", wintypes.BOOL),
    ]


def _user_sid() -> str:
    kernel = _api("kernel32")
    security = _api("advapi32")
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    security.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    security.OpenProcessToken.restype = wintypes.BOOL
    security.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    security.GetTokenInformation.restype = wintypes.BOOL
    security.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    security.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    if not security.OpenProcessToken(
        kernel.GetCurrentProcess(), 8, ctypes.byref(token)
    ):
        raise _storage_error("failed_precondition")
    pointer = ctypes.c_void_p()
    try:
        size = wintypes.DWORD()
        security.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        if not size.value:
            raise _storage_error("failed_precondition")
        buffer = ctypes.create_string_buffer(size.value)
        if not security.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
            raise _storage_error("failed_precondition")
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents
        if not security.ConvertSidToStringSidW(sid, ctypes.byref(pointer)):
            raise _storage_error("failed_precondition")
        return ctypes.wstring_at(pointer)
    finally:
        if pointer.value is not None:
            _free(pointer)
        kernel.CloseHandle(token)


def _descriptor(directory: bool = False) -> tuple[ctypes.c_void_p, _Attributes]:
    security = _api("advapi32")
    pointer = ctypes.c_void_p()
    convert = security.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    convert.restype = wintypes.BOOL
    sid = _user_sid()
    flags = "OICI" if directory else ""
    if not convert(
        f"O:{sid}D:P(A;{flags};FA;;;{sid})",
        1,
        ctypes.byref(pointer),
        None,
    ):
        raise _storage_error("failed_precondition")
    return pointer, _Attributes(ctypes.sizeof(_Attributes), pointer, False)


def _free(pointer: ctypes.c_void_p) -> None:
    kernel = _api("kernel32")
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    kernel.LocalFree(pointer)


def _mkdir(path: Path) -> None:
    pointer, attributes = _descriptor(True)
    try:
        kernel = _api("kernel32")
        create = kernel.CreateDirectoryW
        create.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(_Attributes)]
        create.restype = wintypes.BOOL
        if not create(str(path), ctypes.byref(attributes)):
            if int(getattr(ctypes, "get_last_error")()) == 183:
                raise FileExistsError
            raise _storage_error("failed_precondition")
    finally:
        _free(pointer)


def _create(path: Path) -> None:
    pointer, attributes = _descriptor()
    try:
        kernel = _api("kernel32")
        create = kernel.CreateFileW
        create.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(_Attributes),
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        create.restype = wintypes.HANDLE
        handle = create(
            str(path), 0x40000000, 0, ctypes.byref(attributes), 1, 0x80, None
        )
        if handle == ctypes.c_void_p(-1).value:
            if int(getattr(ctypes, "get_last_error")()) in (80, 183):
                raise FileExistsError
            raise _storage_error("failed_precondition")
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        kernel.CloseHandle(handle)
    finally:
        _free(pointer)


def _check_acl(path: Path) -> None:
    security = _api("advapi32")
    get = security.GetNamedSecurityInfoW
    get.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get.restype = wintypes.DWORD
    pointer = ctypes.c_void_p()
    if get(str(path), 1, 5, None, None, None, None, ctypes.byref(pointer)) != 0:
        raise _storage_error("failed_precondition")
    text = ctypes.c_void_p()
    try:
        convert = security.ConvertSecurityDescriptorToStringSecurityDescriptorW
        convert.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
        ]
        convert.restype = wintypes.BOOL
        if not convert(pointer, 1, 5, ctypes.byref(text), None):
            raise _storage_error("failed_precondition")
        sid = _user_sid()
        if ctypes.wstring_at(text) not in {
            f"O:{sid}D:P(A;;FA;;;{sid})",
            f"O:{sid}D:P(A;OICI;FA;;;{sid})",
            f"O:{sid}D:AI(A;ID;FA;;;{sid})",
        }:
            raise _storage_error("failed_precondition")
    finally:
        if text.value is not None:
            _free(text)
        _free(pointer)


class _AttributeTag(ctypes.Structure):
    _fields_ = [("attributes", wintypes.DWORD), ("tag", wintypes.DWORD)]


@contextmanager
def _pin_directory(path: Path) -> Iterator[None]:
    if not path.is_absolute() or ".." in path.parts:
        raise _storage_error("failed_precondition")
    kernel = _api("kernel32")
    create = kernel.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    information = kernel.GetFileInformationByHandleEx
    information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    information.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    with ExitStack() as held:
        for folder in (*reversed(path.parents), path):
            # Excluding FILE_SHARE_DELETE pins every ancestor against rename/removal.
            handle = create(str(folder), 0x80, 3, None, 3, 0x02200000, None)
            if handle == ctypes.c_void_p(-1).value:
                if (
                    int(getattr(ctypes, "get_last_error")()) not in (2, 3)
                    or folder == folder.parent
                ):
                    raise _storage_error("failed_precondition")
                try:
                    _mkdir(folder)
                except FileExistsError:
                    pass
                handle = create(str(folder), 0x80, 3, None, 3, 0x02200000, None)
                if handle == ctypes.c_void_p(-1).value:
                    raise _storage_error("failed_precondition")
            held.callback(kernel.CloseHandle, handle)
            info = _AttributeTag()
            if (
                not information(handle, 9, ctypes.byref(info), ctypes.sizeof(info))
                or not info.attributes & 0x10
                or info.attributes & 0x400
            ):
                raise _storage_error("failed_precondition")
        yield
