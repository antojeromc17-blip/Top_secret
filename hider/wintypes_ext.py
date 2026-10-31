"""
Shared Win32 typed DLL declarations and constants.

Every function used elsewhere in the package is declared here with
argtypes and restype set — no untyped ctypes calls anywhere.
"""
from __future__ import annotations
import ctypes
import ctypes.wintypes as wt

# ── Scalar constants ───────────────────────────────────────────────────────────
INVALID_HANDLE_VALUE            = ctypes.c_void_p(-1).value   # one definition, used everywhere
INVALID_FILE_ATTRIBUTES: int    = 0xFFFFFFFF

GENERIC_READ                    = 0x80000000
GENERIC_WRITE                   = 0x40000000
DELETE                          = 0x00010000

FILE_SHARE_NONE                 = 0x00000000
FILE_SHARE_READ                 = 0x00000001
FILE_SHARE_WRITE                = 0x00000002
FILE_SHARE_DELETE               = 0x00000004
FILE_SHARE_ALL                  = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE

OPEN_EXISTING                   = 3
CREATE_ALWAYS                   = 2

FILE_FLAG_BACKUP_SEMANTICS      = 0x02000000   # required to open directories

FILE_ATTRIBUTE_READONLY                 = 0x00000001
FILE_ATTRIBUTE_HIDDEN                   = 0x00000002
FILE_ATTRIBUTE_SYSTEM                   = 0x00000004
FILE_ATTRIBUTE_DIRECTORY                = 0x00000010
FILE_ATTRIBUTE_REPARSE_POINT            = 0x00000400
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED      = 0x00002000
FILE_ATTRIBUTE_RECALL_ON_OPEN           = 0x00040000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS    = 0x00400000

TOKEN_QUERY                     = 0x00000008
TokenUser                       = 1             # TOKEN_INFORMATION_CLASS

CRYPTPROTECT_SENSITIVE          = 0x00000040    # keep plaintext in non-pageable memory

WAIT_OBJECT_0                   = 0x00000000
WAIT_TIMEOUT                    = 0x00000102

# ── kernel32 ──────────────────────────────────────────────────────────────────
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)

_k32.CreateFileW.argtypes = [
    wt.LPCWSTR,         # lpFileName
    wt.DWORD,           # dwDesiredAccess
    wt.DWORD,           # dwShareMode
    wt.LPVOID,          # lpSecurityAttributes
    wt.DWORD,           # dwCreationDisposition
    wt.DWORD,           # dwFlagsAndAttributes
    ctypes.c_void_p,    # hTemplateFile  (c_void_p, not wt.HANDLE — fix W5)
]
_k32.CreateFileW.restype = ctypes.c_void_p          # pointer-sized; not wt.HANDLE

_k32.CloseHandle.argtypes = [ctypes.c_void_p]
_k32.CloseHandle.restype  = wt.BOOL

_k32.GetFileAttributesW.argtypes = [wt.LPCWSTR]
_k32.GetFileAttributesW.restype  = wt.DWORD

_k32.SetFileAttributesW.argtypes = [wt.LPCWSTR, wt.DWORD]
_k32.SetFileAttributesW.restype  = wt.BOOL

_k32.GetCurrentProcess.argtypes = []
_k32.GetCurrentProcess.restype  = ctypes.c_void_p

_k32.LocalFree.argtypes = [ctypes.c_void_p]        # must cast pbData before calling
_k32.LocalFree.restype  = ctypes.c_void_p

_k32.CreateMutexW.argtypes = [wt.LPVOID, wt.BOOL, wt.LPCWSTR]
_k32.CreateMutexW.restype  = ctypes.c_void_p

_k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, wt.DWORD]
_k32.WaitForSingleObject.restype  = wt.DWORD

_k32.ReleaseMutex.argtypes = [ctypes.c_void_p]
_k32.ReleaseMutex.restype  = wt.BOOL

_k32.GetVolumeInformationW.argtypes = [
    wt.LPCWSTR,                     # lpRootPathName
    wt.LPWSTR,                      # lpVolumeNameBuffer
    wt.DWORD,                       # nVolumeNameSize
    ctypes.POINTER(wt.DWORD),       # lpVolumeSerialNumber
    ctypes.POINTER(wt.DWORD),       # lpMaximumComponentLength
    ctypes.POINTER(wt.DWORD),       # lpFileSystemFlags
    wt.LPWSTR,                      # lpFileSystemNameBuffer
    wt.DWORD,                       # nFileSystemNameSize
]
_k32.GetVolumeInformationW.restype = wt.BOOL

# ── advapi32 ──────────────────────────────────────────────────────────────────
_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

_advapi32.OpenProcessToken.argtypes = [
    ctypes.c_void_p,                    # ProcessHandle
    wt.DWORD,                           # DesiredAccess
    ctypes.POINTER(ctypes.c_void_p),    # TokenHandle (out)
]
_advapi32.OpenProcessToken.restype = wt.BOOL

_advapi32.GetTokenInformation.argtypes = [
    ctypes.c_void_p,                    # TokenHandle
    ctypes.c_int,                       # TokenInformationClass
    ctypes.c_void_p,                    # TokenInformation (out buffer)
    wt.DWORD,                           # TokenInformationLength
    ctypes.POINTER(wt.DWORD),           # ReturnLength (out)
]
_advapi32.GetTokenInformation.restype = wt.BOOL

_advapi32.ConvertSidToStringSidW.argtypes = [
    ctypes.c_void_p,                    # Sid
    ctypes.POINTER(wt.LPWSTR),          # StringSid (out, LocalAlloc'd)
]
_advapi32.ConvertSidToStringSidW.restype = wt.BOOL

# ── crypt32 ───────────────────────────────────────────────────────────────────
_crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


_crypt32.CryptProtectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),  # pDataIn
    wt.LPCWSTR,                 # szDataDescr
    ctypes.POINTER(DATA_BLOB),  # pOptionalEntropy
    wt.LPVOID,                  # pvReserved
    wt.LPVOID,                  # pPromptStruct
    wt.DWORD,                   # dwFlags
    ctypes.POINTER(DATA_BLOB),  # pDataOut
]
_crypt32.CryptProtectData.restype = wt.BOOL

_crypt32.CryptUnprotectData.argtypes = _crypt32.CryptProtectData.argtypes
_crypt32.CryptUnprotectData.restype  = wt.BOOL

# ── user32 ────────────────────────────────────────────────────────────────────
_user32 = ctypes.WinDLL("user32", use_last_error=True)

_user32.SendMessageTimeoutW.argtypes = [
    wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM, wt.UINT, wt.UINT,
    ctypes.POINTER(ctypes.c_ulong),
]
_user32.SendMessageTimeoutW.restype = ctypes.c_long

