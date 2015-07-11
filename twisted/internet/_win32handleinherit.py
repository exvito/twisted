#!/usr/bin/env python
# ----------------------------------------------------------------------------
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
# ----------------------------------------------------------------------------

import os

import ctypes
from ctypes import wintypes


# --------------------------------------------------------------------------
# We needed these libraries

ntdll = ctypes.windll.ntdll
kernel32 = ctypes.windll.kernel32


# --------------------------------------------------------------------------
# A useful constant

STATUS_INFO_LENGTH_MISMATCH = 0xc0000004


# --------------------------------------------------------------------------
# Collect system-wide SYSTEM_HANDLEs

class SYSTEM_HANDLE(ctypes.Structure):

    _fields_ = [
        ("ProcessId", wintypes.ULONG),
        ("ObjectTypeNumber", wintypes.BYTE),
        ("Flags", wintypes.BYTE),
        ("Handle", wintypes.USHORT),
        ("Object", ctypes.c_void_p),
        ("GrantedAccess", wintypes.DWORD),
    ]


def _getSystemHandles(numHandles=1000):


    """
    Yields all SYSTEM_HANDLES in the system.
    Based on the NtQuerySystemInformation internal Windows API.

    numHandles sets the initial buffer size for collection.
    If it's too small, the function will try to allocate a larger buffer.
    """

    ntdll.NtQuerySystemInformation.restype = ctypes.c_ulong;
    SystemHandleInformation = wintypes.ULONG(0x10)  # Enum in Winternl.h

    while True:

        class SYSTEM_HANDLE_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("HandleCount", wintypes.ULONG),
                ("Handles", SYSTEM_HANDLE * numHandles),
            ]

        SystemInformation = SYSTEM_HANDLE_INFORMATION()
        ReturnLength = ctypes.c_ulong()
        status = ntdll.NtQuerySystemInformation(
            SystemHandleInformation,
            ctypes.byref(SystemInformation),
            ctypes.sizeof(SystemInformation),
            ctypes.byref(ReturnLength),
        )

        if status == STATUS_INFO_LENGTH_MISMATCH:
            # Buffer was short, calculate numHandles from ReturnLength
            currentSize = ctypes.sizeof(SystemInformation)
            neededSize = ReturnLength.value
            systemHandleSize = ctypes.sizeof(SYSTEM_HANDLE)
            numHandles += (neededSize - currentSize) // systemHandleSize
        elif status != 0:
            # Not good
            raise Exception('NtQuerySystemInformation status = %08x' % status)
        else:
            # Success
            break

    count = SystemInformation.HandleCount
    for systemHandle in SystemInformation.Handles:
        yield systemHandle
        count -= 1
        if count == 0:
            break


# --------------------------------------------------------------------------
# Filter SYSTEM_HANDLEs by process id

def _filterSystemHandlesByPID(systemHandles, pid):

    """
    Yields SYSTEM_HANDLES beloging to process identified by pid.
    """

    for systemHandle in systemHandles:
        if systemHandle.ProcessId == pid:
            yield systemHandle


# --------------------------------------------------------------------------
# Filter SYSTEM_HANDLEs by TypeName

class UNICODE_STRING(ctypes.Structure):

    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
        ("_buff", ctypes.c_char * 256),         # Buffer to hold the string
    ]


class PUBLIC_OBJECT_TYPE_INFORMATION(ctypes.Structure):

    _fields_ = [
        ("TypeName", UNICODE_STRING),
        ("Reserved", wintypes.ULONG * 22),
    ]


def _filterSystemHandlesByTypeName(systemHandles, typeName=u'File'):

    """
    Yields all SYSTEM_HANDLES with TypeName == typeName.
    typeName must be a unicode string and defaults to u'File'.
    Based on the NtQueryObject internal Windows API.
    """

    ntdll.NtQueryObject.restype = ctypes.c_ulong;
    ObjectTypeInformation = wintypes.ULONG(2)       # Enum in Winternl.h

    ObjectInformation = PUBLIC_OBJECT_TYPE_INFORMATION()
    for systemHandle in systemHandles:
        status = ntdll.NtQueryObject(
            systemHandle.Handle,
            ObjectTypeInformation,
            ctypes.byref(ObjectInformation),
            ctypes.sizeof(ObjectInformation),
            None,
        )
        if status == STATUS_INFO_LENGTH_MISMATCH:
            raise Exception('need a larger buffer for NtQueryObject')
        elif status != 0:
            raise Exception('NtQueryObject status = %08x' % status)
        if ObjectInformation.TypeName.Buffer == typeName:
            yield systemHandle


# --------------------------------------------------------------------------
# Low level SYSTEM_HANDLEs to upper level HANDLEs

def _handlesFromSystemHandles(systemHandles):

    for systemHandle in systemHandles:
        yield systemHandle.Handle


# --------------------------------------------------------------------------
# HANDLE inheritance getting/setting


HANDLE_FLAG_INHERIT = 0x00000001


def _isHandleInheritable(handle):

    """
    Returns True if the handle is inheritable, False otherwise.
    Based on the GetHandleInformation Windows API.
    """

    kernel32.GetHandleInformation.restype = wintypes.BOOLEAN

    HandleInfoFlags = wintypes.DWORD()

    status = kernel32.GetHandleInformation(
        handle,
        ctypes.byref(HandleInfoFlags),
    )
    if status == 0:
        raise Exception('GetHandleInformation failed')
    return bool(HandleInfoFlags.value & HANDLE_FLAG_INHERIT)


def _clearHandleInheritance(handle):

    """
    Clears our the handle inheritance flag.
    Based on the SetHandleInformation Windows API.
    """

    kernel32.SetHandleInformation.restype = wintypes.BOOLEAN
    status = kernel32.SetHandleInformation(
        handle,
        HANDLE_FLAG_INHERIT,
        0,
    )


def clearFileHandlesInheritance():

    """
    Clears the inheritance flag for all file handles in the process.
    Sockets included.
    """

    all = _getSystemHandles()
    mine = _filterSystemHandlesByPID(all, os.getpid())
    mineFiles = _filterSystemHandlesByTypeName(mine)
    for handle in _handlesFromSystemHandles(mineFiles):
        if _isHandleInheritable(handle):
            _clearHandleInheritance(handle)


# ----------------------------------------------------------------------------

