# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Windows handle inheritance functions.

Purpose: disable file/socket handle inheritance by child processes.

References:
- Sysinternals HOWTO:
  http://forum.sysinternals.com/howto-enumerate-handles_topic18892.html
- NtQuerySystemInformation and NtQueryObject APIs:
  https://msdn.microsoft.com/en-us/library/windows/desktop/ms724509%28v=vs.85%29.aspx
  https://msdn.microsoft.com/en-us/library/bb432383%28v=vs.85%29.aspx
- GetHandleInformation and SetHandleInformation APIs:
  https://msdn.microsoft.com/en-us/library/windows/desktop/ms724329%28v=vs.85%29.aspx
  https://msdn.microsoft.com/en-us/library/windows/desktop/ms724935%28v=vs.85%29.aspx
"""

import os
import cffi


# --------------------------------------------------------------------------
# FFI declarations

_ffi = cffi.FFI()
_ffi.cdef("""
/* https://msdn.microsoft.com/en-us/library/cc230357.aspx */

typedef long NTSTATUS;


/* winternl.h */

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
	/* NOTE: The next line is merged in from sysinternals */
	SystemHandleInformation = 16,
	/* Back to winternl.h */
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;


/* https://msdn.microsoft.com/en-us/library/windows/desktop/aa374892(v=vs.85).aspx */

typedef DWORD ACCESS_MASK;
typedef ACCESS_MASK* PACCESS_MASK;


/* from sysinternals */

typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount; /* Or NumberOfHandles if you prefer. */
    SYSTEM_HANDLE Handles [];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;


/* https://msdn.microsoft.com/en-us/library/windows/desktop/ms724509(v=vs.85).aspx */

NTSTATUS WINAPI NtQuerySystemInformation(
  /* _In_ */      SYSTEM_INFORMATION_CLASS SystemInformationClass,
  /* _Inout_ */   PVOID                    SystemInformation,
  /* _In_ */      ULONG                    SystemInformationLength,
  /* _Out_opt_ */ PULONG                   ReturnLength
);


/* winnt.h */

typedef void *HANDLE;


/* winternl.h */

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;

typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG Reserved [22];    // reserved for internal use
} PUBLIC_OBJECT_TYPE_INFORMATION, *PPUBLIC_OBJECT_TYPE_INFORMATION;


/* https://msdn.microsoft.com/en-us/library/bb432383(v=vs.85).aspx */

NTSTATUS NtQueryObject(
  /* _In_opt_ */  HANDLE                   Handle,
  /* _In_ */      OBJECT_INFORMATION_CLASS ObjectInformationClass,
  /* _Out_opt_ */ PVOID                    ObjectInformation,
  /* _In_ */      ULONG                    ObjectInformationLength,
  /* _Out_opt_ */ PULONG                   ReturnLength
);


/* https://msdn.microsoft.com/en-us/library/windows/desktop/ms724329(v=vs.85).aspx */

BOOL WINAPI GetHandleInformation(
  /* _In_ */  HANDLE  hObject,
  /* _Out_ */ LPDWORD lpdwFlags
);


/* https://msdn.microsoft.com/en-us/library/windows/desktop/ms724935(v=vs.85).aspx */

BOOL WINAPI SetHandleInformation(
  /* _In_ */ HANDLE hObject,
  /* _In_ */ DWORD  dwMask,
  /* _In_ */ DWORD  dwFlags
);
""")


ntdll = _ffi.dlopen('ntdll')
kernel32 = _ffi.dlopen('kernel32')


# --------------------------------------------------------------------------
# NtQuery* APIs return this to indicate the output buffer is too small.

STATUS_INFO_LENGTH_MISMATCH = 0xc0000004


# --------------------------------------------------------------------------
# Collecting system-wide SYSTEM_HANDLEs

def getSystemHandles(bufferSize=1000):

    """
    Yields all SYSTEM_HANDLES in the system.
    Based on the NtQuerySystemInformation internal Windows API.

    bufferSize sets the initial buffer size for collection.
    If it's too small, the function will try to allocate a larger buffer.
    """

    SystemInformationClass = 16     	# SystemHandleInformation @winternl.h

    while True:

        SystemInformation = _ffi.new('char[]', bufferSize);
        SystemInformationLength = bufferSize
        ReturnLength = _ffi.new('PULONG')
        status = ntdll.NtQuerySystemInformation(
            SystemInformationClass,
            SystemInformation,
            SystemInformationLength,
            ReturnLength,
        )

        status = int(_ffi.cast('ULONG', status))
        if status == STATUS_INFO_LENGTH_MISMATCH:
            neededSize = ReturnLength[0]
            bufferSize = neededSize
        elif status != 0:
            raise Exception('NtQuerySystemInformation status = %08x' % status)
        else:
            # Success
            break

    shi = _ffi.cast('SYSTEM_HANDLE_INFORMATION *', SystemInformation)
    for i in xrange(shi.HandleCount):
        yield shi.Handles[i]


# --------------------------------------------------------------------------
# Filter SYSTEM_HANDLEs by process id

def filterSystemHandlesByPID(systemHandles, pid):

    """
    Yields SYSTEM_HANDLES beloging to process identified by pid.
    """

    for systemHandle in systemHandles:
        if systemHandle.ProcessId == pid:
            yield systemHandle


# --------------------------------------------------------------------------
# Filter SYSTEM_HANDLEs by TypeName

def filterSystemHandlesByTypeName(systemHandles, typeName=u'File'):

    """
    Yields all SYSTEM_HANDLES where TypeName == typeName.
    typeName must be a unicode string and defaults to u'File'.
    Based on the NtQueryObject internal Windows API.
    """

    ObjectInformationClass = 2      	# ObjectTypeInformation @winternl.h
    ObjectInformation = _ffi.new('char[]', 1024)
    ObjectInformationLength = 1024

    for systemHandle in systemHandles:
        Handle = _ffi.cast('HANDLE', systemHandle.Handle)
        status = ntdll.NtQueryObject(
            Handle,
            ObjectInformationClass,
            ObjectInformation,
            ObjectInformationLength,
            _ffi.NULL,
        )
        status = int(_ffi.cast('ULONG', status))
        if status == STATUS_INFO_LENGTH_MISMATCH:
            raise Exception('need a larger buffer for NtQueryObject')
        elif status != 0:
            raise Exception('NtQueryObject status = %08x' % status)
        oi = _ffi.cast('PUBLIC_OBJECT_TYPE_INFORMATION *', ObjectInformation)
        if _ffi.string(oi.TypeName.Buffer) == typeName:
            yield systemHandle


# --------------------------------------------------------------------------
# Low level SYSTEM_HANDLEs to upper level HANDLEs

def handlesFromSystemHandles(systemHandles):

    for systemHandle in systemHandles:
        yield systemHandle.Handle


# --------------------------------------------------------------------------
# HANDLE inheritance getting/setting


HANDLE_FLAG_INHERIT = 0x00000001        # winbase.h


def isHandleInheritable(handle):

    """
    Returns True if the handle is inheritable, False otherwise.
    Based on the GetHandleInformation Windows API.
    """

    hObject = _ffi.cast('HANDLE', handle)
    lpdwFlags = _ffi.new('LPDWORD')

    status = kernel32.GetHandleInformation(
        hObject,
        lpdwFlags,
    )
    if status == 0:
        raise Exception('GetHandleInformation failed')
    return bool(lpdwFlags[0] & HANDLE_FLAG_INHERIT)


def clearHandleInheritance(handle):

    """
    Clears the handle inheritance flag.
    Based on the SetHandleInformation Windows API.
    """

    hObject = _ffi.cast('HANDLE', handle)
    status = kernel32.SetHandleInformation(
        hObject,
        HANDLE_FLAG_INHERIT,
        0,
    )
    if status == 0:
        raise Exception('SetHandleInformation failed')


def clearFileHandlesInheritance():

    """
    Clears the inheritance flag for all file handles in the process.
    Sockets included.
    """

    all = getSystemHandles()
    mine = filterSystemHandlesByPID(all, os.getpid())
    mineFiles = filterSystemHandlesByTypeName(mine)
    for handle in handlesFromSystemHandles(mineFiles):
        if isHandleInheritable(handle):
            clearHandleInheritance(handle)


# ----------------------------------------------------------------------------

