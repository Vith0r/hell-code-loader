#include <Windows.h>
#include <stdio.h>
#include <ntstatus.h>
#include <string.h>
#include <stdlib.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <wchar.h>

extern NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

extern NTSTATUS NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten
);

extern NTSTATUS NtWaitForSingleObject(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);

extern NTSTATUS NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

extern NTSTATUS NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
extern NTSTATUS NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);

DWORD SSNtAllocateVirtualMemory;
UINT_PTR AddrNtAllocateVirtualMemory;
DWORD SSNtWriteVirtualMemory;
UINT_PTR AddrNtWriteVirtualMemory;
DWORD SSNtProtectVirtualMemory;
UINT_PTR AddrNtProtectVirtualMemory;
DWORD SSNtGetContextThread;
UINT_PTR AddrNtGetContextThread;
DWORD SSNtSetContextThread;
UINT_PTR AddrNtSetContextThread;