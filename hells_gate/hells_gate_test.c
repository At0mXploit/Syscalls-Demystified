// Simple Hell's Gate demo
// Walks PEB -> ntdll -> EAT -> reads SSN from stub bytes at runtime
// No hardcoded SSNs, no GetProcAddress, no lookup tables
//
// Build:
//   x86_64-w64-mingw32-gcc hells_gate_test.c -o hells_gate_test.exe

#include <windows.h>
#include <stdio.h>

#define SSN_NOT_FOUND 0xFFFFFFFF

// Walk PEB->Ldr->InMemoryOrderModuleList to get ntdll base without any API call.
// ntdll is always the second entry in the list (exe is first).
static PVOID get_ntdll_base(void) {
    ULONG_PTR peb, ldr, flink;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));
    ldr   = *(ULONG_PTR*)(peb  + 0x18);  // PEB->Ldr
    flink = *(ULONG_PTR*)(ldr  + 0x20);  // Ldr->InMemoryOrderModuleList.Flink (exe)
    flink = *(ULONG_PTR*)(flink);         // exe->Flink -> ntdll InMemoryOrderLinks
    return (PVOID)*(ULONG_PTR*)(flink + 0x20); // +0x20 from InMemoryOrderLinks = DllBase
}

// Walk a module's Export Address Table to find a function by name.
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

// Read SSN from an unhooked ntdll stub.
// Clean stub layout:
//   +0x00  4C 8B D1        mov r10, rcx
//   +0x03  B8 XX XX XX XX  mov eax, <SSN>
// If hooked, +0x00 is E9 (jmp) and we return SSN_NOT_FOUND.
static DWORD get_ssn(PVOID func) {
    ULONG_PTR p = (ULONG_PTR)func;
    if (*(BYTE*)(p+0) == 0x4C &&
        *(BYTE*)(p+1) == 0x8B &&
        *(BYTE*)(p+2) == 0xD1 &&
        *(BYTE*)(p+3) == 0xB8)
        return *(DWORD*)(p + 0x04);
    return SSN_NOT_FOUND;
}

int main(void) {
    PVOID ntdll = get_ntdll_base();
    printf("[+] ntdll base: %p\n\n", ntdll);

    const char *targets[] = {
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtQueueApcThread",
        "NtResumeThread",
    };

    for (int i = 0; i < 5; i++) {
        PVOID func = get_func_addr(ntdll, targets[i]);
        if (!func) {
            printf("[-] %-32s not found\n", targets[i]);
            continue;
        }

        DWORD ssn = get_ssn(func);
        if (ssn == SSN_NOT_FOUND)
            printf("[-] %-32s @ %p  HOOKED\n", targets[i], func);
        else
            printf("[+] %-32s @ %p  SSN = 0x%02X (%u)\n", targets[i], func, ssn, ssn);
    }

    return 0;
}
