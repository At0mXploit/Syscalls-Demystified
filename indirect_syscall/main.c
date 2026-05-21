// Indirect syscall test -- allocates memory in current process
// SSN: hardcoded, gadget address resolved at runtime from ntdll+0x12
//
// Build:
//   x86_64-w64-mingw32-gcc syscalls.S main.c -o indirect_syscall.exe

#include <windows.h>
#include <stdio.h>

typedef LONG NTSTATUS;

extern ULONG_PTR g_NtAllocAddr;

extern NTSTATUS SysNtAllocateVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID*    BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

int main(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) { printf("[-] Failed to get ntdll handle\n"); return 1; }

    ULONG_PTR pNtAlloc = (ULONG_PTR)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    if (!pNtAlloc) { printf("[-] Failed to resolve NtAllocateVirtualMemory\n"); return 1; }

    // +0x12 = offset of syscall instruction in every Nt* stub on Win10/11 x64
    g_NtAllocAddr = pNtAlloc + 0x12;

    printf("[*] NtAllocateVirtualMemory  @ %p\n", (void*)pNtAlloc);
    printf("[*] syscall gadget (+0x12)   @ %p\n", (void*)g_NtAllocAddr);

    PVOID  buffer = NULL;
    SIZE_T size   = 0x1000;

    printf("[*] Calling SysNtAllocateVirtualMemory (indirect)...\n");

    NTSTATUS status = SysNtAllocateVirtualMemory(
        (HANDLE)-1,
        &buffer,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (status == 0)
        printf("[+] Allocated %zu bytes at %p\n", size, buffer);
    else
        printf("[-] Syscall failed: 0x%lX\n", status);

    return 0;
}
