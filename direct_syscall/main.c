#include <windows.h>
#include <stdio.h>

typedef LONG NTSTATUS;

extern NTSTATUS SysNtAllocateVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID*    BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

int main(void) {
    PVOID  buffer = NULL;
    SIZE_T size   = 0x1000;

    printf("[*] Calling SysNtAllocateVirtualMemory directly...\n");

    NTSTATUS status = SysNtAllocateVirtualMemory(
        (HANDLE)-1,                     // current process pseudo-handle
        &buffer,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (status == 0) {
        printf("[+] Allocated %zu bytes at %p\n", size, buffer);
        getchar();
    } else {
        printf("[-] Syscall failed: 0x%lX\n", status);
    }
    return 0;
}
