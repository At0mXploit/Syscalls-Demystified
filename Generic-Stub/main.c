#include <stdio.h>
#include "syscall_gate.h"

int main(void) {
    CC cc_alloc = {0};

    // resolve SSN + gadget for NtAllocateVirtualMemory
    if (!ResolveCC("NtAllocateVirtualMemory", &cc_alloc)) {
        printf("[-] failed to resolve NtAllocateVirtualMemory\n");
        return 1;
    }
    printf("[+] SSN    = 0x%04X\n", cc_alloc.ssn);
    printf("[+] gadget = %p\n",     cc_alloc.gad);

    // NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits,
    //                         RegionSize, AllocationType, Protect)
    PVOID  base = NULL;
    SIZE_T size = 0x1000;

    NTSTATUS status = CCStub(
        &cc_alloc,
        (ULONG_PTR)-1,                        // arg1:  ProcessHandle (-1 = current)
        (ULONG_PTR)&base,                     // arg2:  BaseAddress
        (ULONG_PTR)0,                         // arg3:  ZeroBits
        (ULONG_PTR)&size,                     // arg4:  RegionSize
        (ULONG_PTR)(MEM_COMMIT|MEM_RESERVE),  // arg5:  AllocationType
        (ULONG_PTR)PAGE_READWRITE,            // arg6:  Protect
        0, 0, 0, 0, 0                         // arg7-11: unused padding
    );

    if (status == 0) {
        printf("[+] allocated at %p\n", base);
    } else {
        printf("[-] NtAllocateVirtualMemory failed: 0x%08X\n", (DWORD)status);
    }

    return 0;
}
