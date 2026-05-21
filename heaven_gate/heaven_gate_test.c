// Heaven's Gate test -- 32-bit process jumps to 64-bit mode via far jmp to CS 0x33
// WoW64 normally routes 32-bit syscalls through 4 hook layers before reaching the kernel.
// A far jmp to CS 0x33 switches the CPU to 64-bit mode mid-execution, letting us issue
// a 64-bit syscall directly and skip all WoW64 layers.
//
// Build (must be 32-bit):
//   i686-w64-mingw32-gcc heaven_gate_test.c -o heaven_gate_test.exe

#include <windows.h>
#include <stdio.h>

// NtAllocateVirtualMemory SSN -- verify on your build via x64dbg if it fails
#define SSN_ALLOC 0x18

void main()
{
    PVOID  base   = NULL;
    SIZE_T size   = 0x1000;
    HANDLE proc   = (HANDLE)(ULONG_PTR)-1;
    DWORD  status = 0;

    // 64-bit shellcode stub:
    //   mov r10, rcx
    //   mov eax, SSN
    //   syscall
    //   ret
    //   far jmp back to CS 0x23 (32-bit)
    // We embed raw 64-bit bytes and call them via far jmp to CS 0x33
    unsigned char stub[] = {
        // --- entered in 64-bit mode via far jmp from 32-bit code below ---
        0x4C, 0x8B, 0xD1,                               // mov r10, rcx
        0xB8, SSN_ALLOC, 0x00, 0x00, 0x00,              // mov eax, SSN
        0x0F, 0x05,                                     // syscall
        // far jmp back: retfq pops rip then cs -- we push 0x23 then ret addr
        0x48, 0xCB                                      // retfq (far return to 32-bit)
    };

    PVOID exec = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec) { printf("[-] VirtualAlloc failed\n"); return; }
    memcpy(exec, stub, sizeof(stub));

    printf("[*] Heaven's Gate test\n");
    printf("[*] 64-bit stub @ %p\n", exec);
    printf("[*] SSN = 0x%02X, switching to CS 0x33\n\n", SSN_ALLOC);

    // Far call into 64-bit stub via CS 0x33
    // We build a far pointer {offset, selector} on the stack and lcall it
    // Args to NtAllocateVirtualMemory pushed right-to-left on stack before the switch
    __asm__ volatile (
        // push NtAllocateVirtualMemory args right-to-left (32-bit stack)
        "push %[protect]    \n"  // Protect = PAGE_READWRITE
        "push %[alloc_type] \n"  // AllocationType = MEM_COMMIT|MEM_RESERVE
        "push %[sz_ptr]     \n"  // RegionSize ptr
        "push $0            \n"  // ZeroBits
        "push %[base_ptr]   \n"  // BaseAddress ptr
        "push %[proc]       \n"  // ProcessHandle

        // build far pointer: [eip, cs] on stack then retf
        "push $0x33         \n"  // CS selector for 64-bit mode
        "push %[fn]         \n"  // EIP = stub address
        "retf               \n"  // switch to 64-bit, execute stub

        // stub does retfq back here with status in eax
        "mov  %%eax, %[res] \n"
        "add  $24, %%esp    \n"  // clean up the 6 args we pushed
        : [res] "=m" (status)
        : [fn]       "r" ((DWORD)(ULONG_PTR)exec),
          [proc]     "r" ((DWORD)(ULONG_PTR)proc),
          [base_ptr] "r" ((DWORD)(ULONG_PTR)&base),
          [sz_ptr]   "r" ((DWORD)(ULONG_PTR)&size),
          [alloc_type] "i" (MEM_COMMIT | MEM_RESERVE),
          [protect]    "i" (PAGE_READWRITE)
        : "eax", "memory"
    );

    if (status == 0)
        printf("[+] NtAllocateVirtualMemory OK: base=%p size=0x%zX\n", base, size);
    else
        printf("[-] NtAllocateVirtualMemory failed: NTSTATUS=0x%08X\n", status);

    VirtualFree(exec, 0, MEM_RELEASE);
}
