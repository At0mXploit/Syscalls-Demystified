.intel_syntax noprefix
.global CCStub

.text

CCStub:
    // entry rsp+0x00 = return address (gadget's ret uses this — do NOT push anything)
    // rcx = CC*, rdx = arg1, r8 = arg2, r9 = arg3
    // [rsp+0x28] = arg4, [rsp+0x30] = arg5, [rsp+0x38] = arg6 ...

    movzx   eax, word ptr [rcx]          // SSN -> eax
    mov     r11, qword ptr [rcx + 0x08]  // gadget -> r11

    // shift register args down one slot (drop CC* from rcx)
    mov     rcx, rdx
    mov     rdx, r8
    mov     r8,  r9

    // load arg4 into r9 before we clobber its slot
    mov     r9, qword ptr [rsp + 0x28]

    // slide stack args down one slot so kernel reads them from [rsp+0x28]+
    mov     r10, qword ptr [rsp + 0x30]
    mov     qword ptr [rsp + 0x28], r10   // arg5
    mov     r10, qword ptr [rsp + 0x38]
    mov     qword ptr [rsp + 0x30], r10   // arg6
    mov     r10, qword ptr [rsp + 0x40]
    mov     qword ptr [rsp + 0x38], r10   // arg7
    mov     r10, qword ptr [rsp + 0x48]
    mov     qword ptr [rsp + 0x40], r10   // arg8
    mov     r10, qword ptr [rsp + 0x50]
    mov     qword ptr [rsp + 0x48], r10   // arg9
    mov     r10, qword ptr [rsp + 0x58]
    mov     qword ptr [rsp + 0x50], r10   // arg10
    mov     r10, qword ptr [rsp + 0x60]
    mov     qword ptr [rsp + 0x58], r10   // arg11

    mov     r10, rcx   // syscall ABI: r10 = rcx
    jmp     r11        // syscall; ret -> ret pops [rsp+0x00] = our real return addr
