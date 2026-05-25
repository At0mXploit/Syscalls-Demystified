#pragma once
#include <windows.h>

// CC struct: SSN at offset 0x00, gadget pointer at offset 0x08
// pad[6] aligns gad to 8 bytes
typedef struct {
    WORD  ssn;
    BYTE  pad[6];
    PVOID gad;
} CC;

BOOL ResolveCC(const char* funcName, CC* out);

extern NTSTATUS CCStub(
    CC*       cc,
    ULONG_PTR arg1,  ULONG_PTR arg2,  ULONG_PTR arg3,
    ULONG_PTR arg4,  ULONG_PTR arg5,  ULONG_PTR arg6,
    ULONG_PTR arg7,  ULONG_PTR arg8,  ULONG_PTR arg9,
    ULONG_PTR arg10, ULONG_PTR arg11
);
