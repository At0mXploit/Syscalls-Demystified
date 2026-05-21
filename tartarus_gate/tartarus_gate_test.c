// Tartarus Gate SSN resolution test
// Verifies syscall (0F 05) or int 2E (CD 2E) at +0x12 in addition to the
// standard prologue check -- catches partially hooked stubs
//
// Build:
//   x86_64-w64-mingw32-gcc tartarus_gate_test.c -o tartarus_gate_test.exe

#include <windows.h>
#include <stdio.h>

BOOLEAN GetSSNInternal( PBYTE NtFunction, PWORD SSN )
{
    DWORD Offset  = 0;
    BYTE  SSNLow  = 0;
    BYTE  SSNHigh = 0;
    PBYTE sc      = NULL;

    if ( !SSN )
        return FALSE;

    do {
        if ( *( NtFunction + Offset ) == 0xC3 )
            break;

        if ( *( NtFunction + Offset + 0 ) == 0x4C &&
             *( NtFunction + Offset + 1 ) == 0x8B &&
             *( NtFunction + Offset + 2 ) == 0xD1 &&
             *( NtFunction + Offset + 3 ) == 0xB8 )
        {
            sc = NtFunction + Offset + 0x12;
            if ( !( ( sc[ 0 ] == 0x0F && sc[ 1 ] == 0x05 ) ||
                    ( sc[ 0 ] == 0xCD && sc[ 1 ] == 0x2E ) ) )
                return FALSE;

            SSNLow  = *( NtFunction + Offset + 4 );
            SSNHigh = *( NtFunction + Offset + 5 );
            *SSN    = ( SSNHigh << 8 ) | SSNLow;
            return TRUE;
        }
        Offset++;
    } while ( TRUE );

    return FALSE;
}

DWORD GetFunctionSize( PVOID Function )
{
    PBYTE                   Module           = ( PBYTE ) GetModuleHandleA( "ntdll.dll" );
    PIMAGE_NT_HEADERS       NtHeader         = ( PIMAGE_NT_HEADERS )( Module + ( ( PIMAGE_DOS_HEADER ) Module )->e_lfanew );
    PIMAGE_EXPORT_DIRECTORY ExpDirectory     = ( PIMAGE_EXPORT_DIRECTORY )( Module + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    SIZE_T                  ExpDirectorySize = NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;
    PDWORD                  AddrOfFunctions  = ( PDWORD )( Module + ExpDirectory->AddressOfFunctions );
    PDWORD                  AddrOfNames      = ( PDWORD )( Module + ExpDirectory->AddressOfNames );
    PWORD                   AddrOfOrdinals   = ( PWORD  )( Module + ExpDirectory->AddressOfNameOrdinals );
    PVOID                   FunctionAddr     = NULL;
    PCHAR                   FunctionName     = NULL;
    PBYTE                   Addr1            = NULL;
    PBYTE                   Addr2            = NULL;
    DWORD                   SyscallSize      = 0;
    DWORD                   Offset           = 0;

    for ( DWORD i = 0; i < ExpDirectory->NumberOfNames; i++ )
    {
        if ( ( PBYTE ) FunctionAddr >= ( PBYTE ) ExpDirectory &&
             ( PBYTE ) FunctionAddr  < ( PBYTE ) ExpDirectory + ExpDirectorySize )
            continue;

        FunctionName = ( PCHAR ) Module + AddrOfNames[ i ];
        if ( *( PWORD ) FunctionName != 0x775a )
            continue;

        if ( !Addr1 ) {
            Addr1 = Module + AddrOfFunctions[ AddrOfOrdinals[ i ] ];
            continue;
        }

        Addr2  = Module + AddrOfFunctions[ AddrOfOrdinals[ i ] ];
        Offset = Addr1 > Addr2 ? Addr1 - Addr2 : Addr2 - Addr1;

        if ( !SyscallSize || Offset < SyscallSize )
            SyscallSize = Offset;
    }

    return SyscallSize;
}

WORD GetSSN( PBYTE NtFunction )
{
    WORD   SSN       = 0;
    DWORD  Counter   = 0;
    DWORD  SzNtApi   = 0;
    PVOID  Neighbour = NULL;

    if ( GetSSNInternal( NtFunction, &SSN ) )
        return SSN;

    SzNtApi = GetFunctionSize( NtFunction );

    while ( SSN == 0 && Counter < 200 ) {
        Neighbour = NtFunction + ( SzNtApi * Counter );
        if ( GetSSNInternal( Neighbour, &SSN ) ) { SSN -= Counter; break; }

        Neighbour = NtFunction - ( SzNtApi * Counter );
        if ( GetSSNInternal( Neighbour, &SSN ) ) { SSN += Counter; break; }

        Counter++;
    }

    return SSN;
}

void main()
{
    HMODULE ntdll = GetModuleHandleA( "ntdll.dll" );

    const char* funcs[] = {
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtQueueApcThread",
        "NtResumeThread",
    };

    printf( "[*] stub size: 0x%X bytes\n\n",
            GetFunctionSize( GetProcAddress( ntdll, "NtAllocateVirtualMemory" ) ) );

    for ( int i = 0; i < 5; i++ ) {
        PBYTE pFunc = ( PBYTE ) GetProcAddress( ntdll, funcs[ i ] );
        WORD  ssn   = GetSSN( pFunc );
        printf( "[+] %-32s @ %p  SSN = 0x%02X (%u)\n", funcs[ i ], pFunc, ssn, ssn );
    }
}
