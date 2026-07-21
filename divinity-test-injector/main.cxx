#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>

namespace {
    struct process_info_t {
        DWORD m_pid{};
        std::wstring m_name;
    };

    std::wstring trim_quotes( std::wstring value ) {
        while ( !value.empty( ) && ( value.front( ) == L'"' || value.front( ) == L'\'' ) )
            value.erase( value.begin( ) );
        while ( !value.empty( ) && ( value.back( ) == L'"' || value.back( ) == L'\'' ) )
            value.pop_back( );
        while ( !value.empty( ) && iswspace( value.front( ) ) )
            value.erase( value.begin( ) );
        while ( !value.empty( ) && iswspace( value.back( ) ) )
            value.pop_back( );
        return value;
    }

    std::wstring to_lower( std::wstring value ) {
        std::transform( value.begin( ), value.end( ), value.begin( ), ::towlower );
        return value;
    }

    bool ends_with_ignore_case( const std::wstring& value, const wchar_t* suffix ) {
        const auto suffix_len = wcslen( suffix );
        if ( value.size( ) < suffix_len )
            return false;
        return _wcsicmp( value.c_str( ) + value.size( ) - suffix_len, suffix ) == 0;
    }

    std::wstring resolve_full_path( const std::wstring& path ) {
        wchar_t full[ MAX_PATH ]{};
        if ( !GetFullPathNameW( path.c_str( ), MAX_PATH, full, nullptr ) )
            return {};
        return full;
    }

    bool file_exists( const std::wstring& path ) {
        return GetFileAttributesW( path.c_str( ) ) != INVALID_FILE_ATTRIBUTES;
    }

    bool is_dll_path( const std::wstring& path ) {
        return ends_with_ignore_case( path, L".dll" ) && file_exists( path );
    }

    std::vector<process_info_t> enumerate_processes( const std::wstring& filter ) {
        std::vector<process_info_t> processes;

        HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
        if ( snapshot == INVALID_HANDLE_VALUE )
            return processes;

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof( entry );

        const auto filter_lower = to_lower( filter );
        if ( Process32FirstW( snapshot, &entry ) ) {
            do {
                if ( entry.th32ProcessID == 0 )
                    continue;

                process_info_t info{};
                info.m_pid = entry.th32ProcessID;
                info.m_name = entry.szExeFile;

                if ( !filter_lower.empty( ) ) {
                    auto name_lower = to_lower( info.m_name );
                    auto pid_text = std::to_wstring( info.m_pid );
                    if ( name_lower.find( filter_lower ) == std::wstring::npos &&
                        pid_text.find( filter_lower ) == std::wstring::npos ) {
                        continue;
                    }
                }

                processes.push_back( std::move( info ) );
            } while ( Process32NextW( snapshot, &entry ) );
        }

        CloseHandle( snapshot );

        std::sort( processes.begin( ), processes.end( ),
            [ ]( const process_info_t& a, const process_info_t& b ) {
                const auto name_cmp = _wcsicmp( a.m_name.c_str( ), b.m_name.c_str( ) );
                if ( name_cmp != 0 )
                    return name_cmp < 0;
                return a.m_pid < b.m_pid;
            } );

        return processes;
    }

    void print_processes( const std::vector<process_info_t>& processes ) {
        std::wprintf( L"\n  %-5s %-8s %s\n", L"#", L"PID", L"Process" );
        std::wprintf( L"  ----- -------- ------------------------------\n" );

        for ( std::size_t i = 0; i < processes.size( ); ++i ) {
            std::wprintf( L"  %-5zu %-8lu %s\n",
                i + 1,
                processes[ i ].m_pid,
                processes[ i ].m_name.c_str( ) );
        }

        std::wprintf( L"\n  %zu process(es)\n", processes.size( ) );
    }

    DWORD find_process_id_by_name( const std::wstring& process_name ) {
        auto processes = enumerate_processes( process_name );
        for ( const auto& process : processes ) {
            if ( _wcsicmp( process.m_name.c_str( ), process_name.c_str( ) ) == 0 )
                return process.m_pid;
        }
        return 0;
    }

    std::wstring prompt_line( const wchar_t* label ) {
        std::wprintf( L"%s", label );
        std::wstring line;
        std::getline( std::wcin, line );
        return trim_quotes( line );
    }

    std::wstring prompt_dll_path( const std::wstring& initial ) {
        if ( !initial.empty( ) ) {
            auto resolved = resolve_full_path( trim_quotes( initial ) );
            if ( is_dll_path( resolved ) )
                return resolved;
            std::wprintf( L"Invalid DLL from arguments: %s\n", initial.c_str( ) );
        }

        while ( true ) {
            std::wprintf( L"\nDrag a .dll onto this exe, or paste the full DLL path below.\n" );
            auto input = prompt_line( L"DLL path > " );
            if ( input.empty( ) )
                continue;

            auto resolved = resolve_full_path( input );
            if ( !is_dll_path( resolved ) ) {
                std::wprintf( L"Not a valid .dll file: %s\n", input.c_str( ) );
                continue;
            }

            return resolved;
        }
    }

    DWORD prompt_process_id( const std::wstring& initial_target ) {
        if ( !initial_target.empty( ) ) {
            if ( std::all_of( initial_target.begin( ), initial_target.end( ), ::iswdigit ) ) {
                const auto pid = static_cast< DWORD >( std::wcstoul( initial_target.c_str( ), nullptr, 10 ) );
                if ( pid )
                    return pid;
            }

            auto pid = find_process_id_by_name( initial_target );
            if ( pid )
                return pid;

            std::wprintf( L"Could not find process from arguments: %s\n", initial_target.c_str( ) );
        }

        std::wstring filter;
        while ( true ) {
            auto processes = enumerate_processes( filter );
            print_processes( processes );

            std::wprintf( L"\nCommands:\n" );
            std::wprintf( L"  <number>     select from list\n" );
            std::wprintf( L"  <pid>        select by PID\n" );
            std::wprintf( L"  f <text>     filter by name/PID\n" );
            std::wprintf( L"  r            refresh list\n" );
            std::wprintf( L"  q            quit\n" );

            auto input = prompt_line( L"\nSelect process > " );
            if ( input.empty( ) )
                continue;

            if ( _wcsicmp( input.c_str( ), L"q" ) == 0 )
                return 0;

            if ( _wcsicmp( input.c_str( ), L"r" ) == 0 )
                continue;

            if ( input.size( ) >= 2 && ( input[ 0 ] == L'f' || input[ 0 ] == L'F' ) && iswspace( input[ 1 ] ) ) {
                filter = trim_quotes( input.substr( 2 ) );
                continue;
            }

            if ( input.size( ) >= 2 && _wcsnicmp( input.c_str( ), L"f:", 2 ) == 0 ) {
                filter = trim_quotes( input.substr( 2 ) );
                continue;
            }

            if ( std::all_of( input.begin( ), input.end( ), ::iswdigit ) ) {
                const auto value = static_cast< DWORD >( std::wcstoul( input.c_str( ), nullptr, 10 ) );
                if ( !value )
                    continue;

                if ( value <= processes.size( ) )
                    return processes[ value - 1 ].m_pid;

                for ( const auto& process : processes ) {
                    if ( process.m_pid == value )
                        return value;
                }

                HANDLE process = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, value );
                if ( process ) {
                    CloseHandle( process );
                    return value;
                }

                std::wprintf( L"No process matched '%s'\n", input.c_str( ) );
                continue;
            }

            auto pid = find_process_id_by_name( input );
            if ( pid )
                return pid;

            std::wprintf( L"No process matched '%s'\n", input.c_str( ) );
        }
    }

    bool inject_dll( DWORD process_id, const std::wstring& dll_path ) {
        HANDLE process = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            FALSE,
            process_id
        );
        if ( !process ) {
            std::wprintf( L"OpenProcess failed (%lu). Try running as Administrator.\n", GetLastError( ) );
            return false;
        }

        const auto bytes = ( dll_path.size( ) + 1 ) * sizeof( wchar_t );
        void* remote = VirtualAllocEx( process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
        if ( !remote ) {
            std::wprintf( L"VirtualAllocEx failed (%lu)\n", GetLastError( ) );
            CloseHandle( process );
            return false;
        }

        if ( !WriteProcessMemory( process, remote, dll_path.c_str( ), bytes, nullptr ) ) {
            std::wprintf( L"WriteProcessMemory failed (%lu)\n", GetLastError( ) );
            VirtualFreeEx( process, remote, 0, MEM_RELEASE );
            CloseHandle( process );
            return false;
        }

        auto load_library = reinterpret_cast< LPTHREAD_START_ROUTINE >(
            GetProcAddress( GetModuleHandleW( L"kernel32.dll" ), "LoadLibraryW" ) );
        if ( !load_library ) {
            std::wprintf( L"GetProcAddress(LoadLibraryW) failed\n" );
            VirtualFreeEx( process, remote, 0, MEM_RELEASE );
            CloseHandle( process );
            return false;
        }

        HANDLE thread = CreateRemoteThread( process, nullptr, 0, load_library, remote, 0, nullptr );
        if ( !thread ) {
            std::wprintf( L"CreateRemoteThread failed (%lu)\n", GetLastError( ) );
            VirtualFreeEx( process, remote, 0, MEM_RELEASE );
            CloseHandle( process );
            return false;
        }

        WaitForSingleObject( thread, 15000 );

        DWORD exit_code = 0;
        GetExitCodeThread( thread, &exit_code );
        CloseHandle( thread );
        VirtualFreeEx( process, remote, 0, MEM_RELEASE );
        CloseHandle( process );

        if ( !exit_code ) {
            std::wprintf( L"LoadLibraryW returned NULL in the target (wrong arch or missing deps?)\n" );
            return false;
        }

        return true;
    }

    std::wstring process_name_for_pid( DWORD process_id ) {
        auto processes = enumerate_processes( L"" );
        for ( const auto& process : processes ) {
            if ( process.m_pid == process_id )
                return process.m_name;
        }
        return L"<unknown>";
    }
}

int wmain( int argc, wchar_t** argv ) {
    SetConsoleTitleW( L"divinity-test-injector" );

    std::wprintf( L"====================================\n" );
    std::wprintf( L"  Divinity Test Injector\n" );
    std::wprintf( L"====================================\n" );
    std::wprintf( L"Usage:\n" );
    std::wprintf( L"  1) Drag a .dll onto this .exe\n" );
    std::wprintf( L"  2) Or run: divinity-test-injector.exe <dll> [pid|process.exe]\n" );
    std::wprintf( L"  3) Then pick a target process from the list\n" );

    std::wstring dll_arg;
    std::wstring process_arg;
    if ( argc >= 2 )
        dll_arg = argv[ 1 ];
    if ( argc >= 3 )
        process_arg = argv[ 2 ];

    const auto dll_path = prompt_dll_path( dll_arg );
    std::wprintf( L"\nDLL: %s\n", dll_path.c_str( ) );

    const auto process_id = prompt_process_id( process_arg );
    if ( !process_id ) {
        std::wprintf( L"Cancelled.\n" );
        return 1;
    }

    const auto target_name = process_name_for_pid( process_id );
    std::wprintf( L"\nTarget: %s (PID %lu)\n", target_name.c_str( ), process_id );
    std::wprintf( L"Injecting...\n" );

    if ( !inject_dll( process_id, dll_path ) ) {
        std::wprintf( L"Injection failed.\n" );
        std::wprintf( L"Press Enter to exit..." );
        std::wstring unused;
        std::getline( std::wcin, unused );
        return 1;
    }

    std::wprintf( L"Injection succeeded.\n" );
    std::wprintf( L"Press Enter to exit..." );
    std::wstring unused;
    std::getline( std::wcin, unused );
    return 0;
}
