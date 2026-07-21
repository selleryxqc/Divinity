#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <string>

namespace {
    DWORD find_process_id( const wchar_t* process_name ) {
        HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
        if ( snapshot == INVALID_HANDLE_VALUE )
            return 0;

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof( entry );

        DWORD process_id = 0;
        if ( Process32FirstW( snapshot, &entry ) ) {
            do {
                if ( _wcsicmp( entry.szExeFile, process_name ) == 0 ) {
                    process_id = entry.th32ProcessID;
                    break;
                }
            } while ( Process32NextW( snapshot, &entry ) );
        }

        CloseHandle( snapshot );
        return process_id;
    }

    std::wstring module_directory( ) {
        wchar_t path[ MAX_PATH ]{};
        GetModuleFileNameW( nullptr, path, MAX_PATH );
        std::wstring full( path );
        const auto slash = full.find_last_of( L"\\/" );
        if ( slash == std::wstring::npos )
            return L".\\";
        return full.substr( 0, slash + 1 );
    }

    bool inject_dll( DWORD process_id, const std::wstring& dll_path ) {
        HANDLE process = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            FALSE,
            process_id
        );
        if ( !process ) {
            std::printf( "OpenProcess failed (%lu)\n", GetLastError( ) );
            return false;
        }

        const auto bytes = ( dll_path.size( ) + 1 ) * sizeof( wchar_t );
        void* remote = VirtualAllocEx( process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
        if ( !remote ) {
            std::printf( "VirtualAllocEx failed (%lu)\n", GetLastError( ) );
            CloseHandle( process );
            return false;
        }

        if ( !WriteProcessMemory( process, remote, dll_path.c_str( ), bytes, nullptr ) ) {
            std::printf( "WriteProcessMemory failed (%lu)\n", GetLastError( ) );
            VirtualFreeEx( process, remote, 0, MEM_RELEASE );
            CloseHandle( process );
            return false;
        }

        auto load_library = reinterpret_cast< LPTHREAD_START_ROUTINE >(
            GetProcAddress( GetModuleHandleW( L"kernel32.dll" ), "LoadLibraryW" ) );
        if ( !load_library ) {
            std::printf( "GetProcAddress(LoadLibraryW) failed\n" );
            VirtualFreeEx( process, remote, 0, MEM_RELEASE );
            CloseHandle( process );
            return false;
        }

        HANDLE thread = CreateRemoteThread( process, nullptr, 0, load_library, remote, 0, nullptr );
        if ( !thread ) {
            std::printf( "CreateRemoteThread failed (%lu)\n", GetLastError( ) );
            VirtualFreeEx( process, remote, 0, MEM_RELEASE );
            CloseHandle( process );
            return false;
        }

        WaitForSingleObject( thread, 10000 );

        DWORD exit_code = 0;
        GetExitCodeThread( thread, &exit_code );
        CloseHandle( thread );
        VirtualFreeEx( process, remote, 0, MEM_RELEASE );
        CloseHandle( process );

        if ( !exit_code ) {
            std::printf( "LoadLibraryW returned NULL in the target process\n" );
            return false;
        }

        return true;
    }

    DWORD launch_notepad( ) {
        STARTUPINFOW startup{};
        startup.cb = sizeof( startup );
        PROCESS_INFORMATION info{};

        std::wstring command = L"notepad.exe";
        if ( !CreateProcessW(
            nullptr,
            command.data( ),
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            nullptr,
            &startup,
            &info ) ) {
            std::printf( "CreateProcess(notepad.exe) failed (%lu)\n", GetLastError( ) );
            return 0;
        }

        CloseHandle( info.hThread );
        const auto process_id = info.dwProcessId;
        CloseHandle( info.hProcess );

        for ( auto i = 0; i < 50; ++i ) {
            if ( FindWindowW( L"Notepad", nullptr ) )
                break;
            Sleep( 100 );
        }

        return process_id;
    }
}

int wmain( int argc, wchar_t** argv ) {
    SetConsoleTitleW( L"divinity-test-injector" );

    std::wstring dll_path;
    if ( argc >= 2 ) {
        dll_path = argv[ 1 ];
    }
    else {
        dll_path = module_directory( ) + L"divinity-test-dll.dll";
    }

    if ( GetFileAttributesW( dll_path.c_str( ) ) == INVALID_FILE_ATTRIBUTES ) {
        std::wprintf( L"DLL not found: %s\n", dll_path.c_str( ) );
        std::wprintf( L"Usage: divinity-test-injector.exe [path_to_dll]\n" );
        return 1;
    }

    wchar_t full_dll[ MAX_PATH ]{};
    if ( !GetFullPathNameW( dll_path.c_str( ), MAX_PATH, full_dll, nullptr ) ) {
        std::printf( "GetFullPathNameW failed (%lu)\n", GetLastError( ) );
        return 1;
    }
    dll_path = full_dll;

    auto process_id = find_process_id( L"notepad.exe" );
    if ( !process_id ) {
        std::printf( "Notepad not running, launching it...\n" );
        process_id = launch_notepad( );
        if ( !process_id )
            return 1;
    }

    std::printf( "Target PID: %lu\n", process_id );
    std::wprintf( L"Injecting: %s\n", dll_path.c_str( ) );

    if ( !inject_dll( process_id, dll_path ) ) {
        std::printf( "Injection failed\n" );
        return 1;
    }

    std::printf( "Injection succeeded. Notepad should type a message shortly.\n" );
    return 0;
}
