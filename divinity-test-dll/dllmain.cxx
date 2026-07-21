#include <Windows.h>
#include <cstdio>

namespace {
    DWORD WINAPI worker( LPVOID ) {
        wchar_t process_path[ MAX_PATH ]{};
        GetModuleFileNameW( nullptr, process_path, MAX_PATH );

        const wchar_t* process_name = process_path;
        for ( const wchar_t* cursor = process_path; *cursor; ++cursor ) {
            if ( *cursor == L'\\' || *cursor == L'/' )
                process_name = cursor + 1;
        }

        wchar_t message[ 512 ]{};
        swprintf_s(
            message,
            L"Divinity test DLL loaded.\n\nProcess: %s\nPID: %lu",
            process_name,
            GetCurrentProcessId( )
        );

        MessageBoxW( nullptr, message, L"divinity-test-dll", MB_OK | MB_ICONINFORMATION );
        return 0;
    }
}

extern "C" __declspec( dllexport ) BOOL APIENTRY DllMain(
    HMODULE module,
    DWORD reason,
    LPVOID
) {
    if ( reason == DLL_PROCESS_ATTACH ) {
        DisableThreadLibraryCalls( module );
        HANDLE thread = CreateThread( nullptr, 0, worker, nullptr, 0, nullptr );
        if ( thread )
            CloseHandle( thread );
    }

    return TRUE;
}
