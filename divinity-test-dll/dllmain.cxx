#include <Windows.h>
#include <string>

namespace {
    constexpr wchar_t k_message[ ] = L"Hello from Divinity!\r\n";

    HWND find_notepad_edit( ) {
        HWND notepad = FindWindowW( L"Notepad", nullptr );
        if ( !notepad )
            notepad = FindWindowW( L"Notepad", L"Untitled - Notepad" );
        if ( !notepad )
            return nullptr;

        HWND edit = FindWindowExW( notepad, nullptr, L"Edit", nullptr );
        if ( edit )
            return edit;

        HWND rich = FindWindowExW( notepad, nullptr, L"RichEditD2DPT", nullptr );
        if ( rich )
            return rich;

        HWND child = nullptr;
        while ( ( child = FindWindowExW( notepad, child, nullptr, nullptr ) ) != nullptr ) {
            wchar_t class_name[ 64 ]{};
            if ( GetClassNameW( child, class_name, 64 ) &&
                ( wcsstr( class_name, L"Edit" ) || wcsstr( class_name, L"RichEdit" ) ) ) {
                return child;
            }

            HWND nested = FindWindowExW( child, nullptr, L"Edit", nullptr );
            if ( nested )
                return nested;

            nested = FindWindowExW( child, nullptr, L"RichEditD2DPT", nullptr );
            if ( nested )
                return nested;
        }

        return nullptr;
    }

    void type_into_notepad( ) {
        for ( auto attempt = 0; attempt < 50; ++attempt ) {
            HWND edit = find_notepad_edit( );
            if ( !edit ) {
                Sleep( 100 );
                continue;
            }

            SetForegroundWindow( GetAncestor( edit, GA_ROOT ) );
            SetFocus( edit );
            SendMessageW( edit, EM_SETSEL, static_cast< WPARAM >( -1 ), static_cast< LPARAM >( -1 ) );
            SendMessageW( edit, EM_REPLACESEL, TRUE, reinterpret_cast< LPARAM >( k_message ) );
            return;
        }
    }

    DWORD WINAPI worker( LPVOID ) {
        Sleep( 250 );
        type_into_notepad( );
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
