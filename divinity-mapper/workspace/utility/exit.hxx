#pragma once

namespace handler {
    bool control_handler( std::uint32_t signal ) {
        char message[ 512 ];
        sprintf( message,
            oxorany( "Are you sure you want to close?\n\n"
                "The application is currently running.\n"
                "Closing it will terminate all active processes.\n\n"
                "Click 'Yes' to close the application\n"
                "Click 'No' to keep it running" )
        );

        int result = MessageBoxA( nullptr, message, oxorany( "exit::crash_handler - Confirm Exit" ), MB_YESNO | MB_ICONQUESTION | MB_TOPMOST );
        if ( result == IDYES ) {
            logging::print( oxorany( "exit::control_handler: User confirmed exit - signal: %u" ), signal );
            return false;
        }

        logging::print( oxorany( "exit::control_handler: Exit cancelled by user - signal: %u" ), signal );
        return true;
    }

    long crash_handler( EXCEPTION_POINTERS* exception_pointers ) {
        const auto* context = exception_pointers->ContextRecord;
        char message[ 1024 ];
        sprintf( message,
            oxorany( "Oops! Something went wrong!\n\n"
                "The service encountered an unexpected error and needs to close.\n\n"
                "Quick fixes to try:\n"
                "  • Restart the service\n"
                "  • Rollback recent updates to the service\n"
                "  • Check if your antivirus is interfering\n\n"
                "Still having trouble? We're here to help!\n"
                "Contact support through the tickets section.\n\n"
                "Crash Details:\n"
                "Build: %s %s\n"
                "Error: 0x%08X at %p\n"
                "Registers: RSP=%016llX RDI=%016llX\n"
                "           RSI=%016llX RBX=%016llX\n"
                "           RDX=%016llX RCX=%016llX\n"
                "           RAX=%016llX RBP=%016llX" ),
            __DATE__, __TIME__,
            exception_pointers->ExceptionRecord->ExceptionCode,
            exception_pointers->ExceptionRecord->ExceptionAddress,
            context->Rsp, context->Rdi,
            context->Rsi, context->Rbx,
            context->Rdx, context->Rcx,
            context->Rax, context->Rbp
        );

        g_service->unload( );
        g_driver->unload( );

        printf( oxorany( "\n" ) );
        logging::print( oxorany( "exit::crash_handler: Caught exception" ) );
        MessageBoxA( 0, message, "exit::crash_handler - Unexpected Error", MB_ICONERROR | MB_OK );
        return true;
    }
}