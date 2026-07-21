#include <impl/includes.h>

int main( int argc, char** argv ) {
	VirtualAlloc(
		reinterpret_cast< void* >( 0x7f8000000000ULL ),
		0x8000000000ULL,
		MEM_RESERVE,
		PAGE_NOACCESS
	);

	SetConsoleTitleA( oxorany( "divinity-fortnite" ) );
	SetUnhandledExceptionFilter( crash::crash_handler );

	auto std_handle = GetStdHandle( STD_OUTPUT_HANDLE );
	DWORD mode;
	GetConsoleMode( std_handle, &mode );
	mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	SetConsoleMode( std_handle, mode );

	CONSOLE_FONT_INFOEX cfi{ };
	cfi.cbSize = sizeof( cfi );
	cfi.nFont = 0;
	cfi.dwFontSize.X = 8;
	cfi.dwFontSize.Y = 15;
	cfi.FontFamily = FF_DONTCARE;
	cfi.FontWeight = FW_NORMAL;
	wcscpy_s( cfi.FaceName, oxorany( L"Raster Fonts" ) );
	SetCurrentConsoleFontEx( GetStdHandle( STD_OUTPUT_HANDLE ), FALSE, &cfi );

	if ( argc < 2 ) {
		logging::print( oxorany( "No DLL path provided." ) );
		logging::print( oxorany( "Usage: %s <path_to_dll>" ), argv[ 0 ] );
		return std::getchar( );
	}

	if ( !g_driver->create( ) ) {
		logging::print( oxorany( "Could not create communication" ) );
		return std::getchar( );
	}

	if ( !g_driver->initialize( ) ) {
		logging::print( oxorany( "Could not initialize communication." ) );
		return std::getchar( );
	}

	if ( !g_driver->is_active( ) ) {
		logging::print( oxorany( "Could not verify driver status." ) );
		return std::getchar( );
	}

	logging::print( oxorany( "Successfully initialized communication" ) );

	if ( !g_driver->attach_process( oxorany( process_name ) ) ) {
		logging::print( oxorany( "Could not attach to process." ) );
		return std::getchar( );
	}

	logging::print( oxorany( "Cloning virtual address space, please wait.." ) );

	if ( !g_portal->clone_process( g_driver->m_eprocess ) ) {
		logging::print( oxorany( "Could not portal to process." ) );
		return std::getchar( );
	}

	//if ( !g_portal->expose_memory( g_driver->m_base_address ) ) {
	//	logging::print( oxorany( "Could not expose memory. Restart the process and try again." ) );
	//	return std::getchar( );
	//}

	logging::print( oxorany( "Successfully attached to process\n" ) );

	auto dependency = std::make_shared< dependency::c_dependency >( argv[ 1 ] );
	if ( !dependency->is_dll( ) ) {
		logging::print( oxorany( "Could not load dependency." ) );
		return std::getchar( );
	}

	if ( !dependency->map( ) ) {
		logging::print( oxorany( "Could not map dependency." ) );
		return std::getchar( );
	}

	if ( !dependency->inject( ) ) {
		logging::print( oxorany( "Could not inject dependency." ) );
		g_portal->free_all( );
		return std::getchar( );
	}

	dependency->cleanup( );
	logging::print( oxorany( "Portal allocations are released on target process exit" ) );
	logging::print( oxorany( "Press enter to exit injector (keep target running)" ) );
	return std::getchar( );
}