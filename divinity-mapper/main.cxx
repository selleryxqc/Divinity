#include <impl/includes.h>

int main( int argc, char** argv ) {
	SetConsoleTitleA( oxorany( "divinity-mapper" ) );
	SetUnhandledExceptionFilter( handler::crash_handler );

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

	if ( !utility::adjust_privilege( 20 ) )
		return std::getchar( );

	if ( argc < 2 ) {
		logging::print( oxorany( "Missing parameters" ) );
		return std::getchar( );
	}

	logging::print( oxorany( "downloading ntoskrnl PDB..." ) );
	if ( !g_pdb->load( ) ) {
		logging::print( oxorany( "could not load PDB" ) );
		return std::getchar( );
	}

	logging::print( oxorany( "loaded %zu symbols from %s\n" ),
		g_pdb->m_symbols.size( ), g_pdb->m_module_bare.c_str( ) );

	if ( !g_service->create( ) ) {
		logging::print( oxorany( "Could not setup service" ) );
		g_service->unload( );
		return std::getchar( );
	}

	if ( !g_driver->initialize( ) ) {
		logging::print( oxorany( "Could not setup driver" ) );
		g_service->unload( );
		return std::getchar( );
	}

	if ( !g_paging->setup( ) ) {
		logging::print( oxorany( "could not get directory table base" ) );
		g_service->unload( );
		g_driver->unload( );
		return std::getchar( );
	}

	if ( !g_syscall->setup( ) ) {
		logging::print( oxorany( "could not setup kernel execution" ) );
		g_service->unload( );
		g_driver->unload( );
		return std::getchar( );
	}

	auto dependency = std::make_shared< map::c_dependency >( argv[ 1 ] );
	if ( !dependency->load( ) ) {
		logging::print( oxorany( "Could not load dependency" ) );
		g_service->unload( );
		g_driver->unload( );
		return std::getchar( );
	}

	auto map = std::make_unique< map::c_map >( dependency );
	if ( !map->create( ) ) {
		logging::print( oxorany( "could not manual map" ) );
		g_service->unload( );
		g_driver->unload( );
		return std::getchar( );
	}

	if ( !map->execute( ) )
		logging::print( oxorany( "could not execute." ) );

	g_service->unload( );
	g_driver->unload( );
	return std::getchar( );
}