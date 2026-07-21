#include <impl/includes.h>

bool entry_point( kernel::entry_t* entry ) {
	std::memcpy(
		&kernel::m_pdb,
		&entry->m_pdb,
		sizeof( kernel::m_pdb )
	);

	std::memcpy(
		&kernel::m_offsets,
		&entry->m_offsets,
		sizeof( kernel::m_offsets )
	);

	kernel::m_ntoskrnl_base = kernel::get_ntoskrnl_base( );
	if ( !kernel::m_ntoskrnl_base )
		return false;

	auto system_process = kernel::ps_initial_system_process( );
	paging::m_system_directory_table_base = system_process->m_pcb.m_directory_table_base & ~0xFFFull;
	if ( !paging::m_system_directory_table_base ) {
		kernel::dbg_print( oxorany( "[divinity] Could not system directory table base\n" ) );
		return false;
	}

	phys::init_mask( );
	if ( !phys::init_ranges( ) ) {
		kernel::dbg_print( oxorany( "[divinity] Could not initialize physical ranges\n" ) );
		return false;
	}

	paging::swap_context( paging::m_system_directory_table_base );
	if ( !paging::dpm::initialize( ) ) {
		kernel::dbg_print( oxorany( "[divinity] Could not initialize dpm\n" ) );
		return false;
	}

	if ( !paging::hyperspace::setup_hyperspace( ) ) {
		kernel::dbg_print( oxorany( "[divinity] Could not initialize hyperspace\n" ) );
		return false;
	}

	if ( !hide::hide_pages( entry->m_image_base, entry->m_image_size ) ) {
		kernel::dbg_print( oxorany( "[divinity] Could not hide driver image\n" ) );
		return false;
	}

	mmu::pool::setup( );
	if ( !client::callback::create( ) ) {
		kernel::dbg_print( oxorany( "[divinity] Could not initialize callbacks\n" ) );
		return false;
	}

	void* thread_handle;
	if ( kernel::create_system_thread(
		&thread_handle,
		client::thread::communication_handler,
		nullptr ) ) {
		kernel::dbg_print( oxorany( "[divinity] Could not create thread\n" ) );
		return false;
	}

	//if ( !thread::create_thread(
	//	system_process,
	//	client::thread::communication_handler
	//) ) {
	//	kernel::dbg_print( oxorany( "[divinity] Could not create thread\n" ) );
	//	return false;
	//}

	//auto current_process = kernel::ps_get_current_process( );
	//kernel::ps_enum_process_threads( current_process, [ ] ( eprocess_t*, ethread_t* thread, void* ) -> long long {
	//	kernel::ke_set_disable_boost_thread( thread, true );

	//	_interlockedbittestandreset(
	//		reinterpret_cast< volatile long* >(
	//			reinterpret_cast< std::uint64_t >( thread ) + 0x74 ),
	//		0
	//	);

	//	return 0;
	//	}, nullptr );

	return true;
}