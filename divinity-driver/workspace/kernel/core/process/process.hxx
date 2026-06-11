#pragma once

namespace process {
	std::uint64_t get_directory_table_base( eprocess_t* eprocess );

	peb_t* get_process_peb( eprocess_t* eprocess ) {
		auto process_peb_offset = kernel::get_process_peb_offset( );
		return *reinterpret_cast< peb_t** >(
			reinterpret_cast< std::uintptr_t >( eprocess ) + process_peb_offset
			);
	}

	void* get_section_base_address( eprocess_t* eprocess ) {
		auto section_base_address_offset = kernel::get_section_base_address_offset( );
		return *reinterpret_cast< void** >(
			reinterpret_cast< std::uintptr_t >( eprocess ) + section_base_address_offset
			);
	}

	void* get_process_id( eprocess_t* eprocess ) {
		auto process_id_offset = kernel::get_process_id_offset( );
		return *reinterpret_cast< void** >(
			reinterpret_cast< std::uintptr_t >( eprocess ) + process_id_offset
			);
	}

	ethread_t* get_main_thread( eprocess_t* eprocess ) {
		std::uint64_t lowest_tid = MAXULONG_PTR;
		ethread_t* main_thread = nullptr;

		const auto process_va = reinterpret_cast< std::uint64_t >( eprocess );
		auto* head = reinterpret_cast< LIST_ENTRY* >( process_va + offsets::thread_list_head );
		auto* current = head->Flink;
		std::uint32_t guard = 0;

		while ( current && current != head ) {
			auto thread_va = reinterpret_cast< std::uint64_t >( current ) - offsets::thread_list_entry;

			auto cross_flags = *reinterpret_cast< std::uint32_t* >(
				thread_va + offsets::cross_thread_flags );
			bool terminated = ( cross_flags >> 0 ) & 1;
			bool dead = ( cross_flags >> 3 ) & 1;

			if ( !terminated && !dead ) {
				auto tid = reinterpret_cast< std::uint64_t >(
					kernel::ps_get_thread_id(
					reinterpret_cast< ethread_t* >( thread_va ) ) );

				if ( tid && tid < lowest_tid ) {
					lowest_tid = tid;
					main_thread = reinterpret_cast< ethread_t* >( thread_va );
				}
			}

			current = current->Flink;

			if ( ++guard > 1024 )
				break;
		}

		return main_thread;
	}

	const char* get_image_file_name( eprocess_t* eprocess ) {
		if ( !kernel::mm_is_address_valid( eprocess ) )
			return 0;

		auto image_file_name_offset = kernel::get_image_file_name_offset( );
		auto image_file_name_ptr = reinterpret_cast< const char* >(
			reinterpret_cast< std::uintptr_t >( eprocess ) + image_file_name_offset
			);

		if ( !kernel::mm_is_address_valid( const_cast< char* >( image_file_name_ptr ) ) )
			return 0;

		char image_file_name[ 16 ] = { 0 };
		__try {
			for ( int i = 0; i < 15; i++ ) {
				image_file_name[ i ] = image_file_name_ptr[ i ];
				if ( image_file_name[ i ] == '\0' )
					break;
			}
			image_file_name[ 15 ] = '\0';
		}
		__except ( 1 ) {
			return 0;
		}

		return image_file_name;
	}

	eprocess_t* get_eprocess( const char* process_name ) {
		auto process_list_head = kernel::ps_active_process_head( );
		if ( !process_list_head )
			return nullptr;

		auto linkage_va =
			reinterpret_cast< std::uintptr_t >( process_list_head ) -
			reinterpret_cast< std::uintptr_t >( kernel::ps_initial_system_process( ) );
		if ( !linkage_va )
			return nullptr;

		for ( auto flink = process_list_head->m_flink; flink; flink = flink->m_flink ) {
			if ( !kernel::mm_is_address_valid( flink ) )
				break;

			auto curr_eprocess = reinterpret_cast< eprocess_t* >(
				reinterpret_cast< std::uintptr_t >( flink ) - linkage_va
				);
			if ( !curr_eprocess )
				continue;

			auto image_file_name = get_image_file_name( curr_eprocess );
			if ( _stricmp( image_file_name, process_name ) == 0 ) {
				return curr_eprocess;
			}
		}

		return nullptr;
	}


	eprocess_t* get_eprocess( std::uint32_t target_pid ) {
		auto process_list_head = kernel::ps_active_process_head( );
		if ( !process_list_head )
			return nullptr;

		auto linkage_va = 
			reinterpret_cast< std::uintptr_t >( process_list_head ) -
			reinterpret_cast< std::uintptr_t >( kernel::ps_initial_system_process( ) );
		if ( !linkage_va )
			return nullptr;

		for ( auto flink = process_list_head->m_flink; flink; flink = flink->m_flink ) {
			if ( !kernel::mm_is_address_valid( flink ) )
				break;

			auto current_process = reinterpret_cast< eprocess_t* >(
				reinterpret_cast< std::uintptr_t >( flink ) - linkage_va
				);
			if ( !current_process )
				continue;

			auto process_id = get_process_id( current_process );
			if ( process_id == reinterpret_cast< void* >( target_pid ) )
				return current_process;
		}

		return nullptr;
	}

	eprocess_t* attach( eprocess_t* eprocess ) {
		auto current_thread = reinterpret_cast< ethread_t* >( __readgsqword( 0x188 ) );
		if ( !current_thread )
			return nullptr;

		auto apc_state = &current_thread->m_kthread.m_apc_state;
		auto org_process = apc_state->m_process;

		apc_state->m_process = eprocess;
		__writecr3( eprocess->m_pcb.m_directory_table_base );
		return org_process;
	}
}