#pragma once

namespace nt {
	std::uint64_t ps_get_process_image_file_name( eprocess_t* process ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "PsGetProcessImageFileName" ) );
		}

		return g_syscall->call_kernel<std::uint64_t>( fn_address, process );
	}

	std::uint32_t ps_get_process_session_id( eprocess_t* process ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "PsGetProcessSessionId" ) );
		}

		return g_syscall->call_kernel<std::uint32_t>( fn_address, process );
	}

	bool is_address_valid( void* address ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MmIsAddressValid" ) );
		}

		if ( !fn_address )
			return false;

		return g_syscall->call_kernel<bool>( fn_address, address );
	}

	void memcpy( void* dst, void* src, std::uint64_t size ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "memcpy" ) );
		}

		if ( !fn_address )
			return;

		g_syscall->call_kernel( fn_address, dst, src, size );
	}

	void memset( void* dst, int value, std::uint64_t size ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "memset" ) );
		}

		if ( !fn_address )
			return;

		g_syscall->call_kernel( fn_address, dst, value, size );
	}

	std::uint64_t get_ps_active_process_head( ) {
		return 0;
	}

	void* get_pde_address( std::uint64_t address ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MiGetPdeAddress" ) );
		}

		if ( !fn_address )
			return nullptr;

		return g_syscall->call_kernel<void*>( fn_address, address );
	}

	physical_memory_range_t* mm_get_physical_memory_ranges( ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MmGetPhysicalMemoryRanges" ) );
		}

		if ( !fn_address )
			return nullptr;

		return g_syscall->call_kernel<physical_memory_range_t*>( fn_address );
	}

	void* mm_allocate_independent_pages( std::size_t size ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MmAllocateIndependentPages" ) );
		}

		if ( !fn_address )
			return nullptr;

		return g_syscall->call_kernel<void*>( fn_address, size, -1 );
	}

	void mm_free_independent_pages( std::uint64_t independent_pages, std::size_t size ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MmFreeIndependentPages" ) );
		}

		if ( !fn_address )
			return;

		g_syscall->call_kernel<void>( fn_address, reinterpret_cast< void* >( independent_pages ), size );
	}

	void* get_pte_address( std::uint64_t address ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "GetPteAddress" ) );
		}

		if ( !fn_address )
			return nullptr;

		return g_syscall->call_kernel<void*>( fn_address, address );
	}

	void* ps_get_process_peb( void* eprocess ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "PsGetProcessPeb" ) );
		}

		if ( !fn_address )
			return nullptr;

		return g_syscall->call_kernel<void*>( fn_address, eprocess );
	}

	void* ps_lookup_process_by_pid( std::uint32_t process_id ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "PsLookupProcessByProcessId" ) );
		}

		void* process = nullptr;
		auto status = g_syscall->call_kernel<NTSTATUS>(
			fn_address,
			reinterpret_cast< HANDLE >( process_id ),
			&process
		);

		if ( !NT_SUCCESS( status ) ) {
			logging::print( oxorany( "Could not lookup process with %d" ), status );
			return nullptr;
		}

		return process;
	}

	std::uint64_t ps_get_process_section_base_address( void* process ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "PsGetProcessSectionBaseAddress" ) );
		}

		if ( !fn_address )
			return 0;

		return g_syscall->call_kernel<std::uint64_t>( fn_address, process );
	}

	bool ex_acquire_resource( void* resource, bool wait ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "ExAcquireResourceExclusiveLite" ) );
		}

		if ( !fn_address )
			return false;

		return g_syscall->call_kernel<bool>( fn_address, resource, wait );
	}

	piddb_cache_entry_t* lookup_element_table( avl_table_t* table, void* buffer ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "RtlLookupElementGenericTableAvl" ) );
		}

		if ( !fn_address )
			return nullptr;

		return g_syscall->call_kernel<piddb_cache_entry_t*>( fn_address, table, buffer );
	}

	void release_resource( void* resource ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "ExReleaseResourceLite" ) );
		}

		if ( !fn_address )
			return;

		g_syscall->call_kernel( fn_address, resource );
	}

	bool delete_table_entry( avl_table_t* table, void* buffer ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "RtlDeleteElementGenericTableAvl" ) );
		}

		if ( !fn_address )
			return false;

		return g_syscall->call_kernel<bool>( fn_address, table, buffer );
	}

	bool rtl_equal_unicode_string( UNICODE_STRING* str1, UNICODE_STRING* str2, bool case_insensitive ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "RtlEqualUnicodeString" ) );
		}

		if ( !fn_address )
			return false;

		return g_syscall->call_kernel<bool>( fn_address, str1, str2, case_insensitive );
	}

	void* ex_allocate_pool( std::size_t size ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "ExAllocatePoolWithTag" ) );
		}
		if ( !fn_address )
			return nullptr;

		logging::print( "[syscall] ExAllocatePoolWithTag pool=512 size=0x%llx tag=0x%x\n", size, 0x4556494c );

		return g_syscall->call_kernel<void*>( fn_address,
			( std::uint64_t )512,        // NonPagedPoolNx
			size,
			( std::uint64_t )0x4556494c  // tag
		);
	}

	void* mm_allocate_contiguous_memory( std::size_t size, physical_address_t highest_acceptable_address ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MmAllocateContiguousMemory" ) );
		}

		if ( !fn_address )
			return nullptr;

		return g_syscall->call_kernel<void*>( fn_address, size, highest_acceptable_address );
	}

	void* mm_get_virtual_for_physical( physical_address_t physical_address ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MmGetVirtualForPhysical" ) );
		}

		if ( !fn_address )
			return nullptr;

		return g_syscall->call_kernel<void*>( fn_address, physical_address );
	}

	physical_address_t mm_get_physical_address( void* virtual_address ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MmGetPhysicalAddress" ) );
		}

		if ( !fn_address )
			return { };

		physical_address_t result{};
		result.m_quad_part = g_syscall->call_kernel<std::uint64_t>( fn_address, virtual_address );
		return result;
	}

	void* mm_map_io_space( physical_address_t physical_address, std::size_t number_of_bytes, std::uint32_t cache_type ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MmMapIoSpace" ) );
		}

		if ( !fn_address )
			return nullptr;

		return g_syscall->call_kernel<void*>( fn_address, physical_address, number_of_bytes, cache_type );
	}

	void mm_unmap_io_space( void* base_address, std::size_t number_of_bytes ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MmUnmapIoSpace" ) );
		}

		if ( !fn_address )
			return;

		g_syscall->call_kernel<void>( fn_address, base_address, number_of_bytes );
	}

	std::uint64_t read_msr( std::uint32_t msr_index ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "HalpWheaNativeReadMsr" ) );
		}

		if ( !fn_address )
			return 0;

		return g_syscall->call_kernel<std::uint64_t>( fn_address, 0, msr_index );
	}

	void* ke_get_current_processor( ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "KeGetCurrentProcessorNumberEx" ) );
		}

		if ( !fn_address )
			return nullptr;

		return g_syscall->call_kernel<void*>( fn_address, nullptr );
	}

	NTSTATUS ke_set_target_processor_dpc( void* dpc, void* processor_number ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "KeSetTargetProcessorDpcEx" ) );
		}

		if ( !fn_address )
			return 0xC0000001;

		return g_syscall->call_kernel<NTSTATUS>( fn_address, dpc, processor_number );
	}

	void* ke_insert_queue_dpc( void* dpc, void* system_arg1, void* system_arg2 ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "KeInsertQueueDpc" ) );
		}

		if ( !fn_address )
			return nullptr;

		return g_syscall->call_kernel<void*>( fn_address, dpc, system_arg1, system_arg2 );
	}

	void* mm_get_system_routine_address( std::wstring routine_name ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MmGetSystemRoutineAddress" ) );
		}

		if ( !fn_address )
			return nullptr;

		unicode_string_t system_routine_name;
		rtl_init_unicode_string( &system_routine_name, routine_name.c_str( ) );
		return g_syscall->call_kernel<void*>( fn_address, &system_routine_name );
	}

	void* ke_initialize_dpc( void* dpc, void* routine, void* context ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "KeInitializeDpc" ) );
		}

		if ( !fn_address )
			return nullptr;

		return g_syscall->call_kernel<void*>( fn_address, dpc, routine, context );
	}

	std::uint32_t ke_query_max_processor_count( ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "KeQueryMaximumProcessorCountEx" ) );
		}

		if ( !fn_address )
			return 0;

		return g_syscall->call_kernel<std::uint32_t>( fn_address, 0 );
	}


	KAFFINITY ke_query_active_processors( ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "KeQueryActiveProcessors" ) );
		}

		if ( !fn_address )
			return { };

		return g_syscall->call_kernel<KAFFINITY>( fn_address );
	}

	void ke_set_system_affinity_thread( KAFFINITY affinity ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "KeSetSystemAffinityThread" ) );
		}

		if ( !fn_address )
			return;

		g_syscall->call_kernel<void>( fn_address, affinity );
	}

	bool ke_cancel_timer( void* timer ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "KeCancelTimer" ) );
		}

		if ( !fn_address )
			return 0;

		return g_syscall->call_kernel<bool>( fn_address, timer );
	}

	std::uint64_t get_kprcb( int processor ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "KeGetPrcb" ) );
		}

		if ( !fn_address )
			return 0;

		return g_syscall->call_kernel<std::uint64_t>( fn_address, processor );
	}

	std::uint64_t get_current_kprcb( ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "KeGetCurrentPrcb" ) );
		}

		if ( !fn_address )
			return 0;

		return g_syscall->call_kernel<std::uint64_t>( fn_address );
	}

	std::uint64_t query_system_information( int information_class, void* buffer, std::uint32_t buffer_size, std::uint32_t* return_length ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "ZwQuerySystemInformation" ) );
		}

		if ( !fn_address )
			return 0;

		return g_syscall->call_kernel<NTSTATUS>(
			fn_address,
			information_class,
			buffer,
			buffer_size,
			return_length
		);
	}

	NTSTATUS mm_copy_memory(
		void* target_address,
		mm_copy_address_t source_address,
		std::size_t number_of_bytes,
		std::uint32_t flags,
		std::size_t* number_of_bytes_transferred
	) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MmCopyMemory" ) );
		}

		if ( !fn_address )
			return 1;

		return g_syscall->call_kernel<NTSTATUS>( fn_address, target_address, source_address, number_of_bytes, flags );
	}

	inline void ke_flush_entire_tb( bool invalidate, bool all_processors ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "KeFlushEntireTb" ) );
		}

		if ( !fn_address )
			return;

		g_syscall->call_kernel<void>( fn_address, invalidate, all_processors );
	}

	inline void ke_invalidate_all_caches( ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "KeInvalidateAllCaches" ) );
		}

		if ( !fn_address )
			return;

		g_syscall->call_kernel<void>( fn_address );
	}

	inline void ke_flush_single_tb( std::uintptr_t address, bool all_processors, bool invalidate ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "KeFlushSingleTb" ) );
		}

		if ( !fn_address )
			return;

		g_syscall->call_kernel<void>( fn_address, address, all_processors, invalidate );
	}

	std::pair< std::uint8_t*, std::uint8_t* > get_gdt_idt( ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "KiGetGdtIdt" ) );
		}

		if ( !fn_address )
			return { };

		uint8_t gdt_info[ 10 ];
		uint8_t idt_info[ 10 ];
		g_syscall->call_kernel<void*>( fn_address, &gdt_info, &idt_info );
		return std::make_pair( gdt_info, idt_info );
	}

	void* get_current_process_eprocess( ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "PsGetCurrentProcess" ) );
		}

		if ( !fn_address )
			return nullptr;

		return g_syscall->call_kernel<void*>( fn_address );
	}

	bool rtl_compare_unicode_string( unicode_string_t* str1, unicode_string_t* str2, bool case_insensitive ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "RtlCompareUnicodeString" ) );
		}

		if ( !fn_address )
			return false;

		return g_syscall->call_kernel<bool>( fn_address, str1, str2, case_insensitive );
	}

	void rtl_init_unicode_string( unicode_string_t* destination_string, const wchar_t* source_string ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "RtlInitUnicodeString" ) );
		}

		if ( !fn_address )
			return;

		g_syscall->call_kernel<void>( fn_address, destination_string, source_string );
	}

	void* ps_lookup_thread_by_tid( std::uint32_t tid ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "PsLookupThreadByThreadId" ) );
		}

		if ( !fn_address )
			return nullptr;

		void* thread = nullptr;
		auto status = g_syscall->call_kernel< NTSTATUS >(
			fn_address,
			reinterpret_cast< void* >( static_cast< std::uint64_t >( tid ) ),
			&thread
		);

		if ( !NT_SUCCESS( status ) || !thread )
			return nullptr;

		return thread;
	}

	void ob_dereference_object( void* object ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "ObfDereferenceObject" ) );
		}

		if ( !fn_address )
			return;

		g_syscall->call_kernel< void* >( fn_address, object );
	}

	bool mm_initialize_process_address_space( eprocess_t* clone_process, eprocess_t* target_process ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MmInitializeProcessAddressSpace" ) );
		}

		if ( !fn_address )
			return false;

		auto flags = mm_allocate_independent_pages( sizeof( ULONG ) );
		if ( !flags )
			return false;

		auto result = g_syscall->call_kernel< std::int64_t >(
			fn_address,
			clone_process,
			target_process,
			nullptr,
			flags,
			0
		);

		if ( result ) {
			logging::print( oxorany( "MmInitializeProcessAddressSpace failed with: 0x%llx" ), result );
			return false;
		}

		return true;
	}

	std::int32_t mi_copy_on_write( std::uint64_t virtual_address, std::uint64_t* pte_address ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MiCopyOnWrite" ) );
		}

		if ( !fn_address )
			return false;

		return g_syscall->call_kernel< std::int32_t >( fn_address, virtual_address, pte_address, -1, 0 );
	}

	void ke_stack_attach_process(
		eprocess_t* process,
		kapc_state_t* apc_state
	) {
		static auto fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "KeStackAttachProcess" ) );
			if ( !fn_address ) return;
		}

		g_syscall->call_kernel< void* >( fn_address, process, apc_state );
	}

	void ke_unstack_detach_process(
		kapc_state_t* apc_state
	) {
		static auto fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "KeUnstackDetachProcess" ) );
			if ( !fn_address ) return;
		}

		g_syscall->call_kernel< void* >( fn_address, apc_state );
	}

	bool mm_set_page_protection( std::uint64_t virtual_address, std::size_t size, std::uint64_t protection ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MmSetPageProtection" ) );
			if ( !fn_address )
				return 0;
		}

		return g_syscall->call_kernel< bool >( fn_address, virtual_address, size, protection );
	}

	void mi_delete_vad( eprocess_t* process, void* vad ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MiDeleteVad" ) );
		}
		if ( !fn_address )
			return;

		g_syscall->call_kernel<void>( fn_address, process, vad );
	}

	void mi_delete_inserted_clone_vads( eprocess_t* process ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MiDeleteInsertedCloneVads" ) );
		}
		if ( !fn_address )
			return;
		g_syscall->call_kernel<void>( fn_address, process );
	}

	void mi_clean_vad( void* vad_root ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MiCleanVad" ) );
		}
		if ( !fn_address )
			return;
		g_syscall->call_kernel<void>( fn_address, vad_root );
	}

	void mi_remove_vad( eprocess_t* process, void* vad ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MiRemoveVad" ) );
		}
		if ( !fn_address )
			return;

		g_syscall->call_kernel<void>( fn_address, process, vad );
	}

	void mi_finish_vad_deletion( eprocess_t* process, void* vad ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MiFinishVadDeletion" ) );
		}
		if ( !fn_address )
			return;
		g_syscall->call_kernel<void>( fn_address, process, vad );
	}

	void mi_free_vad_events( void* vad ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MiFreeVadEvents" ) );
		}
		if ( !fn_address )
			return;
		g_syscall->call_kernel<void>( fn_address, vad );
	}

	void mi_lock_down_working_set( eprocess_t* process, int index ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MiLockDownWorkingSet" ) );
		}
		if ( !fn_address )
			return;
		g_syscall->call_kernel<void>( fn_address, process, index );
	}

	void mi_release_vad_event_blocks( eprocess_t* process, void* vad ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MiReleaseVadEventBlocks" ) );
		}
		if ( !fn_address )
			return;
		g_syscall->call_kernel<void>( fn_address, process, vad );
	}

	void mi_return_vad_quota( eprocess_t* process, void* vad ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MiReturnVadQuota" ) );
		}
		if ( !fn_address )
			return;
		g_syscall->call_kernel<void>( fn_address, process, vad );
	}

	void mi_delete_vad_bitmap( void* vad ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MiDeleteVadBitmap" ) );
		}
		if ( !fn_address )
			return;
		g_syscall->call_kernel<void>( fn_address, vad );
	}

	void mi_free_vad_event_bitmap( eprocess_t* process, void* vad, int bit ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MiFreeVadEventBitmap" ) );
		}
		if ( !fn_address )
			return;
		g_syscall->call_kernel<void>( fn_address, process, vad, bit );
	}

	void mi_return_process_vads( eprocess_t* process ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MiReturnProcessVads" ) );
		}
		if ( !fn_address )
			return;
		g_syscall->call_kernel<void>( fn_address, process );
	}

	void mi_dereference_vad( void* vad ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MiDereferenceVad" ) );
		}
		if ( !fn_address )
			return;
		g_syscall->call_kernel<void>( fn_address, vad );
	}

	void mi_clone_discard_vad_commit( void* vad ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MiCloneDiscardVadCommit" ) );
		}
		if ( !fn_address )
			return;
		g_syscall->call_kernel<void>( fn_address, vad );
	}

	bool rtl_create_user_thread(
		void* process_handle,
		void* security_descriptor,
		bool create_suspended,
		std::uint32_t stack_zero_bits,
		std::size_t stack_reserved,
		std::size_t stack_commit,
		void* start_address,
		void* parameter,
		void** thread_handle,
		void* client_id
	) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "RtlCreateUserThread" ) );
		}

		if ( !fn_address )
			return false;

		auto result = g_syscall->call_kernel<std::int64_t>(
			fn_address,
			process_handle,
			security_descriptor,
			create_suspended,
			stack_zero_bits,
			stack_reserved,
			stack_commit,
			start_address,
			parameter,
			thread_handle,
			client_id
		);

		if ( result ) {
			logging::print( oxorany( "RtlCreateUserThread failed with: 0x%llx" ), result );
			return false;
		}

		return true;
	}

	bool ps_create_system_thread(
		void** thread_handle,
		std::uint32_t desired_access,
		void* object_attributes,
		void* process_handle,
		void* client_id,
		void* start_routine,
		void* start_context
	) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "PsCreateSystemThread" ) );
		}

		if ( !fn_address )
			return 0xC0000001;

		auto result = g_syscall->call_kernel<NTSTATUS>(
			fn_address,
			thread_handle,
			desired_access,
			object_attributes,
			process_handle,
			client_id,
			start_routine,
			start_context
		);

		if ( result ) {
			logging::print( oxorany( "PsCreateSystemThread failed with: 0x%llx" ), result );
			return false;
		}

		return true;
	}

	std::int32_t ob_open_object_by_pointer(
		void* object,
		std::uint32_t handle_attributes,
		void* access_state,
		std::uint32_t desired_access,
		void* object_type,
		std::uint8_t processor_mode,
		void** handle
	) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "ObOpenObjectByPointer" ) );
		}

		if ( !fn_address )
			return 0xC0000001;

		return g_syscall->call_kernel<std::int32_t>(
			fn_address,
			object,
			handle_attributes,
			access_state,
			desired_access,
			object_type,
			processor_mode,
			handle
		);
	}

	NTSTATUS zw_close( void* handle ) {
		static std::uint64_t fn_zw_close = 0;
		if ( !fn_zw_close ) {
			fn_zw_close = g_pdb->get_symbol_address( oxorany( "ZwClose" ) );
		}

		if ( !fn_zw_close )
			return 1;

		return g_syscall->call_kernel<NTSTATUS>( fn_zw_close, handle );
	}

	void* ps_loaded_module_list( ) {
		static void* ps_loaded_module_list = nullptr;
		if ( !ps_loaded_module_list ) {
			ps_loaded_module_list = reinterpret_cast< void* >(
				g_pdb->get_symbol_address( oxorany( "PsLoadedModuleList" ) )
				);
		}

		if ( !ps_loaded_module_list )
			return { };

		return ps_loaded_module_list;
	}

	void flush_caches( void* address ) {
		ke_flush_entire_tb( true, true );
		ke_invalidate_all_caches( );
		ke_flush_single_tb( reinterpret_cast< std::uint64_t >( address ), true, true );
	}
}