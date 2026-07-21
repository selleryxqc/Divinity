#pragma once 

namespace map {
	class c_map {
	public:
		c_map( ) { }
		~c_map( ) { }
		c_map( std::shared_ptr< c_dependency > dependency ) : m_dependency( dependency ) { }

		bool create( ) {
			auto dependency_size = m_dependency->get_size( );
			m_mapped_image.resize( dependency_size );
			std::memset( m_mapped_image.data( ), 0, dependency_size );

			this->m_dependency_base = module::allocate_large_page( dependency_size );
			if ( !m_dependency_base )
				return false;

			if ( !relocate( ) ) {
				logging::print( oxorany( "could not map relocations" ) );
				return false;
			}

			map_delayed_imports( );
			map_imports( );

			if ( !map_sections( ) ) {
				logging::print( oxorany( "could not map sections" ) );
				return false;
			}

			nt::memcpy(
				reinterpret_cast< void* >( m_dependency_base ),
				m_mapped_image.data( ),
				m_mapped_image.size( )
			);

			logging::print( oxorany( "created module mapping\n" ) );
			return true;
		}

		bool execute( ) {
			this->m_entry_point = m_dependency->get_entry_point( );
			if ( !m_entry_point ) {
				logging::print( oxorany( "could not find entry point" ) );
				return false;
			}

			entry_t entry{ };
			entry.m_pdb.m_mm_allocate_independent_pages = g_pdb->get_symbol_address( oxorany( "MmAllocateIndependentPagesEx" ) );
			entry.m_pdb.m_mm_free_independent_pages = g_pdb->get_symbol_address( oxorany( "MmFreeIndependentPages" ) );
			entry.m_pdb.m_mm_set_page_protection = g_pdb->get_symbol_address( oxorany( "MmSetPageProtection" ) );
			entry.m_pdb.m_mi_lock_page_table_page = g_pdb->get_symbol_address( oxorany( "MiLockPageTablePage" ) );
			entry.m_pdb.m_mi_is_page_on_bad_list = g_pdb->get_symbol_address( oxorany( "MiIsPageOnBadList" ) );
			entry.m_pdb.m_mi_make_page_bad = g_pdb->get_symbol_address( oxorany( "MiMakePageBad" ) );
			entry.m_pdb.m_mm_initialize_process_address_space = g_pdb->get_symbol_address( oxorany( "MmInitializeProcessAddressSpace" ) );
			entry.m_pdb.m_po_idle = g_pdb->get_symbol_address( oxorany( "PoIdle" ) );
			entry.m_pdb.m_ke_query_active_processor_count_ex = g_pdb->get_symbol_address( oxorany( "KeQueryActiveProcessorCountEx" ) );
			entry.m_pdb.m_ki_nmi_callback_list_head = g_pdb->get_symbol_address( oxorany( "KiNmiCallbackListHead" ) );
			entry.m_pdb.m_psp_allocate_thread = g_pdb->get_symbol_address( oxorany( "PspAllocateThread" ) );
			entry.m_pdb.m_ke_initialize_thread = g_pdb->get_symbol_address( oxorany( "KeInitializeThread" ) );
			entry.m_pdb.m_ke_start_thread = g_pdb->get_symbol_address( oxorany( "KeStartThread" ) );
			entry.m_pdb.m_ke_ready_thread = g_pdb->get_symbol_address( oxorany( "KeReadyThread" ) );
			entry.m_pdb.m_mi_copy_on_write = g_pdb->get_symbol_address( oxorany( "MiCopyOnWrite" ) );
			entry.m_pdb.m_ke_set_disable_boost_thread = g_pdb->get_symbol_address( oxorany( "KeSetDisableBoostThread" ) );
			entry.m_pdb.m_ps_enum_process_threads = g_pdb->get_symbol_address( oxorany( "PsEnumProcessThreads" ) );
			entry.m_pdb.m_ps_suspend_thread = g_pdb->get_symbol_address( oxorany( "PsSuspendThread" ) );
			entry.m_pdb.m_ps_resume_thread = g_pdb->get_symbol_address( oxorany( "PsResumeThread" ) );
			entry.m_pdb.m_ps_get_context_thread = g_pdb->get_symbol_address( oxorany( "PsGetContextThread" ) );
			entry.m_pdb.m_ps_set_context_thread = g_pdb->get_symbol_address( oxorany( "PsSetContextThread" ) );
			entry.m_pdb.m_mi_remove_vad = g_pdb->get_symbol_address( oxorany( "MiRemoveVad" ) );
			entry.m_pdb.m_ex_query_big_pool_tag = g_pdb->get_symbol_address( oxorany( "ExQueryBigPoolTag" ) );
			entry.m_pdb.m_ex_map_handle_to_pointer = g_pdb->get_symbol_address( oxorany( "ExMapHandleToPointer" ) );
			entry.m_pdb.m_ex_destroy_handle = g_pdb->get_symbol_address( oxorany( "ExDestroyHandle" ) );
			entry.m_pdb.m_psp_thread_delete = g_pdb->get_symbol_address( oxorany( "PspThreadDelete" ) );
			entry.m_pdb.m_mi_initialize_pfn_for_other_process = g_pdb->get_symbol_address( oxorany( "MiInitializePfnForOtherProcess" ) );
			entry.m_pdb.m_mi_allocate_vad = g_pdb->get_symbol_address( oxorany( "MiAllocateVad" ) );
			entry.m_pdb.m_mi_insert_vad = g_pdb->get_symbol_address( oxorany( "MiInsertVad" ) );
			entry.m_pdb.m_rtlp_debug_print_callback_list = g_pdb->get_symbol_address( oxorany( "RtlpDebugPrintCallbackList" ) );
			entry.m_pdb.m_nt_global_flag = g_pdb->get_symbol_address( oxorany( "NtGlobalFlag" ) );
			entry.m_pdb.m_kdp_debug_routine_select = g_pdb->get_symbol_address( oxorany( "KdpDebugRoutineSelect" ) );
			entry.m_pdb.m_kdp_trap = g_pdb->get_symbol_address( oxorany( "KdpTrap" ) );
			entry.m_pdb.m_kdp_report = g_pdb->get_symbol_address( oxorany( "KdpReport" ) );
			entry.m_pdb.m_etw_trace_silo_kernel_event = g_pdb->get_symbol_address( oxorany( "EtwTraceSiloKernelEvent" ) );
			entry.m_pdb.m_ke_service_descriptor_table = g_pdb->get_symbol_address( oxorany( "KeServiceDescriptorTable" ) );
			entry.m_pdb.m_ki_system_call64 = g_pdb->get_symbol_address( oxorany( "KiSystemCall64" ) );
			entry.m_pdb.m_psp_user_thread_start = g_pdb->get_symbol_address( oxorany( "PspUserThreadStart" ) );
			entry.m_pdb.m_rtl_get_extended_context_length2 = g_pdb->get_symbol_address( oxorany( "RtlGetExtendedContextLength2" ) );
			entry.m_pdb.m_rtl_initialize_extended_context2 = g_pdb->get_symbol_address( oxorany( "RtlInitializeExtendedContext2" ) );


			/*
			
			            std::uint64_t m_ke_service_descriptor_table;
            std::uint64_t m_ki_system_call64;*/
			entry.m_offsets.m_thread_start_address = g_pdb->get_struct_member( "_ETHREAD", "StartAddress" );
			entry.m_offsets.m_directory_table_base = g_pdb->get_struct_member( "_KPROCESS", "DirectoryTableBase" );
			entry.m_offsets.m_user_directory_table_base = g_pdb->get_struct_member( "_KPROCESS", "UserDirectoryTableBase" );
			entry.m_offsets.m_vad_root = g_pdb->get_struct_member( "_EPROCESS", "VadRoot" );
			entry.m_offsets.m_flags = g_pdb->get_struct_member( "_EPROCESS", "Flags" );
			entry.m_offsets.m_flags3 = g_pdb->get_struct_member( "_EPROCESS", "Flags3" );
			entry.m_offsets.m_rundown_protect = g_pdb->get_struct_member( "_EPROCESS", "RundownProtect" );
			entry.m_offsets.m_thread_list_head = g_pdb->get_struct_member( "_EPROCESS", "ThreadListHead" );

			entry.m_directory_table_base = g_paging->m_directory_table_base;
			entry.m_ntoskrnl_base = g_pdb->m_module_base;
			entry.m_image_size = m_mapped_image.size( );
			entry.m_image_base = m_dependency_base;

			auto entry_address = reinterpret_cast< std::uint64_t >(
				nt::mm_allocate_independent_pages( sizeof( entry ) )
				);

			if ( !entry_address )
				return false;

			nt::memcpy(
				reinterpret_cast< void* >( entry_address ),
				&entry, sizeof( entry )
			);

			auto result = g_syscall->call_kernel< bool >( 
				m_dependency_base + m_entry_point,
				entry_address );
			if ( result ) {
				logging::print( oxorany( "successfully executed\n" ) );
				return result;
			}

			return result;
		}

	private:
		eprocess_t* m_target_process;
		std::shared_ptr< c_dependency > m_dependency;
		std::uint64_t m_dependency_base{ };
		std::uint64_t m_entry_point{ };
		std::vector< std::uint8_t > m_mapped_image;

		bool relocate( ) {
			auto delta_offset = m_dependency_base - m_dependency->get_image_base( );
			if ( m_dependency->is_reloc_stripped( ) ) {
				logging::print( oxorany( "depedency relocations stripped" ) );
				return false;
			}

			auto reloc_dir = m_dependency->get_reloc_directory( );
			if ( !reloc_dir ) {
				logging::print( oxorany( "could not find relocation directory" ) );
				return false;
			}

			auto reloc_entry = m_dependency->rva_to_va<reloc_entry_t*>( reloc_dir->m_virtual_address );
			if ( !reloc_entry ) {
				logging::print( oxorany( "could not find relocation entry" ) );
				return false;
			}

			auto reloc_end = reinterpret_cast< reloc_entry_t* >(
				reinterpret_cast< std::uint8_t* >( reloc_entry ) + reloc_dir->m_size
				);

			while ( reloc_entry < reloc_end && reloc_entry->m_size ) {
				auto record_count = ( reloc_entry->m_size - 8 ) >> 1;
				logging::print( oxorany( "relocating block with size: 0x%x" ), reloc_entry->m_size );

				for ( auto idx = 0u; idx < record_count; idx++ ) {
					auto offset = reloc_entry->m_item[ idx ].m_offset % 4096;
					auto type = reloc_entry->m_item[ idx ].m_type;
					if ( type == IMAGE_REL_BASED_ABSOLUTE )
						continue;

					auto reloc_addr = m_dependency->rva_to_va< std::uint8_t* >( reloc_entry->m_to_rva );
					auto reloc_va = reinterpret_cast< std::uint64_t* >( reloc_addr + offset );
					*reloc_va += delta_offset;
				}

				reloc_entry = reinterpret_cast< reloc_entry_t* >(
					reinterpret_cast< uint8_t* >( reloc_entry ) + reloc_entry->m_size
					);
			}

			return true;
		}

		bool map_imports( ) {
			auto import_table = m_dependency->get_import_table( );
			if ( !import_table->m_virtual_address || !import_table->m_size ) {
				logging::print( oxorany( "could not find import table" ) );
				return false;
			}

			auto import_desc = m_dependency->rva_to_va< import_descriptor_t* >( import_table->m_virtual_address );
			while ( import_desc->m_name ) {
				auto module_name = m_dependency->rva_to_va< LPSTR >( import_desc->m_name );
				if ( !module_name ) {
					logging::print( oxorany( "could not resolve import name" ) );
					break;
				}

				auto import_module = module::get_kernel_module( module_name );
				if ( !import_module ) {
					logging::print( oxorany( "could not resolve module" ) );
					return false;
				}

				auto first_thunk = m_dependency->rva_to_va< nt_image_thunk_data_t* >( import_desc->m_first_thunk );
				auto orig_first_thunk = m_dependency->rva_to_va< nt_image_thunk_data_t* >( import_desc->m_original_first_thunk );
				if ( !orig_first_thunk || !first_thunk ) {
					logging::print( oxorany( "could not resolve thunk data" ) );
					break;
				}

				while ( first_thunk->u1.address_of_data ) {
					if ( IMAGE_SNAP_BY_ORDINAL64( orig_first_thunk->u1.ordinal ) ) {
						auto ordinal = IMAGE_ORDINAL64( orig_first_thunk->u1.ordinal );
						first_thunk->u1.function = import_module->get_export( ( const char* )ordinal );
						if ( !first_thunk->u1.function ) {
							logging::print( oxorany( "could not resolve function %s:%s" ), ( const char* )ordinal, module_name );
							return false;
						}
					}
					else {
						auto ibn = m_dependency->rva_to_va< nt_image_import_name_t* >( orig_first_thunk->u1.address_of_data );
						if ( !ibn ) {
							logging::print( oxorany( "could not get IBN" ) );
							return false;
						}

						first_thunk->u1.function = import_module->get_export( ibn->name );
						if ( !first_thunk->u1.function ) {
							logging::print( oxorany( "could not resolve function %s:%s" ), ibn->name, module_name );
							return false;
						}
					}

					orig_first_thunk++;
					first_thunk++;
				}

				memset( module_name, 0, std::strlen( module_name ) );
				import_desc++;
			}

			return true;
		}

		bool map_delayed_imports( ) {
			auto delay_descriptor = m_dependency->get_delay_import_descriptor( );
			if ( !delay_descriptor->m_virtual_address || !delay_descriptor->m_size ) {
				return true;
			}

			auto delay_desc = m_dependency->rva_to_va< image_delayload_descriptor_t* >( delay_descriptor->m_virtual_address );
			while ( delay_desc->m_dll_name_rva ) {
				auto module_name = m_dependency->rva_to_va< LPSTR >( delay_desc->m_dll_name_rva );
				if ( !module_name ) {
					logging::print( oxorany( "could not resolve import name" ) );
					break;
				}

				auto import_module = module::get_kernel_module( module_name );
				if ( !import_module ) {
					logging::print( oxorany( "could not resolve module" ) );
					return false;
				}

				auto first_thunk = m_dependency->rva_to_va< nt_image_thunk_data_t* >( delay_desc->m_import_address_table_rva );
				auto orig_first_thunk = m_dependency->rva_to_va< nt_image_thunk_data_t* >( delay_desc->m_import_name_table_rva );
				if ( !orig_first_thunk || !first_thunk ) {
					logging::print( oxorany( "could not resolve thunk data" ) );
					break;
				}

				while ( first_thunk->u1.address_of_data ) {
					if ( IMAGE_SNAP_BY_ORDINAL64( orig_first_thunk->u1.ordinal ) ) {
						auto ordinal = IMAGE_ORDINAL64( orig_first_thunk->u1.ordinal );
						first_thunk->u1.function = import_module->get_export( ( const char* )ordinal );
					}
					else {
						auto ibn = m_dependency->rva_to_va< nt_image_import_name_t* >( orig_first_thunk->u1.address_of_data );
						if ( !ibn ) {
							logging::print( oxorany( "could not get IBN" ) );
							return false;
						}

						first_thunk->u1.function = import_module->get_export( ibn->name );
					}

					if ( !first_thunk->u1.function ) {
						logging::print( oxorany( "couldnt not resolve function" ) );
						return false;
					}

					orig_first_thunk++;
					first_thunk++;
				}
			}

			return true;
		}

		bool map_sections( ) {
			auto section_count = m_dependency->get_section_count( );
			for ( auto idx = 0ul; idx < section_count; idx++ ) {
				auto section = m_dependency->get_section( idx );
				if ( !section->m_virtual_address || !section->m_size_of_raw_data )
					continue;

				auto section_buffer = m_mapped_image.data( ) + section->m_virtual_address;
				auto source_data = m_dependency->get_raw_image( ).data( ) + section->m_pointer_to_raw_data;
				std::memcpy( section_buffer, source_data, section->m_size_of_raw_data );

				logging::print( oxorany( "mapped section -> %s" ), section->m_name );
			}

			return true;
		}
	};
}