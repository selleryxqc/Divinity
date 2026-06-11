#pragma once

namespace client {
	eprocess_t* m_eprocess{ nullptr };
	mdl_t* m_comm_mdl{ nullptr };
	void* m_wnf_subscription{ };
	void* m_wnf_rundown{ };
	void* m_wnf_ctx{ };

	namespace thread {
		void communication_handler( void* context ) {
loop_start:
			while ( true ) {
				if ( !control::is_valid( ) ) {
					continue;
				}

				auto result = kernel::ke_wait_for_single_object(
					control::m_request_handle,
					0,
					0,
					false,
					0
				);

				if ( result == nt_status_t::timeout ) {
					continue;
				}

				control::m_control_data->m_status = false;
				switch ( control::m_control_data->m_request_type ) {
					case control::control_type::verify: {
						control::m_control_data->m_status = true;
					} break;
					case control::control_type::get_eprocess: {
						control::m_control_data->m_process = process::get_eprocess(
							control::m_control_data->m_process_id );
						if ( control::m_control_data->m_process )
							control::m_control_data->m_status = true;
					} break;
					case control::control_type::get_process_id: {
						control::m_control_data->m_process_id = reinterpret_cast< std::uint32_t >(
							process::get_process_id( control::m_control_data->m_process ) );
						if ( control::m_control_data->m_process_id )
							control::m_control_data->m_status = true;
					} break;
					case control::control_type::get_process_peb: {
						control::m_control_data->m_process_peb = process::get_process_peb(
							control::m_control_data->m_process );
						if ( control::m_control_data->m_process_peb )
							control::m_control_data->m_status = true;
					} break;
					case control::control_type::get_base_address: {
						control::m_control_data->m_address2 = process::get_section_base_address(
							control::m_control_data->m_process );
						if ( control::m_control_data->m_address2 )
							control::m_control_data->m_status = true;
					} break;
					case control::control_type::get_directory_table_base: {
						control::m_control_data->m_address = process::get_directory_table_base(
							control::m_control_data->m_process );
						if ( control::m_control_data->m_address )
							control::m_control_data->m_status = true;
					} break;
					case control::control_type::swap_directory_table_base: {
						control::m_control_data->m_address1 = paging::swap_context(
							control::m_control_data->m_address );
					} break;
					case control::control_type::hyperspace_entries: {
						if ( paging::hyperspace_entries(
							control::m_control_data->m_pt_entries,
							control::m_control_data->m_address
						) ) control::m_control_data->m_status = true;
					} break;
					case control::control_type::hide_process_pages: {
						control::m_control_data->m_status = hide::hide_vad(
							control::m_control_data->m_process,
							control::m_control_data->m_address
						);

						if ( control::m_control_data->m_status )
							control::m_control_data->m_status = hide::hide_pages(
								control::m_control_data->m_address,
								control::m_control_data->m_size
							);
					} break;
					case control::control_type::map_process_page: {
						auto mapped_va = paging::ptm::map_page(
							control::m_control_data->m_address,
							paging::page_protection::readwrite
						);

						control::m_control_data->m_address2 = mapped_va;
						control::m_control_data->m_status = ( mapped_va != nullptr );
					} break;
					case control::control_type::read_physical: {
						auto read_buffer = mmu::alloc_kva( paging::page_4kb_size );
						if ( !read_buffer ) {
							control::m_control_data->m_status = false;
							break;
						}

						control::m_control_data->m_status = paging::dpm::read_physical(
							control::m_control_data->m_address,
							reinterpret_cast< void* >( read_buffer ),
							control::m_control_data->m_size
						);

						if ( control::m_control_data->m_status ) {
							auto shared_buffer = reinterpret_cast< std::uint8_t* >( control::m_control_data )
								+ sizeof( control::control_data_t );

							auto read_size = min( control::m_control_data->m_size, paging::page_4kb_size );
							std::memcpy( shared_buffer, reinterpret_cast< void* >( read_buffer ), read_size );
						}

						mmu::free_kva( read_buffer, paging::page_4kb_size );
					} break;
					case control::control_type::write_physical: {
						auto write_buffer = mmu::alloc_kva( paging::page_4kb_size );
						if ( !write_buffer ) {
							control::m_control_data->m_status = false;
							break;
						}

						auto shared_buffer = reinterpret_cast< std::uint8_t* >( control::m_control_data )
							+ sizeof( control::control_data_t );

						auto write_size = min( control::m_control_data->m_size, paging::page_4kb_size );
						std::memcpy( reinterpret_cast< void* >( write_buffer ), shared_buffer, write_size );

						control::m_control_data->m_status = paging::dpm::write_physical(
							control::m_control_data->m_address,
							control::m_control_data->m_address2,
							control::m_control_data->m_size
						);

						mmu::free_kva( write_buffer, paging::page_4kb_size );
					} break;
					case control::control_type::read_virtual: {
						auto read_virtual = [ ] ( std::uint64_t virtual_address, void* buffer, std::size_t size ) -> bool {
							auto current_buffer = static_cast< std::uint8_t* >( buffer );
							auto current_va = virtual_address;
							auto remaining = size;

							while ( remaining > 0 ) {
								std::uint32_t page_size = 0;
								std::uint64_t physical_address = 0;
								if ( !paging::translate_linear( current_va, &physical_address, &page_size ) ) {
									return false;
								}

								auto page_offset = current_va & ( static_cast< unsigned long long >( page_size ) - 1 );
								auto read_size = min( static_cast< std::size_t >( page_size - page_offset ), remaining );

								if ( !paging::dpm::read_physical( physical_address, current_buffer, read_size ) )
									return false;

								current_va += read_size;
								current_buffer += read_size;
								remaining -= read_size;
							}

							return true;
							};

						auto read_buffer = mmu::alloc_kva( paging::page_4kb_size );
						if ( !read_buffer ) {
							control::m_control_data->m_status = false;
							break;
						}

						control::m_control_data->m_status = read_virtual(
							control::m_control_data->m_address,
							reinterpret_cast< void* >( read_buffer ),
							control::m_control_data->m_size
						);

						if ( control::m_control_data->m_status ) {
							auto shared_buffer = reinterpret_cast< std::uint8_t* >( control::m_control_data )
								+ sizeof( control::control_data_t );

							auto read_size = min( control::m_control_data->m_size, paging::page_4kb_size );
							std::memcpy( shared_buffer, reinterpret_cast< void* >( read_buffer ), read_size );
						}
						
						mmu::free_kva( read_buffer, paging::page_4kb_size );
					} break;
					case control::control_type::write_virtual: {
						auto write_virtual = [ ] ( std::uint64_t virtual_address, void* buffer, std::size_t size ) -> bool {
							auto current_buffer = static_cast< std::uint8_t* >( buffer );
							auto current_va = virtual_address;
							auto remaining = size;

							while ( remaining > 0 ) {
								std::uint32_t page_size = 0;
								std::uint64_t physical_address = 0;
								if ( !paging::translate_linear( current_va, &physical_address, &page_size ) ) {
									return false;
								}

								auto page_offset = current_va & ( static_cast< unsigned long long >( page_size ) - 1 );
								auto write_size = min( static_cast< std::size_t >( page_size - page_offset ), remaining );
								if ( !paging::dpm::write_physical( physical_address, current_buffer, write_size ) )
									return false;

								current_va += write_size;
								current_buffer += write_size;
								remaining -= write_size;
							}

							return true;
							};

						auto write_buffer = mmu::alloc_kva( paging::page_4kb_size );
						if ( !write_buffer ) {
							control::m_control_data->m_status = false;
							break;
						}

						auto shared_buffer = reinterpret_cast< std::uint8_t* >( control::m_control_data )
							+ sizeof( control::control_data_t );

						auto write_size = min( control::m_control_data->m_size, paging::page_4kb_size );
						std::memcpy( reinterpret_cast< void* >( write_buffer ), shared_buffer, write_size );

						control::m_control_data->m_status = write_virtual(
							control::m_control_data->m_address,
							reinterpret_cast< void* >( write_buffer ),
							control::m_control_data->m_size
						);

						mmu::free_kva( write_buffer, paging::page_4kb_size );
					} break;
					case control::control_type::lookup_thread: {
						control::m_control_data->m_thread = kernel::ps_lookup_thread_by_tid(
							control::m_control_data->m_thread_id
						);
					} break;
					case control::control_type::suspend_thread: {
						control::m_control_data->m_status = !kernel::ps_suspend_thread(
							control::m_control_data->m_thread,
							&control::m_control_data->m_count
						);
					} break;
					case control::control_type::resume_thread: {
						control::m_control_data->m_status = !kernel::ps_resume_thread(
							control::m_control_data->m_thread,
							&control::m_control_data->m_count
						);
					} break;
					case control::control_type::get_thread_context: {
						CONTEXT* base_address = nullptr;
						std::size_t size = sizeof( CONTEXT );

						auto result = kernel::zw_allocate_virtual_memory(
							NtCurrentProcess( ),
							reinterpret_cast< void** >( &base_address ),
							0,
							&size,
							MEM_COMMIT,
							PAGE_READWRITE
						);

						if ( result || !base_address ) {
							control::m_control_data->m_status = false;
							break;
						}

						base_address->ContextFlags = CONTEXT_FULL;

						auto status = kernel::ps_get_context_thread(
							control::m_control_data->m_thread,
							base_address,
							control::m_control_data->m_mode
						);

						auto shared_buffer = reinterpret_cast< std::uint8_t* >( control::m_control_data )
							+ sizeof( control::control_data_t );
						std::memcpy( shared_buffer, base_address, sizeof( CONTEXT ) );

						std::size_t free_size = 0;
						kernel::zw_free_virtual_memory(
							NtCurrentProcess( ),
							reinterpret_cast< void** >( &base_address ),
							&free_size,
							MEM_RELEASE
						);

						control::m_control_data->m_status = !status;
					} break;
					case control::control_type::set_thread_context: {
						auto context = reinterpret_cast< context_t* >(
							reinterpret_cast< uint8_t* >( control::m_control_data ) + sizeof( control::control_data_t )
							);

						CONTEXT* base_address = nullptr;
						SIZE_T size = sizeof( CONTEXT );

						auto result = kernel::zw_allocate_virtual_memory(
							NtCurrentProcess( ),
							reinterpret_cast< void** >( &base_address ),
							0,
							&size,
							MEM_COMMIT,
							PAGE_READWRITE
						);

						if ( result || !base_address ) {
							control::m_control_data->m_status = false;
							break;
						}

						auto shared_buffer = reinterpret_cast< uint8_t* >( control::m_control_data )
							+ sizeof( control::control_data_t );
						std::memcpy( base_address, shared_buffer, sizeof( context_t ) );

						auto status = kernel::ps_set_context_thread(
							control::m_control_data->m_thread,
							base_address,
							1
						);

						std::size_t free_size = 0;
						kernel::zw_free_virtual_memory(
							NtCurrentProcess( ),
							reinterpret_cast< void** >( &base_address ),
							&free_size,
							MEM_RELEASE
						);

						control::m_control_data->m_status = !status;
					} break;
					case control::control_type::clone_in_hyperspace: {
						auto result = paging::hyperspace::clone_process( control::m_control_data->m_process );
						if ( result )
							control::m_control_data->m_status = true;
					} break;
					case control::control_type::hyperspace_get_context: {
						auto index =
							paging::hyperspace::find_entry( control::m_control_data->m_process );
						control::m_control_data->m_process = paging::hyperspace::m_entries[ index ].m_clone_process;
						control::m_control_data->m_address = control::m_control_data->m_process->m_pcb.m_directory_table_base;
					} break;
					case control::control_type::hyperspace_allocate_virtual: {
						auto base_address = paging::hyperspace::allocate_virtual(
							control::m_control_data->m_process, 
							control::m_control_data->m_size );
						if ( base_address )
							control::m_control_data->m_address = base_address;
					} break;
					case control::control_type::hyperspace_free_virtual: {
						auto result = paging::hyperspace::free_virtual(
							control::m_control_data->m_process, 
							control::m_control_data->m_address );
						if ( result )
							control::m_control_data->m_status = true;
					} break;
					case control::control_type::hyperspace_remap_pages: {
						auto result = paging::hyperspace::remap_to_hyperspace(
							control::m_control_data->m_process,
							control::m_control_data->m_address,
							control::m_control_data->m_size,
							false );
						if ( result )
							control::m_control_data->m_status = true;
					} break;
					case control::control_type::hyperspace_expose_pages: {
						auto base_address = paging::hyperspace::expose_hyperspace(
							control::m_control_data->m_process,
							control::m_control_data->m_process2,
							control::m_control_data->m_address,
							control::m_control_data->m_size );
						if ( base_address ) {
							control::m_control_data->m_address1 = base_address;
							control::m_control_data->m_status = true;
						}
					} break;
					case control::control_type::hyperspace_clone_pages: {
						auto base_address = paging::hyperspace::expose_clone_pages(
							control::m_control_data->m_process,
							control::m_control_data->m_process2,
							control::m_control_data->m_address,
							control::m_control_data->m_size );
						if ( base_address ) {
							control::m_control_data->m_address1 = base_address;
							control::m_control_data->m_status = true;
						}
					} break;
					case control::control_type::hyperspace_rexpose_pages: {
						auto result = paging::hyperspace::refresh_hyperspace(
							control::m_control_data->m_process,
							control::m_control_data->m_process2 );
						if ( result )
							control::m_control_data->m_status = true;
					} break;
				}

				if ( control::m_response_handle ) {
					kernel::ke_release_semaphore( control::m_response_handle, 0, 1, false );
				}
			}

			goto loop_start;
		}
	}

	namespace callback {
		nt_status_t initialize( control::control_initialize_t* control_initialize ) {
			client::m_eprocess = kernel::ps_lookup_process_by_pid( control_initialize->m_process_id );
			if ( !client::m_eprocess )
				return nt_status_t::success;

			auto orig_process = process::attach( client::m_eprocess );
			auto orig_dtb = paging::swap_context( __readcr3( ) );

			paging::ptm::clean_cache( );
			if ( !paging::ptm::initialize( ) )
				return nt_status_t::unsuccessful;

			auto data_size = sizeof( control::control_data_t ) + 0x1000;
			auto base_address = control_initialize->m_base_address;

			client::m_comm_mdl = reinterpret_cast< mdl_t* >(
				kernel::io_allocate_mdl( nullptr, data_size, false, false, nullptr )
				);
			if ( !client::m_comm_mdl )
				return nt_status_t::unsuccessful;

			auto page_aligned_va = base_address & ~( paging::page_4kb_size - 1 );
			auto byte_offset = base_address & ( paging::page_4kb_size - 1 );
			auto page_count = ( ( byte_offset + data_size + paging::page_4kb_size - 1 ) / paging::page_4kb_size );

			client::m_comm_mdl->m_start_va = reinterpret_cast< void* >( page_aligned_va );
			client::m_comm_mdl->m_byte_offset = static_cast< std::uint32_t >( byte_offset );
			client::m_comm_mdl->m_byte_count = static_cast< std::uint32_t >( data_size );
			client::m_comm_mdl->m_mdl_flags |= 0x0001 | 0x0004;
			client::m_comm_mdl->m_process = client::m_eprocess;

			auto pfn_array = reinterpret_cast< std::uint64_t* >(
				reinterpret_cast< std::uint8_t* >( client::m_comm_mdl ) + sizeof( mdl_t )
				);

			for ( auto idx = 0ull; idx < page_count; idx++ ) {
				std::uint64_t current_pa;
				auto current_va = base_address + ( idx * paging::page_4kb_size );
				if ( !paging::translate_linear( current_va, &current_pa ) )
					return nt_status_t::unsuccessful;

				pfn_array[ idx ] = current_pa >> 12;
			}

			control::m_control_data = reinterpret_cast< control::control_data_t* >(
				kernel::mm_map_locked_pages_specify_cache(
					client::m_comm_mdl,
					0,
					1,
					nullptr,
					false,
					63
				) );
			if ( !control::m_control_data )
				return nt_status_t::unsuccessful;

			if ( kernel::ob_reference_object_by_handle(
				control_initialize->m_response_semaphore,
				0x1F0003,
				nullptr,
				0,
				reinterpret_cast< void** >( &control::m_response_handle ),
				nullptr
			) ) return nt_status_t::unsuccessful;

			if ( kernel::ob_reference_object_by_handle(
				control_initialize->m_request_semaphore,
				0x1F0003,
				nullptr,
				0,
				reinterpret_cast< void** >( &control::m_request_handle ),
				nullptr
			) ) return nt_status_t::unsuccessful;

			kernel::dbg_print( oxorany( "[divinity] initialized communications\n" ) );
			paging::swap_context( orig_dtb );
			process::attach( orig_process );
			return nt_status_t::success;
		}

		bool create( ) {
			kernel::ex_initialize_rundown_protection( &m_wnf_rundown );
			m_wnf_ctx = mmu::alloc_pool( sizeof( std::uint32_t ), 64 );
			if ( !m_wnf_ctx )
				return false;

			memset( m_wnf_ctx, 0, sizeof( std::uint32_t ) );

			auto wnf_callback = [ ](
				void* wnf_struct,
				PCWNF_STATE_NAME state_name,
				long             event_mask,
				long             change_stamp,
				void* type_id,
				void* callback_context
				) -> nt_status_t {
					if ( !kernel::ex_acquire_rundown_protection( &m_wnf_rundown ) )
						return nt_status_t::success;

					ULONG buffer_size = 0;
					ULONG time_stamp = 0;

					auto result = kernel::ex_query_wnf_state_data(
						wnf_struct, &time_stamp, nullptr, &buffer_size
					);

					if ( result != STATUS_BUFFER_TOO_SMALL || !buffer_size ) {
						kernel::ex_release_rundown_protection( &m_wnf_rundown );
						return result;
					}

					auto wnf_data = mmu::alloc_pool( buffer_size );
					if ( !wnf_data ) {
						kernel::ex_release_rundown_protection( &m_wnf_rundown );
						return nt_status_t::unsuccessful;
					}

					result = kernel::ex_query_wnf_state_data(
						wnf_struct, &time_stamp, wnf_data, &buffer_size
					);

					if ( !result ) {
						auto control_data = reinterpret_cast< control::control_initialize_t* >( wnf_data );
						result = initialize( control_data );
					}

					mmu::free_pool( wnf_data );
					kernel::ex_release_rundown_protection( &m_wnf_rundown );
					return result;
				};

			WNF_STATE_NAME state_name{ 0 };
			state_name.Data[ 0 ] = static_cast< uint32_t >( 0x0d83063ea3be0875 & 0xFFFFFFFF );
			state_name.Data[ 1 ] = static_cast< uint32_t >( ( 0x0d83063ea3be0875 >> 32 ) & 0xFFFFFFFF );

			if ( kernel::ex_subscribe_wnf_state_change(
				&m_wnf_subscription,
				&state_name,
				3,
				nullptr,
				wnf_callback,
				m_wnf_ctx
			) ) {
				kernel::ex_unsubscribe_wnf_state_change( &m_wnf_subscription );
				return false;
			}

			return true;
		}
	}
}