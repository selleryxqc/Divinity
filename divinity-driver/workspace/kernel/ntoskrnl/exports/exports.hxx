#pragma once

namespace kernel {
    nt_status_t ps_set_create_process_notify_routine( p_create_process_notify_routine callback_routine, bool remove ) {
        static std::uint8_t* fn_address = nullptr;
        if ( !fn_address ) {
            fn_address = reinterpret_cast< std::uint8_t* >(
                get_export( m_ntoskrnl_base, oxorany( "PsSetCreateProcessNotifyRoutine" ) )
                );
            if ( !fn_address )
                return nt_status_t::not_supported;
        }

        using function_t = nt_status_t( __stdcall* )( p_create_process_notify_routine, bool );
        auto fn = reinterpret_cast< function_t >( fn_address );
        return fn( callback_routine, remove ? true : false );
    }

    std::uint32_t get_image_file_name_offset( ) {
        static std::uint32_t image_file_name_offset = 0;
        if ( !image_file_name_offset ) {
            auto ps_get_process_image_file_name = reinterpret_cast< std::uint8_t* >(
                get_export( m_ntoskrnl_base, oxorany( "PsGetProcessImageFileName" ) )
                );

            if ( !ps_get_process_image_file_name ) {
                return 0;
            }

            while ( !( ps_get_process_image_file_name[ 0 ] == 0x48 &&
                ps_get_process_image_file_name[ 1 ] == 0x8D &&
                ps_get_process_image_file_name[ 2 ] == 0x81 ) ) {
                ps_get_process_image_file_name++;
            }

            image_file_name_offset = *reinterpret_cast< std::uint32_t* >( ps_get_process_image_file_name + 3 );
        }

        return image_file_name_offset;
    }

    nt_status_t create_system_thread(
        void** thread_handle,
        pkstart_routine start_routine,
        void* start_context
    ) {
        static auto fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( m_ntoskrnl_base, oxorany( "PsCreateSystemThread" ) );
            if ( !fn_address ) return {};
        }

        using function_t = nt_status_t( * )(
            void** thread_handle,
            std::uint32_t desired_access,
            object_attributes_t* object_attributes,
            void* process_handle,
            client_id_t* client_id,
            pkstart_routine start_routine,
            void* start_context
            );

        return reinterpret_cast< function_t >( fn_address )(
            thread_handle,
            THREAD_ALL_ACCESS,
            nullptr,
            nullptr,
            nullptr,
            start_routine,
            start_context
            );
    }

    std::uint64_t ex_destroy_handle( std::uint64_t table, HANDLE handle, void* entry ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = m_pdb.m_ex_destroy_handle;
            if ( !export_address ) return 0;
        }

        using fn_t = std::uint64_t( std::uint64_t, HANDLE, void* );
        return reinterpret_cast< fn_t* >( export_address )( table, handle, entry );
    }

    std::uint64_t ex_map_handle_to_pointer( std::uint64_t table, HANDLE handle ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = m_pdb.m_ex_map_handle_to_pointer;
            if ( !export_address ) return 0;
        }

        using fn_t = std::uint64_t( std::uint64_t, HANDLE );
        return reinterpret_cast< fn_t* >( export_address )( table, handle );
    }

    void* mm_allocate_contiguous_memory_specify_cache(
        std::size_t number_of_bytes,
        std::uint64_t lowest_acceptable_address,
        std::uint64_t highest_acceptable_address,
        std::uint64_t boundary_address_multiple,
        std::uint32_t cache_type
    ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "MmAllocateContiguousMemorySpecifyCache" ) );
            if ( !export_address ) return nullptr;
        }

        physical_address_t lowest{ }; lowest.m_quad_part = static_cast< std::uint64_t >( lowest_acceptable_address );
        physical_address_t highest{ }; highest.m_quad_part = static_cast< std::uint64_t >( highest_acceptable_address );
        physical_address_t boundary{  }; boundary.m_quad_part = static_cast< std::uint64_t >( boundary_address_multiple );

        using function_t = void* ( * )(
            std::size_t,
            physical_address_t,
            physical_address_t,
            physical_address_t,
            std::uint32_t
            );

        return reinterpret_cast< function_t >( export_address )(
            number_of_bytes,
            lowest,
            highest,
            boundary,
            cache_type
            );
    }

    void mm_free_contiguous_memory( void* base_address ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "MmFreeContiguousMemory" ) );
            if ( !export_address ) return;
        }

        using function_t = void( * )( void* );
        reinterpret_cast< function_t >( export_address )( base_address );
    }

    nt_status_t mi_copy_on_write( std::uint64_t virtual_address, std::uint64_t* pte_address, std::int64_t pfn ) {
        static std::uint64_t mi_copy_on_write = 0ull;
        if ( !mi_copy_on_write ) {
            mi_copy_on_write = m_pdb.m_mi_copy_on_write;
            if ( !mi_copy_on_write )
                return nt_status_t::unsuccessful;
        }

        using mi_copy_on_write_t = nt_status_t( __fastcall* )( std::uint64_t, std::uint64_t*, std::int64_t, std::int32_t );
        return reinterpret_cast< mi_copy_on_write_t >( mi_copy_on_write )( virtual_address, pte_address, pfn, 0 );
    }

    nt_status_t mi_remove_vad( mmvad_short_t* vad, eprocess_t* process ) {
        static auto mi_remove_vad = 0ull;
        if ( !mi_remove_vad ) {
            mi_remove_vad = m_pdb.m_mi_remove_vad;
            if ( !mi_remove_vad )
                return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( __fastcall* )( mmvad_short_t*, eprocess_t* );
        return reinterpret_cast< function_t >( mi_remove_vad )( vad, process );
    }

    nt_status_t ps_suspend_thread( ethread_t* thread, std::uint32_t* previous_suspend_count ) {
        static auto ps_suspend_thread = 0ull;
        if ( !ps_suspend_thread ) {
            ps_suspend_thread = m_pdb.m_ps_suspend_thread;
            if ( !ps_suspend_thread )
                return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( __fastcall* )( ethread_t*, std::uint32_t* );
        return reinterpret_cast< function_t >( ps_suspend_thread )( thread, previous_suspend_count );
    }

    nt_status_t ps_resume_thread( ethread_t* thread, std::uint32_t* previous_suspend_count ) {
        static auto ps_resume_thread = 0ull;
        if ( !ps_resume_thread ) {
            ps_resume_thread = m_pdb.m_ps_resume_thread;
            if ( !ps_resume_thread )
                return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( __fastcall* )( ethread_t*, std::uint32_t* );
        return reinterpret_cast< function_t >( ps_resume_thread )( thread, previous_suspend_count );
    }

    nt_status_t ps_get_context_thread( ethread_t* thread, CONTEXT* context, std::uint32_t mode ) {
        static auto ps_get_context_thread = 0ull;
        if ( !ps_get_context_thread ) {
            ps_get_context_thread = m_pdb.m_ps_get_context_thread;
            if ( !ps_get_context_thread )
                return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( __fastcall* )( ethread_t*, CONTEXT*, std::uint32_t );
        return reinterpret_cast< function_t >( ps_get_context_thread )( thread, context, mode );
    }

    nt_status_t ps_set_context_thread( ethread_t* thread, CONTEXT* context, std::uint32_t mode ) {
        static auto ps_set_context_thread = 0ull;
        if ( !ps_set_context_thread ) {
            ps_set_context_thread = m_pdb.m_ps_set_context_thread;
            if ( !ps_set_context_thread )
                return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( __fastcall* )( ethread_t*, CONTEXT*, std::uint32_t );
        return reinterpret_cast< function_t >( ps_set_context_thread )( thread, context, mode );
    }

    nt_status_t ex_free_pool_with_tag( void* pool, unsigned long tag ) {
        static auto function_address = 0ull;
        if ( !function_address ) {
            function_address = get_export( m_ntoskrnl_base, oxorany( "ExFreePoolWithTag" ) );
            if ( !function_address ) return {};
        }
        using function_t = void( * )(
            void*,
            unsigned long
            );
        reinterpret_cast< function_t >( function_address )(
            pool,
            tag
            );
        return nt_status_t::success;
    }

    nt_status_t ex_query_wnf_state_data( void* wnf_struct, PULONG time_stamp, void* buffer, PULONG size ) {
        static auto function_address = 0ull;
        if ( !function_address ) {
            function_address = get_export( m_ntoskrnl_base, oxorany( "ExQueryWnfStateData" ) );
            if ( !function_address ) return {};
        }

        using function_t = nt_status_t( * )(
            void*,
            PULONG,
            void*,
            PULONG
            );

        return reinterpret_cast< function_t >( function_address )(
            wnf_struct,
            time_stamp,
            buffer,
            size
            );
    }

    ethread_t* ps_lookup_thread_by_tid( std::uint32_t thread_id ) {
        static void* ps_lookup_thread_by_tid = nullptr;
        if ( !ps_lookup_thread_by_tid ) {
            ps_lookup_thread_by_tid = reinterpret_cast< void* >(
                get_export( m_ntoskrnl_base,
                oxorany( "PsLookupThreadByThreadId" )
                )
                );

            if ( !ps_lookup_thread_by_tid )
                return nullptr;
        }

        ethread_t* thread = nullptr;
        using function_t = nt_status_t( * )( HANDLE thread_id, ethread_t** thread );
        auto status = reinterpret_cast< function_t >( ps_lookup_thread_by_tid )(
            reinterpret_cast< HANDLE >( thread_id ),
            &thread
            );

        if ( !status ) {
            return thread;
        }

        return nullptr;
    }

    nt_status_t ps_set_load_image_notify_routine( p_load_image_notify_routine callback_routine ) {
        static std::uint8_t* fn_address = nullptr;
        if ( !fn_address ) {
            fn_address = reinterpret_cast< std::uint8_t* >(
                get_export( m_ntoskrnl_base, oxorany( "PsSetLoadImageNotifyRoutine" ) )
                );
            if ( !fn_address ) return {};
        }

        using function_t = nt_status_t( __stdcall* )( p_load_image_notify_routine );
        auto fn = reinterpret_cast< function_t >( fn_address );
        return fn( callback_routine );
    }

    int rtl_compare_unicode_string(
        unicode_string_t* string1,
        unicode_string_t* string2,
        bool case_insensitive
    ) {
        static auto fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( m_ntoskrnl_base, oxorany( "RtlCompareUnicodeString" ) );
            if ( !fn_address ) return 0;
        }

        using function_t = int( * )(
            unicode_string_t* string1,
            unicode_string_t* string2,
            bool case_insensitive
            );

        return reinterpret_cast< function_t >( fn_address )(
            string1,
            string2,
            case_insensitive
            );
    }


    eprocess_t* ps_get_current_process( ) {
        static auto ps_get_current_process = 0ull;
        if ( !ps_get_current_process ) {
            ps_get_current_process = get_export( m_ntoskrnl_base, oxorany( "PsGetCurrentProcess" ) );
            if ( !ps_get_current_process ) return {};
        }

        using function_t = eprocess_t * ( );
        return reinterpret_cast< function_t* >( ps_get_current_process )( );
    }

    __int64 ke_set_disable_boost_thread( ethread_t* thread, bool enabled ) {
        static auto ke_set_disable_boost_thread = 0ull;
        if ( !ke_set_disable_boost_thread ) {
            ke_set_disable_boost_thread = m_pdb.m_ke_set_disable_boost_thread;
            if ( !ke_set_disable_boost_thread ) {
                return { };
            }
        }

        using function_t = __int64( ethread_t*, bool );
        return reinterpret_cast< function_t* >( ke_set_disable_boost_thread )( thread, enabled );
    }

    __int64 ps_enum_process_threads( eprocess_t* process, __int64( *callback )( eprocess_t*, ethread_t*, void* ), void* parameter ) {
        static auto ps_enum_process_threads = 0ull;
        if ( !ps_enum_process_threads ) {
            ps_enum_process_threads = m_pdb.m_ps_enum_process_threads;
            if ( !ps_enum_process_threads ) {
                return { };
            }
        }

        using function_t = __int64( eprocess_t*, __int64( __fastcall* )( eprocess_t*, ethread_t*, void* ), void* );
        return reinterpret_cast< function_t* >( ps_enum_process_threads )( process, callback, parameter );
    }

    nt_status_t mm_copy_memory(
        void* target_address,
        mm_copy_address_t source_address,
        std::size_t number_of_bytes,
        std::uint32_t flags,
        std::size_t* number_of_bytes_transferred
    ) {
        static auto fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( m_ntoskrnl_base, oxorany( "MmCopyMemory" ) );
            if ( !fn_address ) return { };
        }

        using function_t = nt_status_t(
            void* target_address,
            mm_copy_address_t source_address,
            std::size_t number_of_bytes,
            std::uint32_t flags,
            std::size_t* number_of_bytes_transferred
        );

        return reinterpret_cast< function_t* >( fn_address )(
            target_address,
            source_address,
            number_of_bytes,
            flags,
            number_of_bytes_transferred
            );
    }


    nt_status_t psp_allocate_thread(
        std::uint64_t process_address,
        std::uint64_t user_context,
        bool previous_mode,
        void* thread_creation_params,
        void* context_record,
        void* unknown6,
        void* start_routine,
        void* start_context,
        std::uint32_t* creation_flags,
        ethread_t** out_thread,
        void* stack_info,
        void* output_buffer
    ) {
        static auto psp_allocate_thread = 0ull;
        if ( !psp_allocate_thread ) {
            psp_allocate_thread = m_pdb.m_psp_allocate_thread;
            if ( !psp_allocate_thread )
                return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( __fastcall* )(
            std::uint64_t, std::uint64_t, bool, void*, void*, void*, void*,
            void*, std::uint32_t*, ethread_t**, void*, void*
            );

        return reinterpret_cast< function_t >( psp_allocate_thread )(
            process_address,
            user_context,
            previous_mode,
            thread_creation_params,
            context_record,
            unknown6,
            start_routine,
            start_context,
            creation_flags,
            out_thread,
            stack_info,
            output_buffer
            );
    }

    void ke_flush_entire_tb( bool invalidate, bool all_processors ) {
        static auto fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( m_ntoskrnl_base, oxorany( "KeFlushEntireTb" ) );
            if ( !fn_address ) return;
        }

        using function_t = void( * )( bool invalidate, bool all_processors );
        reinterpret_cast< function_t >( fn_address )( invalidate, all_processors );
    }

    void ke_invalidate_all_caches( ) {
        static auto fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( m_ntoskrnl_base, oxorany( "KeInvalidateAllCaches" ) );
            if ( !fn_address ) return;
        }

        using function_t = void( * )( );
        reinterpret_cast< function_t >( fn_address )( );
    }

    unsigned char ke_raise_irql_to_dpc_level( ) {
        static auto fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( m_ntoskrnl_base, oxorany( "KeRaiseIrqlToDpcLevel" ) );
            if ( !fn_address ) return 0;
        }
        using function_t = unsigned char( * )( );
        return reinterpret_cast< function_t >( fn_address )( );
    }

    std::uint8_t ke_get_current_irql( ) {
        static auto ke_get_current_irql = 0ull;
        if ( !ke_get_current_irql ) {
            ke_get_current_irql = get_export( m_ntoskrnl_base, oxorany( "KeGetCurrentIrql" ) );
            if ( !ke_get_current_irql ) return {};
        }

        using function_t = std::uint8_t( );
        reinterpret_cast< function_t* >( ke_get_current_irql )( );
    }

    unsigned char ke_raise_irql( unsigned char irql ) {
        static auto fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( m_ntoskrnl_base, oxorany( "KeRaiseIrql" ) );
            if ( !fn_address ) return 0;
        }

        using function_t = unsigned char( * )( unsigned char );
        return reinterpret_cast< function_t >( fn_address )( irql );
    }

    nt_status_t ps_create_system_thread(
        void** thread_handle,
        std::uint32_t desired_access,
        void* object_attributes,
        void* process_handle,
        void* client_id,
        void* start_routine,
        void* start_context ) {
        static auto fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( m_ntoskrnl_base, "PsCreateSystemThread" );
            if ( !fn_address ) return {};
        }

        using function_t = nt_status_t(
            void** thread_handle,
            std::uint32_t desired_access,
            void* object_attributes,
            void* process_handle,
            void* client_id,
            void* start_routine,
            void* start_context
        );

        return reinterpret_cast< function_t* >( fn_address )(
            thread_handle,
            desired_access,
            object_attributes,
            process_handle,
            client_id,
            start_routine,
            start_context
            );
    }

    void ke_lower_irql( unsigned char new_irql ) {
        static auto fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( m_ntoskrnl_base, oxorany( "KeLowerIrql" ) );
            if ( !fn_address ) return;
        }
        using function_t = void( * )( unsigned char );
        reinterpret_cast< function_t >( fn_address )( new_irql );
    }

    void ke_flush_single_tb( std::uintptr_t address, bool all_processors, bool invalidate ) {
        static auto fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( m_ntoskrnl_base, oxorany( "KeFlushSingleTb" ) );
            if ( !fn_address ) return;
        }

        using function_t = void( * )( std::uintptr_t address, bool all_processors, bool invalidate );
        reinterpret_cast< function_t >( fn_address )( address, all_processors, invalidate );
    }

    kthread_t* ke_get_current_thread( ) {
        static auto fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( m_ntoskrnl_base, oxorany( "KeGetCurrentThread" ) );
            if ( !fn_address ) return {};
        }

        using function_t = kthread_t * ( );
        return reinterpret_cast< function_t* >( fn_address )( );
    }

    long long obf_reference_object( void* object ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "ObfReferenceObject" ) );
            if ( !export_address ) return 0;
        }
        using function_t = long long( void* );
        return reinterpret_cast< function_t* >( export_address )( object );
    }

    nt_status_t ke_initialize_thread(
        ethread_t* thread,
        void* kernel_stack,
        pkstart_routine system_routine,
        PKSTART_ROUTINE start_routine,
        void* start_context,
        void* context_frame,
        void* teb,
        eprocess_t* process
    ) {
        static auto ke_initialize_thread = 0ull;
        if ( !ke_initialize_thread ) {
            ke_initialize_thread = m_pdb.m_ke_initialize_thread;
            if ( !ke_initialize_thread )
                return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( __fastcall* )(
            ethread_t*, void*, pkstart_routine, PKSTART_ROUTINE,
            void*, void*, void*, eprocess_t*
            );

        return reinterpret_cast< function_t >( ke_initialize_thread )(
            thread,
            kernel_stack,
            system_routine,
            start_routine,
            start_context,
            context_frame,
            teb,
            process
            );
    }

    nt_status_t ke_start_thread(
        ethread_t* thread,
        void* affinity,
        void* ideal_processor
    ) {
        static auto ke_start_thread = 0ull;
        if ( !ke_start_thread ) {
            ke_start_thread = m_pdb.m_ke_start_thread;
            if ( !ke_start_thread )
                return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( __fastcall* )(
            ethread_t*, void*, void*
            );

        return reinterpret_cast< function_t >( ke_start_thread )(
            thread,
            affinity,
            ideal_processor
            );
    }

    nt_status_t ke_ready_thread( ethread_t* thread ) {
        static auto ke_ready_thread = 0ull;
        if ( !ke_ready_thread ) {
            ke_ready_thread = m_pdb.m_ke_ready_thread;
            if ( !ke_ready_thread )
                return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( __fastcall* )( ethread_t* );
        return reinterpret_cast< function_t >( ke_ready_thread )( thread );
    }

    // PsGetThreadId - Get TID from thread
    HANDLE ps_get_thread_id( ethread_t* thread ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "PsGetThreadId" ) );
            if ( !export_address )
                return nullptr;
        }

        using function_t = HANDLE( __fastcall* )( ethread_t* );
        return reinterpret_cast< function_t >( export_address )( thread );
    }

    kpcr_t* ke_get_pcr( ) {
        return reinterpret_cast< kpcr_t* >( KeGetPcr( ) );
    }

    std::uint64_t get_po_idle( ) {
        return m_pdb.m_po_idle;
    }

    std::uint64_t get_psp_user_thread_start( ) {
        return m_pdb.m_psp_user_thread_start;
    }

    knmi_handler_callback_t* get_ki_nmi_callback_list_head( ) {
        static auto ki_nmi_callback_list_head = 0ull;
        if ( !ki_nmi_callback_list_head ) {
            ki_nmi_callback_list_head = m_pdb.m_ki_nmi_callback_list_head;
            if ( !ki_nmi_callback_list_head ) return {};
        }

        return reinterpret_cast< knmi_handler_callback_t* >( ki_nmi_callback_list_head );
    }

    std::uint32_t ke_query_active_processor_count( ) {
        static auto ke_query_active_processor_count_ex = 0ull;
        if ( !ke_query_active_processor_count_ex ) {
            ke_query_active_processor_count_ex = m_pdb.m_ke_query_active_processor_count_ex;
            if ( !ke_query_active_processor_count_ex ) return {};
        }

        using function_t = std::uint32_t( std::uint32_t );
        return reinterpret_cast< function_t* >( ke_query_active_processor_count_ex )( 0xFFFF );
    }

    object_type_t* ps_thread_object_type( ) {
        static auto ps_thread_object_type = 0ull;
        if ( !ps_thread_object_type ) {
            ps_thread_object_type = get_export( m_ntoskrnl_base, oxorany( "PsThreadObjectType" ) );
            if ( !ps_thread_object_type ) return nullptr;
        }

        return *reinterpret_cast< object_type_t** >( ps_thread_object_type );
    }

    bool mm_is_address_valid( void* virtual_address ) {
        static auto fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( m_ntoskrnl_base, oxorany( "MmIsAddressValid" ) );
            if ( !fn_address ) return {};
        }

        using function_t = bool( void* virtual_address );
        return reinterpret_cast< function_t* >( fn_address )( virtual_address );
    }

    bool ps_is_system_thread( ethread_t* thread ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "PsIsSystemThread" ) );
            if ( !export_address ) return 0;
        }

        using function_t = bool( ethread_t* );
        return reinterpret_cast< function_t* >( export_address )( thread );
    }

    std::uint64_t ke_register_bound_callback( PBOUND_CALLBACK bound_callback ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "KeRegisterBoundCallback" ) );
            if ( !export_address ) return 0;
        }

        using function_t = std::uint64_t( PBOUND_CALLBACK );
        return reinterpret_cast< function_t* >( export_address )( bound_callback );
    }

    teb_t* ps_get_current_thread_teb( ) {
        static auto ps_get_current_thread_teb = 0ull;
        if ( !ps_get_current_thread_teb ) {
            ps_get_current_thread_teb = get_export( m_ntoskrnl_base, oxorany( "PsGetCurrentThreadTeb" ) );
            if ( !ps_get_current_thread_teb ) return {};
        }

        using function_t = teb_t * ( );
        return reinterpret_cast< function_t* >( ps_get_current_thread_teb )( );
    }

    nt_status_t zw_allocate_virtual_memory(
        HANDLE process_handle,
        void** base_address,
        ULONG_PTR zero_bits,
        SIZE_T* region_size,
        ULONG allocation_type,
        ULONG protect ) {
        static auto fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( m_ntoskrnl_base, oxorany( "ZwAllocateVirtualMemory" ) );
            if ( !fn_address ) return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( HANDLE, void**, ULONG_PTR, PSIZE_T, ULONG, ULONG );
        return reinterpret_cast< function_t* >( fn_address )(
            process_handle,
            base_address,
            zero_bits,
            region_size,
            allocation_type,
            protect
            );
    }

    void* mi_allocate_vad( uint64_t start_va, uint64_t end_va, uint8_t flags ) {
        static auto fn = 0ull;
        if (!fn) {
            fn = m_pdb.m_mi_allocate_vad;
            if (!fn) return nullptr;
        }
        using function_t = void*( uint64_t, uint64_t, uint8_t );
        return reinterpret_cast<function_t*>(fn)( start_va, end_va, flags );
    }

    std::uint64_t rtl_get_extended_context_length2(
        std::uint64_t context_flags,
        std::uint32_t* length,
        std::uint64_t xstate_mask
    ) {
        static auto fn = 0ull;
        if ( !fn ) {
            fn = m_pdb.m_rtl_get_extended_context_length2;
            if ( !fn ) return 0;
        }
        using function_t = std::uint64_t( std::uint64_t, std::uint32_t*, std::uint64_t );
        return reinterpret_cast< function_t* >( fn )( context_flags, length, xstate_mask );
    }

    std::uint64_t rtl_initialize_extended_context2(
        std::uint64_t buffer,
        std::uint32_t context_flags,
        std::uint64_t* ctx_ptr,
        std::uint64_t xstate_mask
    ) {
        static auto fn = 0ull;
        if ( !fn ) {
            fn = m_pdb.m_rtl_initialize_extended_context2;
            if ( !fn ) return 0;
        }
        using function_t = std::uint64_t( std::uint64_t, std::uint32_t, std::uint64_t*, std::uint64_t );
        return reinterpret_cast< function_t* >( fn )( buffer, context_flags, ctx_ptr, xstate_mask );
    }

    void mi_insert_vad( void* vad, eprocess_t* process, uint8_t flags ) {
        static auto fn = 0ull;
        if (!fn) {
            fn = m_pdb.m_mi_insert_vad;
            if (!fn) return;
        }
        using function_t = void( void*, eprocess_t*, uint8_t );
        reinterpret_cast<function_t*>(fn)( vad, process, flags );
    }

    bool mi_initialize_pfn_for_other_process( uint64_t pfn, uint64_t pte_va, uint64_t parent_pfn, uint16_t flags ) {
        static auto mi_initialize_pfn_for_other_process_fn = 0ull;
        if ( !mi_initialize_pfn_for_other_process_fn ) {
            mi_initialize_pfn_for_other_process_fn = m_pdb.m_mi_initialize_pfn_for_other_process;
            if ( !mi_initialize_pfn_for_other_process_fn )
                return false;
        }

        using function_t = __int64( uint64_t, uint64_t, uint64_t, uint16_t );
        reinterpret_cast< function_t* >( mi_initialize_pfn_for_other_process_fn )(
            pfn, pte_va, parent_pfn, flags );

        return true;
    }

    bool mm_initialize_process_address_space( eprocess_t* clone_process, eprocess_t* target_process ) {
        static auto mm_initialize_process_address_space = 0ull;
        if ( !mm_initialize_process_address_space ) {
            mm_initialize_process_address_space = m_pdb.m_mm_initialize_process_address_space;
            if ( !mm_initialize_process_address_space )
                return false;
        }

        ULONG flags = 0;
        using function_t = __int64( eprocess_t*, eprocess_t*, void*, ULONG*, int );
        auto result = reinterpret_cast< function_t* >( mm_initialize_process_address_space )(
            clone_process, target_process, nullptr, &flags, 0 );

        return result == 0;
    }

    std::uint32_t rand( ) {
        static auto fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( m_ntoskrnl_base, oxorany( "RtlRandomEx" ) );
            if ( !fn_address ) return {};
        }

        unsigned int low = *reinterpret_cast< unsigned int* >( 0xFFFFF78000000000 );
        unsigned int mul = *reinterpret_cast< unsigned int* >( 0xFFFFF78000000004 );
        auto seed = ( ( std::uint64_t )( low ) * ( uint64_t )( mul ) ) >> 24;

        using function_t = std::uint32_t( unsigned long* );
        return reinterpret_cast< function_t* >( fn_address )( ( unsigned long* )&seed );
    }

    long ke_set_event(
        kevent_t* event,
        long increment,
        bool wait ) {
        static auto function_address = 0ull;
        if ( !function_address ) {
            function_address = get_export( m_ntoskrnl_base, oxorany( "KeSetEvent" ) );
            if ( !function_address ) return nt_status_t::unsuccessful;
        }

        using function_t = long( * )(
            kevent_t*,
            long,
            bool
            );

        return reinterpret_cast< function_t >( function_address )(
            event,
            increment,
            wait
            );
    }

    hal_private_dispatch_t* get_hal_private_dispatch( ) {
        static hal_private_dispatch_t* hal_private_dispatch{ };
        if ( !hal_private_dispatch ) {
            hal_private_dispatch = reinterpret_cast
                < hal_private_dispatch_t* >( get_export( m_ntoskrnl_base, oxorany( "HalPrivateDispatchTable" ) ) );
            if ( !hal_private_dispatch )
                return { };
        }

        return hal_private_dispatch;
    }

    std::uint8_t* get_ki_cpu_tracing_flags( ) {
        std::uint8_t* ki_cpu_tracing_flags_ptr = nullptr;
        if ( !ki_cpu_tracing_flags_ptr ) {
            auto ke_bug_check_ex = get_export( m_ntoskrnl_base, oxorany( "KeBugCheckEx" ) );
            if ( !ke_bug_check_ex ) {
                return { };
            }

            std::uint64_t ki_cpu_tracing_flags = ke_bug_check_ex;
            while ( *reinterpret_cast< unsigned short* >( ki_cpu_tracing_flags ) != 0xE800 ) ki_cpu_tracing_flags++; ki_cpu_tracing_flags += 2;
            while ( *reinterpret_cast< unsigned short* >( ki_cpu_tracing_flags ) != 0xE800 ) ki_cpu_tracing_flags++; ki_cpu_tracing_flags++;
            ki_cpu_tracing_flags = ( ki_cpu_tracing_flags + 5 ) + *reinterpret_cast< int* >( ki_cpu_tracing_flags + 1 );
            while ( *reinterpret_cast< unsigned short* >( ki_cpu_tracing_flags ) != 0x05F7 ) ki_cpu_tracing_flags++;
            ki_cpu_tracing_flags = ( ki_cpu_tracing_flags + 10 ) + *reinterpret_cast< int* >( ki_cpu_tracing_flags + 2 );
            ki_cpu_tracing_flags_ptr = reinterpret_cast< std::uint8_t* >( ki_cpu_tracing_flags );
            if ( !ki_cpu_tracing_flags_ptr ) {
                return { };
            }
        }

        return ki_cpu_tracing_flags_ptr;
    }


    void ke_initialize_event( kevent_t* event, long type, bool state ) {
        static auto ke_initialize_event = 0ull;
        if ( !ke_initialize_event ) {
            ke_initialize_event = get_export( m_ntoskrnl_base, oxorany( "KeInitializeEvent" ) );
            if ( !ke_initialize_event ) return;
        }

        using function_t = void( kevent_t*, long, bool );
        reinterpret_cast< function_t* >( ke_initialize_event )( event, type, state );
    }

    void mm_free_independent_pages( std::uint64_t independent_pages, std::size_t size ) {
        static auto mm_free_independent_pages = 0ull;
        if ( !mm_free_independent_pages ) {
            mm_free_independent_pages = m_pdb.m_mm_free_independent_pages;
            if ( !mm_free_independent_pages )
                return;
        }

        using function_t = void( std::uint64_t, int );
        reinterpret_cast< function_t* >( mm_free_independent_pages )( independent_pages, size );
    }

    void ke_clear_event( kevent_t* event ) {
        static auto ke_clear_event = 0ull;
        if ( !ke_clear_event ) {
            ke_clear_event = get_export( m_ntoskrnl_base, oxorany( "KeClearEvent" ) );
            if ( !ke_clear_event ) return;
        }

        using function_t = void( kevent_t* );
        reinterpret_cast< function_t* >( ke_clear_event )( event );
    }

    eprocess_t* io_get_current_process( ) {
        static auto io_get_current_process = 0ull;
        if ( !io_get_current_process ) {
            io_get_current_process = get_export( m_ntoskrnl_base, oxorany( "IoGetCurrentProcess" ) );
            if ( !io_get_current_process ) return {};
        }

        using function_t = eprocess_t * ( );
        return reinterpret_cast< function_t* >( io_get_current_process )( );
    }

    bool mm_set_page_protection( std::uint64_t virtual_address, std::size_t size, std::uint64_t protection ) {
        static std::uint64_t mm_set_page_protection = 0ull;
        if ( !mm_set_page_protection ) {
            mm_set_page_protection = m_pdb.m_mm_set_page_protection;
            if ( !mm_set_page_protection )
                return static_cast< nt_status_t >( -1 );
        }

        using function_t = bool( __stdcall* )( std::uint64_t, std::size_t, std::uint64_t );
        return reinterpret_cast< function_t >( mm_set_page_protection )( virtual_address, size, protection );
    }

    __int64 __fastcall mi_lock_page_table_page( mmpfn_t* pfn_entry, int a2 ) {
        static auto mi_lock_page_table_page = 0ull;
        if ( !mi_lock_page_table_page ) {
            mi_lock_page_table_page = m_pdb.m_mi_lock_page_table_page;
            if ( !mi_lock_page_table_page )
                return 0;
        }

        using function_t = __int64( mmpfn_t*, int );
        return reinterpret_cast< function_t* >( mi_lock_page_table_page )( pfn_entry, a2 );
    }

    char mi_is_page_on_bad_list( mmpfn_t* pfn_entry ) {
        static auto mi_is_page_on_bad_list = 0ull;
        if ( !mi_is_page_on_bad_list ) {
            mi_is_page_on_bad_list = m_pdb.m_mi_is_page_on_bad_list;
            if ( !mi_is_page_on_bad_list )
                return 0;
        }

        using function_t = char( __stdcall* )( mmpfn_t* );
        return reinterpret_cast< function_t >( mi_is_page_on_bad_list )( pfn_entry );
    }

    char mi_make_page_bad( mmpfn_t* pfn_entry, char lock ) {
        static auto mi_make_page_bad = 0ull;
        if ( !mi_make_page_bad ) {
            mi_make_page_bad = m_pdb.m_mi_make_page_bad;
            if ( !mi_make_page_bad )
                return 0;
        }

        using function_t = char( __stdcall* )( mmpfn_t*, char );
        return reinterpret_cast< function_t >( mi_make_page_bad )( pfn_entry, lock );
    }

    std::uint64_t get_psp_cid_table( ) {
        static std::uint8_t* export_address = nullptr;
        if ( !export_address ) {
            export_address = reinterpret_cast< std::uint8_t* >(
                m_pdb.m_psp_thread_delete );
            if ( !export_address ) return 0;
        }

        auto ptr = export_address;
        while ( ptr[ 0 ] != 0x48 || ptr[ 1 ] != 0x8B || ptr[ 2 ] != 0x0D )
            ptr++;

        return *reinterpret_cast< std::uint64_t* >(
            &ptr[ 7 ] + *reinterpret_cast< std::int32_t* >( &ptr[ 3 ] ) );
    }

    std::uint64_t get_pool_big_page_table( ) {
        static std::uint8_t* export_address = nullptr;
        if ( !export_address ) {
            export_address = reinterpret_cast< std::uint8_t* >(
                m_pdb.m_ex_query_big_pool_tag );
            if ( !export_address ) return 0;
        }
        auto ptr = export_address;
        while ( !( ( ptr[ 0 ] == 0x48 || ptr[ 0 ] == 0x4C )
            && ( ptr[ 1 ] == 0x8B )
            && ( ptr[ 2 ] == 0x1D || ptr[ 2 ] == 0x0D ) ) )
            ptr++;
        return *reinterpret_cast< std::uint64_t* >(
            ptr + 7 + *reinterpret_cast< std::int32_t* >( ptr + 3 ) );
    }

    std::uint32_t get_pool_big_page_table_size( ) {
        static std::uint8_t* export_address = nullptr;
        if ( !export_address ) {
            export_address = reinterpret_cast< std::uint8_t* >(
                m_pdb.m_ex_query_big_pool_tag );
            if ( !export_address ) return 0;
        }
        auto ptr = export_address;
        while ( !( ( ptr[ 0 ] == 0x48 || ptr[ 0 ] == 0x4C )
            && ( ptr[ 1 ] == 0x8B )
            && ( ptr[ 2 ] == 0x0B || ptr[ 2 ] == 0x0D ) ) )
            ptr++;
        return *reinterpret_cast< std::uint32_t* >(
            ptr + 6 + *reinterpret_cast< std::int32_t* >( ptr + 2 ) );
    }

    eprocess_t* ps_initial_system_process( ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "PsInitialSystemProcess" ) );
            if ( !export_address ) return {};
        }

        return *reinterpret_cast< eprocess_t** >( export_address );
    }

    physical_memory_range_t* mm_get_physical_memory_ranges( ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "MmGetPhysicalMemoryRanges" ) );
            if ( !export_address ) return nullptr;
        }

        using function_t = physical_memory_range_t * ( void );
        return reinterpret_cast< function_t* >( export_address )( );
    }

    mmpfn_t* get_mm_pfn_database( ) {
        static std::uint8_t* export_address = 0ull;
        if ( !export_address ) {
            export_address = reinterpret_cast< std::uint8_t* >(
                get_export( m_ntoskrnl_base, oxorany( "KeCapturePersistentThreadState" ) ) );
            if ( !export_address ) return { };
        }

        while ( export_address[ 0x0 ] != 0x48
            || export_address[ 0x1 ] != 0x8B
            || export_address[ 0x2 ] != 0x05 )
            export_address++;

        return *reinterpret_cast< mmpfn_t** >(
            &export_address[ 0x7 ] + *reinterpret_cast< std::int32_t* >( &export_address[ 0x3 ] ) );
    }

    void* mm_get_virtual_for_physical( std::uintptr_t phys_addr ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "MmGetVirtualForPhysical" ) );
            if ( !export_address ) return nullptr;
        }

        using function_t = void* ( * )( std::uintptr_t physical_address );
        return reinterpret_cast< function_t >( export_address )( phys_addr );
    }

    physical_address_t mm_get_physical_address( void* virtual_address ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "MmGetPhysicalAddress" ) );
            if ( !export_address ) return { };
        }

        using function_t = physical_address_t( * )( void* virtual_address );
        return reinterpret_cast< function_t >( export_address )( virtual_address );
    }

    std::uint32_t ke_get_current_processor_number( ) {
        static auto fn_ke_get_current_processor_number = 0ull;
        if ( !fn_ke_get_current_processor_number ) {
            fn_ke_get_current_processor_number = get_export( m_ntoskrnl_base, oxorany( "KeGetCurrentProcessorNumberEx" ) );
            if ( !fn_ke_get_current_processor_number ) return {};
        }

        using function_t = std::uint32_t( __int64 );
        return reinterpret_cast< function_t* >( fn_ke_get_current_processor_number )( 0 );
    }

    void* mm_allocate_independent_pages( std::size_t size ) {
        static auto mm_allocate_independent_pages = 0ull;
        if ( !mm_allocate_independent_pages ) {
            mm_allocate_independent_pages = m_pdb.m_mm_allocate_independent_pages;
            if ( !mm_allocate_independent_pages )
                return nullptr;
        }

        using function_t = void* ( std::uint64_t, int, std::uint64_t, unsigned int );
        return reinterpret_cast< function_t* >( mm_allocate_independent_pages )( size, -1, 0, 0 );
    }

    void* ex_allocate_pool_with_tag( std::uint32_t pool_type, std::size_t number_of_bytes, std::uint32_t tag ) {
        static std::uint64_t export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "ExAllocatePoolWithTag" ) );
            if ( !export_address ) return { };
        }

        using function_t = void* ( * )( std::uint32_t, std::size_t, std::uint32_t );
        return reinterpret_cast< function_t >( export_address )( pool_type, number_of_bytes, tag );
    }

    void ex_initialize_rundown_protection( void* rundown_ref ) {
        static std::uint64_t export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "ExInitializeRundownProtection" ) );
            if ( !export_address ) return;
        }

        using function_t = void( * )( void* );
        reinterpret_cast< function_t >( export_address )( rundown_ref );
    }

    bool ex_acquire_rundown_protection( void* rundown_ref ) {
        static std::uint64_t export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "ExAcquireRundownProtection" ) );
            if ( !export_address ) return false;
        }

        using function_t = bool( * )( void* );
        return reinterpret_cast< function_t >( export_address )( rundown_ref );
    }

    void ex_release_rundown_protection( void* rundown_ref ) {
        static std::uint64_t export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "ExReleaseRundownProtection" ) );
            if ( !export_address ) return;
        }

        using function_t = void( * )( void* );
        reinterpret_cast< function_t >( export_address )( rundown_ref );
    }

    nt_status_t ex_subscribe_wnf_state_change(
        PVOID* wnfStruct,
        PCWNF_STATE_NAME stateName,
        ULONG eventMask,
        PULONG changeStamp,
        PVOID callback,
        PVOID callbackContext ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "ExSubscribeWnfStateChange" ) );
            if ( !export_address ) return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( * )(
            PVOID*,
            PCWNF_STATE_NAME,
            ULONG,
            PULONG,
            PVOID,
            PVOID
            );

        return reinterpret_cast< function_t >( export_address )(
            wnfStruct,
            stateName,
            eventMask,
            changeStamp,
            callback,
            callbackContext
            );
    }

    nt_status_t ex_unsubscribe_wnf_state_change( void* wnf_handle ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "ExUnsubscribeWnfStateChange" ) );
            if ( !export_address ) return {};
        }

        using function_t = nt_status_t( void* );
        return reinterpret_cast< function_t* >( export_address )( wnf_handle );
    }

    void rtl_init_unicode_string( unicode_string_t* destination_string, const wchar_t* source_string ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "RtlInitUnicodeString" ) );
            if ( !export_address ) return;
        }

        using fn_t = void( * )( unicode_string_t*, const wchar_t* );
        reinterpret_cast< fn_t >( export_address )( destination_string, source_string );
    }

    nt_status_t cm_register_callback_ex(
        ex_callback_function_t callback_function,
        unicode_string_t altitude,
        ularge_integer_t* cookie
    ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "CmRegisterCallbackEx" ) );
            if ( !export_address ) return {};
        }

        using function_t = nt_status_t(
            ex_callback_function_t callback_function,
            unicode_string_t* altitude,
            void* driver,
            void* context,
            ularge_integer_t* cookie,
            std::uint64_t reserved
        );

        return reinterpret_cast< function_t* >( export_address )(
            callback_function,
            &altitude,
            reinterpret_cast< void* >( 1 ),
            nullptr,
            cookie,
            0
            );
    }

    eprocess_t* ps_lookup_process_by_pid( std::uint32_t process_id ) {
        static void* export_address = nullptr;
        if ( !export_address ) {
            export_address = reinterpret_cast< void* >(
                kernel::get_export(
                    m_ntoskrnl_base,
                    oxorany( "PsLookupProcessByProcessId" )
                )
                );

            if ( !export_address )
                return nullptr;
        }

        eprocess_t* process = nullptr;
        using function_t = nt_status_t( * )( HANDLE process_id, eprocess_t** process );
        auto status = reinterpret_cast< function_t >( export_address )(
            reinterpret_cast< HANDLE >( process_id ),
            &process
            );

        if ( !status ) {
            return process;
        }

        return nullptr;
    }


    mdl_t* io_allocate_mdl(
        void* virtual_address,
        std::size_t length,
        bool secondary_buffer,
        bool charge_quota,
        iop_irp_t* irp
    ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "IoAllocateMdl" ) );
            if ( !export_address ) return {};
        }

        using function_t = mdl_t * (
            void* virtual_address,
            std::size_t length,
            bool secondary_buffer,
            bool charge_quota,
            iop_irp_t* irp
            );

        return reinterpret_cast< function_t* >( export_address ) (
            virtual_address,
            length,
            secondary_buffer,
            charge_quota,
            irp );
    }

    void mm_build_mdl_for_non_paged_pool(
        mdl_t* mdl
    ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "MmBuildMdlForNonPagedPool" ) );
            if ( !export_address ) return;
        }

        using function_t = void(
            mdl_t* mdl
            );

        reinterpret_cast< function_t* >( export_address ) ( mdl );
    }

    void* mm_map_locked_pages(
        mdl_t* mdl,
        std::uint8_t access_mode
    ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "MmMapLockedPages" ) );
            if ( !export_address ) return {};
        }

        using function_t = void* (
            mdl_t* mdl,
            std::uint8_t access_mode
            );

        return reinterpret_cast< function_t* >( export_address ) (
            mdl,
            access_mode );
    }

    void mm_probe_and_lock_pages(
        mdl_t* mdl,
        std::uint8_t access_mode,
        std::uint32_t operation
    ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "MmProbeAndLockPages" ) );
            if ( !export_address ) return;
        }

        using function_t = void(
            mdl_t* mdl,
            std::uint8_t access_mode,
            std::uint32_t operation
            );

        reinterpret_cast< function_t* >( export_address ) (
            mdl,
            access_mode,
            operation );
    }

    void* mm_map_locked_pages_specify_cache( mdl_t* mdl,
        std::uint8_t access_mode,
        std::uint32_t cache_type,
        void* base_address,
        bool bug_check_on_failure,
        std::uint32_t priority
    ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "MmMapLockedPagesSpecifyCache" ) );
            if ( !export_address ) return {};
        }

        using function_t = void* (
            mdl_t* mdl,
            std::uint8_t access_mode,
            std::uint32_t cache_type,
            void* base_address,
            bool bug_check_on_failure,
            std::uint32_t priority
            );

        return reinterpret_cast< function_t* >( export_address ) (
            mdl,
            access_mode,
            cache_type,
            base_address,
            bug_check_on_failure,
            priority );
    }


    long ke_release_semaphore(
        ksemaphore_t* semaphore,
        long increment,
        long adjustment,
        bool wait
    ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "KeReleaseSemaphore" ) );
            if ( !export_address ) return {};
        }

        using function_t = long ( * )(
            ksemaphore_t*,
            long,
            long,
            bool
            );

        return reinterpret_cast< function_t >( export_address )(
            semaphore,
            increment,
            adjustment,
            wait
            );
    }

    nt_status_t ob_reference_object_by_handle(
        void* handle,
        std::uint32_t desired_access,
        void* object_type,
        std::uint8_t access_mode,
        void** object,
        void* handle_information
    ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "ObReferenceObjectByHandle" ) );
            if ( !export_address ) return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( * )(
            void*,
            std::uint32_t,
            void*,
            std::uint8_t,
            void**,
            void*
            );

        return reinterpret_cast< function_t >( export_address )(
            handle,
            desired_access,
            object_type,
            access_mode,
            object,
            handle_information
            );
    }

    nt_status_t mm_protect_mdl_system_address( mdl_t* mdl, std::uint32_t new_protect ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "MmProtectMdlSystemAddress" ) );
            if ( !export_address ) return {};
        }
        using function_t = nt_status_t(
            mdl_t* mdl,
            std::uint32_t new_protect
        );

        return reinterpret_cast< function_t* >( export_address ) (
            mdl,
            new_protect );
    }

    void mm_unmap_locked_pages( void* base_address, mdl_t* mdl ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "MmUnmapLockedPages" ) );
            if ( !export_address ) return;
        }
        using function_t = void(
            void* base_address,
            mdl_t* mdl
            );
        reinterpret_cast< function_t* >( export_address ) (
            base_address,
            mdl );
    }

    void mm_unlock_pages( mdl_t* mdl ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "MmUnlockPages" ) );
            if ( !export_address ) return;
        }
        using function_t = void( mdl_t* mdl );
        reinterpret_cast< function_t* >( export_address )( mdl );
    }

    void io_free_mdl( mdl_t* mdl ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "IoFreeMdl" ) );
            if ( !export_address ) return;
        }
        using function_t = void( mdl_t* mdl );
        reinterpret_cast< function_t* >( export_address )( mdl );
    }

    nt_status_t ke_wait_for_single_object(
        void* object,
        long wait_reason,
        long wait_mode,
        bool alertable,
        int wait_duration
    ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "KeWaitForSingleObject" ) );
            if ( !export_address ) return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( * )(
            void*,
            long,
            long,
            bool,
            ularge_integer_t*
            );

        ularge_integer_t timeout{ };
        timeout.m_quad_part = wait_duration * -10000i64;
        return reinterpret_cast< function_t >( export_address )(
            object,
            wait_reason,
            wait_mode,
            alertable,
            &timeout
            );
    }

    std::uint64_t mm_user_probe_address( ) {
        static auto mm_user_probe_address = 0ull;
        if ( !mm_user_probe_address ) {
            mm_user_probe_address = get_export( m_ntoskrnl_base, oxorany( "MmUserProbeAddress" ) );
            if ( !mm_user_probe_address ) return nt_status_t::unsuccessful;
        }

        return *reinterpret_cast< std::uint64_t* >( mm_user_probe_address );
    }

    std::uint64_t mm_system_range_start( ) {
        static auto mm_system_range_start = 0ull;
        if ( !mm_system_range_start ) {
            mm_system_range_start = get_export( m_ntoskrnl_base, oxorany( "MmSystemRangeStart" ) );
            if ( !mm_system_range_start ) return nt_status_t::unsuccessful;
        }

        return *reinterpret_cast< std::uint64_t* >( mm_system_range_start );
    }

    list_entry_t* ps_active_process_head( ) {
        static list_entry_t* ps_active_process_head = nullptr;
        if ( !ps_active_process_head ) {
            static std::uint8_t* export_address;
            if ( !export_address ) {
                export_address = reinterpret_cast< std::uint8_t* >(
                    get_export( m_ntoskrnl_base, oxorany( "KeCapturePersistentThreadState" ) )
                    );
                if ( !export_address ) return {};
            }

            while ( export_address[ 0x0 ] != 0x20
                || export_address[ 0x1 ] != 0x48
                || export_address[ 0x2 ] != 0x8d )
                export_address++;

            ps_active_process_head = *reinterpret_cast< list_entry_t** >
                ( &export_address[ 0x8 ] + *reinterpret_cast< std::int32_t* >( &export_address[ 0x4 ] ) );
        }

        return ps_active_process_head;
    }

    std::uint32_t get_section_base_address_offset( ) {
        static std::uint32_t section_base_address_offset = 0;
        if ( !section_base_address_offset ) {
            auto ps_get_process_section_base_address = reinterpret_cast< std::uint8_t* >(
                get_export( m_ntoskrnl_base, oxorany( "PsGetProcessSectionBaseAddress" ) )
                );

            if ( !ps_get_process_section_base_address )
                return { };

            while ( !( ps_get_process_section_base_address[ 0 ] == 0x48 ||
                ps_get_process_section_base_address[ 1 ] == 0x8B ||
                ps_get_process_section_base_address[ 2 ] == 0x81 ) )
                ps_get_process_section_base_address++;

            section_base_address_offset = *reinterpret_cast< std::uint32_t* >( ps_get_process_section_base_address + 3 );
        }

        return section_base_address_offset;
    }

    std::uint32_t get_process_id_offset( ) {
        static std::uint32_t process_id_offset = 0;
        if ( !process_id_offset ) {
            auto ps_get_process_id = reinterpret_cast< std::uint8_t* >(
                get_export( m_ntoskrnl_base, oxorany( "PsGetProcessId" ) )
                );

            if ( !ps_get_process_id )
                return { };

            while ( !( ps_get_process_id[ 0 ] == 0x48 ||
                ps_get_process_id[ 1 ] == 0x8B ||
                ps_get_process_id[ 2 ] == 0x81 ) )
                ps_get_process_id++;

            process_id_offset = *reinterpret_cast< std::uint32_t* >( ps_get_process_id + 3 );
        }

        return process_id_offset;
    }

    std::uint32_t get_process_peb_offset( ) {
        static std::uint32_t process_peb_offset = 0;
        if ( !process_peb_offset ) {
            auto ps_get_process_peb = reinterpret_cast< std::uint8_t* >(
                get_export( m_ntoskrnl_base, oxorany( "PsGetProcessPeb" ) )
                );

            if ( !ps_get_process_peb )
                return { };

            while ( !( ps_get_process_peb[ 0 ] == 0x48 ||
                ps_get_process_peb[ 1 ] == 0x8B ||
                ps_get_process_peb[ 2 ] == 0x81 ) )
                ps_get_process_peb++;

            process_peb_offset = *reinterpret_cast< std::uint32_t* >( ps_get_process_peb + 3 );
        }

        return process_peb_offset;
    }

    void ex_acquire_push_lock_exclusive( std::uint64_t push_lock ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "ExAcquirePushLockExclusiveEx" ) );
            if ( !export_address ) return;
        }

        using function_t = void( * )( std::uint64_t, std::uint32_t );
        reinterpret_cast< function_t >( export_address )( push_lock, 0 );
    }

    void ex_release_push_lock_exclusive( std::uint64_t push_lock ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "ExReleasePushLockExclusiveEx" ) );
            if ( !export_address ) return;
        }

        using function_t = void( * )( std::uint64_t, std::uint32_t );
        reinterpret_cast< function_t >( export_address )( push_lock, 0 );
    }

    nt_status_t zw_free_virtual_memory(
        HANDLE process_handle,
        void** base_address,
        SIZE_T* region_size,
        ULONG free_type ) {
        static auto fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( m_ntoskrnl_base, oxorany( "ZwFreeVirtualMemory" ) );
            if ( !fn_address ) return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( HANDLE, void**, PSIZE_T, ULONG );
        return reinterpret_cast< function_t* >( fn_address )(
            process_handle,
            base_address,
            region_size,
            free_type
            );
    }

    template<class... args_t>
    std::int8_t dbg_print( const char* format, args_t... va_args ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "DbgPrintEx" ) );
            if ( !export_address ) return 0;
        }

        using function_t = std::int32_t( std::uint32_t flag, std::uint32_t level,
            const char* format, args_t... va_args );
        return reinterpret_cast< function_t* >( export_address )( 0, 0, format, va_args... ) ==
            nt_status_t::success;
    }
}