#pragma once

namespace hook {
    paging::pth::hook_state_t m_hook_state;

    struct process_ctx_t {
        eprocess_t* m_target_process;
        std::uint64_t m_target_cr3;
    };

    namespace lbr {
        kevent_t m_event;
        bool ( *m_callback )( void* ) = nullptr;
        void* m_context = nullptr;

        std::uint8_t( *hal_clear_last_branch_record_stack_org )( ) = nullptr;
        std::uint8_t __fastcall hal_clear_last_branch_record_stack_hk( ) {
            if ( !m_callback || !m_context )
                return hal_clear_last_branch_record_stack_org( );

            if ( m_callback( m_context ) )
                kernel::ke_set_event( &m_event, 0, false );

            return hal_clear_last_branch_record_stack_org( );
        }

        bool install_hook( ) {
            auto hal_dispatch = kernel::get_hal_private_dispatch( );
            if ( !hal_dispatch )
                return false;

            auto hal_clear_last_branch_record_stack = reinterpret_cast< std::uint64_t >(
                hal_dispatch->m_hal_clear_last_branch_record_stack
                );
            if ( !hal_clear_last_branch_record_stack )
                return false;

            if ( !paging::pth::create(
                hal_clear_last_branch_record_stack,
                hal_clear_last_branch_record_stack_hk,
                &hal_clear_last_branch_record_stack_org,
                &m_hook_state
            ) ) return false;

            if ( auto* cpu_tracing_flags = kernel::get_ki_cpu_tracing_flags( ) )
                *cpu_tracing_flags = 2;

            return true;
        }

        bool uninstall_hook( ) {
            if ( hal_clear_last_branch_record_stack_org ) {
                auto hal_dispatch = kernel::get_hal_private_dispatch( );
                if ( !hal_dispatch )
                    return false;

                auto target_fn = reinterpret_cast< std::uint64_t >(
                    hal_dispatch->m_hal_clear_last_branch_record_stack
                    );

                if ( !target_fn )
                    return false;

                if ( !paging::pth::remove( target_fn, m_hook_state ) )
                    return false;
            }

            if ( auto* flags = kernel::get_ki_cpu_tracing_flags( ) )
                *flags = 0;

            return true;
        }
    }
}

namespace process {
    std::uint64_t get_directory_table_base( eprocess_t* target_process ) {
        auto* ctx = reinterpret_cast< hook::process_ctx_t* >(
            mmu::alloc_kva( paging::page_4kb_size ) );
        if ( !ctx )
            return 0;

        ctx->m_target_process = target_process;
        ctx->m_target_cr3 = 0;

        kernel::ke_initialize_event( &hook::lbr::m_event, 1, false );
        hook::lbr::m_context = ctx;
        hook::lbr::m_callback = [ ] ( void* data ) -> bool {
            if ( !data ) return false;
            auto* ctx = reinterpret_cast< hook::process_ctx_t* >( data );
            if ( ctx->m_target_process == kernel::io_get_current_process( ) ) {
                ctx->m_target_cr3 = __readcr3( );
                return true;
            }
            return false;
            };

        if ( !hook::lbr::install_hook( ) ) {
            memset( ctx, 0, paging::page_4kb_size );
            mmu::free_kva( reinterpret_cast< std::uint64_t >( ctx ), paging::page_4kb_size );
            return 0;
        }

        auto result = kernel::ke_wait_for_single_object(
            &hook::lbr::m_event, 0, 0, false, 20000 );

        hook::lbr::uninstall_hook( );
        hook::lbr::m_callback = nullptr;

        auto target_cr3 = ctx->m_target_cr3;

        kernel::ke_clear_event( &hook::lbr::m_event );

        memset( ctx, 0, paging::page_4kb_size );
        mmu::free_kva( reinterpret_cast< std::uint64_t >( ctx ), paging::page_4kb_size );

        if ( result == nt_status_t::timeout )
            return 0;

        return target_cr3;
    }
}