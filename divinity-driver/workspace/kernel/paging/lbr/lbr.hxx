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
        if ( !target_process || !kernel::mm_is_address_valid( target_process ) )
            return 0;

        auto dtb = target_process->m_pcb.m_directory_table_base;
        auto user_dtb_offset = kernel::m_offsets.m_user_directory_table_base;
        if ( user_dtb_offset ) {
            auto user_dtb = *reinterpret_cast< std::uint64_t* >(
                reinterpret_cast< std::uint64_t >( target_process ) + user_dtb_offset );
            if ( user_dtb )
                dtb = user_dtb;
        }
        else {
            auto legacy_user_dtb = *reinterpret_cast< std::uint64_t* >(
                reinterpret_cast< std::uint64_t >( target_process ) + 0x280 );
            if ( legacy_user_dtb )
                dtb = legacy_user_dtb;
        }

        if ( !dtb )
            return 0;

        return dtb & ~0xFFFull;
    }
}
