#pragma once

namespace hide {
    mmvad_short_t* find_vad( eprocess_t* process, std::uint64_t va ) {
        auto vad_root = reinterpret_cast< rtl_avl_tree_t* >(
            reinterpret_cast< std::uint8_t* >( process ) + 0x7d8 );

        auto node = reinterpret_cast< mmvad_short_t* >( vad_root->m_root );
        if ( !node )
            return nullptr;

        const auto target_vpn = va >> paging::page_shift;

        while ( node ) {
            if ( node->m_vad_node.m_parent_value == static_cast< std::uintptr_t >( -2 ) )
                return nullptr;

            const auto start_vpn =
                ( static_cast< std::uint64_t >( node->m_starting_vpn_high ) << 32 )
                | node->m_starting_vpn;

            const auto end_vpn =
                ( static_cast< std::uint64_t >( node->m_ending_vpn_high ) << 32 )
                | node->m_ending_vpn;

            if ( target_vpn < start_vpn ) {
                node = reinterpret_cast< mmvad_short_t* >( node->m_vad_node.m_left );
            }
            else if ( target_vpn > end_vpn ) {
                node = reinterpret_cast< mmvad_short_t* >( node->m_vad_node.m_right );
            }
            else {
                return node;
            }
        }

        return nullptr;
    }

    template <typename va_t>
    bool hide_pages( va_t address, std::size_t size, bool lock_page = false ) {
        const auto page_mask = paging::page_4kb_size - 1;
        const auto aligned_size = ( size + page_mask ) & ~page_mask;
        const auto page_count = aligned_size >> paging::page_shift;

        const auto va = reinterpret_cast< std::uint64_t >( ( void* )address );
        for ( auto idx = 0; idx < page_count; ++idx ) {
            const auto current_va = va + ( idx << paging::page_shift );
            const auto current_pa = phys::virtual_to_physical( current_va );
            if ( !current_pa )
                continue;

            auto pfn_entry = phys::get_pfn_entry( current_pa >> paging::page_shift );
            if ( !pfn_entry )
                continue;

            if ( lock_page ) {
                if ( !kernel::mi_lock_page_table_page( pfn_entry, 3 ) ) {
                    return false;
                }
            }
            else {
                //if ( kernel::mi_make_page_bad( pfn_entry, 2 ) ) {
                //    if ( kernel::mi_is_page_on_bad_list( pfn_entry ) ) {
                //        pfn_entry->m_u4.m_file_only = 1;
                //    }
                //}

                pfn_entry->m_u3.m_e3.parity_error = 1;
            }
        }

        return true;
    }

    template <typename va_t>
    bool hide_vad( eprocess_t* process, va_t address ) {
        const auto va = reinterpret_cast< std::uint64_t >( ( void* )address );
        if ( !va || !process )
            return false;

        auto vad = find_vad( process, va );
        if ( !vad ) {
            kernel::dbg_print( oxorany( "[vad] no VAD found for 0x%llx\n" ), va );
            return false;
        }

        const auto org_process = process::attach( process );
        ExAcquirePushLockExclusive(
            reinterpret_cast< PEX_PUSH_LOCK >( &vad->m_push_lock ) );

        kernel::mi_remove_vad( vad, process );

        ExReleasePushLockExclusive(
            reinterpret_cast< PEX_PUSH_LOCK >( &vad->m_push_lock ) );
        process::attach( org_process );

        kernel::dbg_print( oxorany( "[vad] node 0x%llx removed\n" ), vad );
        return true;
    }

    bool hide_big_pool( std::uint64_t va ) {
        if ( !va ) return false;

        //auto table = kernel::get_pool_big_page_table( );
        //auto table_size = kernel::get_pool_big_page_table_size( );
        //if ( !table || !table_size )
        //    return false;

        //for ( auto idx = 0; idx < table_size; idx++ ) {
        //    auto entry = reinterpret_cast< pool_big_page_entry_t* >( table + idx * 0x18 );
        //    if ( entry->va & 1 )
        //        continue;

        //    if ( va >= entry->va && va < entry->va + entry->size ) {
        //        entry->va = 1;
        //        entry->tag = 0;
        //        entry->size = 0;
        //        return true;
        //    }
        //}

        return true;
    }
}