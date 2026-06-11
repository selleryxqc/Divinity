#pragma once

namespace paging {
    namespace hyperspace {
        void cleanup_callback( void* parent_id, void* process_id, bool create );

        struct hyperspace_mapping_t {
            std::uint64_t m_target_va;
            std::uint64_t m_hyperspace_va;
            std::size_t   m_hyperspace_size;
            std::uint32_t m_hyperspace_pml4;
            std::uint64_t m_client_dtb;
            std::uint64_t m_target_dtb;
            bool          m_active;
        };

        struct hyperspace_entry_t {
            eprocess_t*          m_orig_process;
            eprocess_t*          m_clone_process;
            std::uint64_t        m_clone_base;
            std::uint64_t        m_pml4_pa;
            std::uint64_t        m_hyperspace_cr3;
            std::uint64_t        m_hyperspace_va;
            hyperspace_mapping_t m_hyperspace_mapping;
            bool                 m_active;
        };

        constexpr std::uint32_t max_entries = 512;
        hyperspace_entry_t m_entries[ max_entries ] = {};

        std::int32_t find_entry( eprocess_t* process ) {
            for ( auto i = 0; i < max_entries; i++ ) {
                if ( m_entries[ i ].m_active && m_entries[ i ].m_orig_process == process )
                    return i;
            }
            return -1;
        }

        std::int32_t find_free_slot( ) {
            for ( auto i = 0; i < max_entries; i++ ) {
                if ( !m_entries[ i ].m_active )
                    return i;
            }
            return -1;
        }

        std::uint32_t find_free_pml4_index(
            const std::uint64_t* dtbs,
            std::uint32_t        dtb_count,
            bool                 high_address = false
        ) {
            const auto range_start = high_address ? 256 : 1;
            const auto range_end   = high_address ? 512 : 256;

            for ( auto idx = range_start; idx < range_end; idx++ ) {
                bool conflict = false;

                for ( auto j = 0; j < dtb_count; j++ ) {
                    if ( !dtbs[ j ] ) continue;

                    pml4e entry{ };
                    if ( dpm::read_physical( dtbs[ j ] + ( idx * sizeof( pml4e ) ),
                        &entry, sizeof( pml4e ) ) && entry.hard.present ) {
                        conflict = true;
                        break;
                    }
                }

                if ( !conflict )
                    return idx;
            }

            return static_cast< std::uint32_t >( -1 );
        }

        void zero_pml4_index(
            std::uint32_t        pml4_index,
            const std::uint64_t* dtbs,
            std::uint32_t        dtb_count
        ) {
            pml4e zero{ };
            for ( std::uint32_t i = 0; i < dtb_count; i++ ) {
                if ( !dtbs[ i ] ) continue;
                dpm::write_physical( dtbs[ i ] + ( pml4_index * sizeof( pml4e ) ),
                    &zero, sizeof( pml4e ) );
            }
        }

        bool mirror_pml4_index(
            std::uint32_t        pml4_index,
            std::uint64_t        src_dtb,
            const std::uint64_t* dst_dtbs,
            std::uint32_t        dst_count
        ) {
            pml4e entry{ };
            if ( !dpm::read_physical( src_dtb + ( pml4_index * sizeof( pml4e ) ),
                &entry, sizeof( pml4e ) ) || !entry.hard.present )
                return false;

            for ( std::uint32_t i = 0; i < dst_count; i++ ) {
                if ( !dst_dtbs[ i ] ) continue;
                dpm::write_physical( dst_dtbs[ i ] + ( pml4_index * sizeof( pml4e ) ),
                    &entry, sizeof( pml4e ) );
            }

            return true;
        }

        bool clone_process( eprocess_t* target_process ) {
            if ( find_entry( target_process ) != -1 ) {
                kernel::dbg_print( oxorany( "[divinity] already cloned, skipping\n" ) );
                return true;
            }

            auto slot = find_free_slot( );
            if ( slot == -1 )
                return false;

            auto org_pml4_pa = process::get_directory_table_base( target_process );
            if ( !org_pml4_pa )
                return false;

            auto pml4_va = mmu::alloc_kva( page_4kb_size );
            if ( !pml4_va )
                return false;

            auto pml4_pa = phys::virtual_to_physical( pml4_va );
            if ( !pml4_pa ) {
                mmu::free_kva( pml4_va, page_4kb_size );
                return false;
            }

            if ( !dpm::read_physical( org_pml4_pa, reinterpret_cast< void* >( pml4_va ), page_4kb_size ) ) {
                memset( reinterpret_cast< void* >( pml4_va ), 0, page_4kb_size );
                mmu::free_kva( pml4_va, page_4kb_size );
                return false;
            }

            auto* entries = reinterpret_cast< pml4e* >( pml4_va );
            memset( entries, 0, 256 * sizeof( pml4e ) );

            auto org_cr3 = paging::swap_context( org_pml4_pa );
            auto self_reference_idx = paging::get_pml4_self_reference( );
            paging::swap_context( org_cr3 );

            if ( self_reference_idx == -1 ) {
                memset( reinterpret_cast< void* >( pml4_va ), 0, page_4kb_size );
                mmu::free_kva( pml4_va, page_4kb_size );
                return false;
            }

            entries[ self_reference_idx ].hard.pfn = pml4_pa >> 12;

            const auto orig_page = ( reinterpret_cast< std::uintptr_t >( target_process ) >> 12 ) << 12;
            const auto offset = reinterpret_cast< std::uintptr_t >( target_process ) & 0xFFF;

            auto clone_base = mmu::alloc_kva( page_4kb_size );
            if ( !clone_base ) {
                memset( reinterpret_cast< void* >( pml4_va ), 0, page_4kb_size );
                mmu::free_kva( pml4_va, page_4kb_size );
                return false;
            }

            std::memcpy(
                reinterpret_cast< void* >( clone_base ),
                reinterpret_cast< void* >( orig_page ),
                page_4kb_size
            );

            auto process_base = clone_base + offset;
            *reinterpret_cast< std::uint64_t* >( process_base + 0x28  ) = pml4_pa;
            *reinterpret_cast< std::uint64_t* >( process_base + 0x280 ) = pml4_pa;

            auto active_links = reinterpret_cast< list_entry_t* >( process_base + 0x30 );
            active_links->m_flink = active_links;
            active_links->m_blink = active_links;

            InterlockedOr(  reinterpret_cast< long* >( process_base + 0x87C ),  0x10 );
            InterlockedAnd( reinterpret_cast< long* >( process_base + 0x87C ), ~0x4  );

            *reinterpret_cast< std::uint64_t* >( process_base + 0x7D8 ) = 0;
            *reinterpret_cast< std::uint64_t* >( process_base + 0x7E0 ) = 0;
            *reinterpret_cast< std::uint64_t* >( process_base + 0x7E8 ) = 0;

            auto mm_proc_links = reinterpret_cast< list_entry_t* >( process_base + 0x7F8 );
            mm_proc_links->m_flink = mm_proc_links;
            mm_proc_links->m_blink = mm_proc_links;

            auto* orig_thread_head  = reinterpret_cast< list_entry_t* >(
                reinterpret_cast< std::uint64_t >( target_process ) + offsets::thread_list_head );
            auto* clone_thread_head = reinterpret_cast< list_entry_t* >(
                process_base + offsets::thread_list_head );
            clone_thread_head->m_flink = orig_thread_head->m_flink;
            clone_thread_head->m_blink = orig_thread_head->m_blink;

            *reinterpret_cast< void** >( process_base + 0x768 ) = nullptr;

            InterlockedExchange64(
                reinterpret_cast< long long* >( process_base + 0x6D8 ), 0 );

            auto clone_process = reinterpret_cast< eprocess_t* >( process_base );
            auto mm_support = *reinterpret_cast< std::uint64_t* >(
                reinterpret_cast< std::uint64_t >( clone_process ) + 0x6A0 );
            *reinterpret_cast< std::uint8_t* >( mm_support + 341 ) |= 0x1;

            InterlockedOr(
                reinterpret_cast< volatile long* >(
                    reinterpret_cast< std::uint64_t >( clone_process ) + 0x464 ),
                0x400 );

            if ( !kernel::mm_initialize_process_address_space( clone_process, target_process ) ) {
                kernel::dbg_print( oxorany( "[divinity] MmInitializeProcessAddressSpace failed\n" ) );
                memset( reinterpret_cast< void* >( clone_base ), 0, page_4kb_size );
                memset( reinterpret_cast< void* >( pml4_va ), 0, page_4kb_size );
                mmu::free_kva( clone_base, page_4kb_size );
                mmu::free_kva( pml4_va, page_4kb_size );
                return false;
            }

            InterlockedOr(
                reinterpret_cast< volatile long* >(
                    reinterpret_cast< std::uint64_t >( clone_process ) + 0x464 ),
                0x400 );

            *reinterpret_cast< std::uint8_t* >( mm_support + 341 ) |= 0x2;
            *reinterpret_cast< std::uint8_t* >( mm_support + 341 ) |= 0x1;

            m_entries[ slot ].m_clone_base = clone_base;
            m_entries[ slot ].m_clone_process = clone_process;
            m_entries[ slot ].m_orig_process = target_process;
            m_entries[ slot ].m_active = true;

            auto hyperspace_pml4_va = mmu::alloc_kva( page_4kb_size );
            if ( !hyperspace_pml4_va )
                return false;

            auto hyperspace_pml4_pa = phys::virtual_to_physical( hyperspace_pml4_va );
            if ( !hyperspace_pml4_pa ) {
                memset( reinterpret_cast< void* >( hyperspace_pml4_va ), 0, page_4kb_size );
                mmu::free_kva( hyperspace_pml4_va, page_4kb_size );
                return false;
            }

            memset(
                reinterpret_cast< void* >( hyperspace_pml4_va ),
                0, 256 * sizeof( pml4e )
            );

            for ( auto idx = 256; idx < 512; idx++ ) {
                pml4e entry{ };
                dpm::read_physical( org_pml4_pa + ( idx * sizeof( pml4e ) ),
                    &entry, sizeof( pml4e ) );
                reinterpret_cast< pml4e* >( hyperspace_pml4_va )[ idx ] = entry;
            }

            m_entries[ slot ].m_hyperspace_cr3 = hyperspace_pml4_pa;
            m_entries[ slot ].m_hyperspace_va = hyperspace_pml4_va;

            return true;
        }

        std::uint64_t expose_hyperspace(
            eprocess_t* target_process,
            eprocess_t* client_process,
            std::uint64_t target_va,
            std::size_t   size
        ) {
            auto idx = find_entry( target_process );
            if ( idx == -1 )
                return 0;

            auto& mapping = m_entries[ idx ].m_hyperspace_mapping;
            if ( mapping.m_active )
                return 0;

            auto clone_cr3 = m_entries[ idx ].m_clone_process->m_pcb.m_directory_table_base;
            auto client_dtb = client_process->m_pcb.m_directory_table_base;
            auto target_dtb = process::get_directory_table_base( target_process );
            if ( !clone_cr3 || !client_dtb || !target_dtb )
                return 0;

            const auto aligned_size = ( size + page_4kb_mask ) & ~page_4kb_mask;
            if ( !aligned_size )
                return 0;

            auto page_buf = reinterpret_cast< std::uint8_t* >( mmu::alloc_kva( page_4kb_size ) );
            if ( !page_buf )
                return 0;

            const std::uint64_t target_dtbs [ ] { clone_cr3, client_dtb, target_dtb };
            auto pml4_index = find_free_pml4_index( target_dtbs, 3 );
            if ( pml4_index == static_cast< std::uint32_t >( -1 ) ) {
                memset( page_buf, 0, page_4kb_size );
                mmu::free_kva( reinterpret_cast< std::uint64_t >( page_buf ), page_4kb_size );
                return 0;
            }

            auto hyperspace_va = static_cast< std::uint64_t >( pml4_index ) << 39;
            if ( !map_page_tables( hyperspace_va, aligned_size, clone_cr3 ) ) {
                memset( page_buf, 0, page_4kb_size );
                mmu::free_kva( reinterpret_cast< std::uint64_t >( page_buf ), page_4kb_size );
                return 0;
            }

            std::uint32_t pages_copied = 0;
            std::uint32_t pages_skipped = 0;
            for ( std::uint64_t offset = 0; offset < aligned_size; offset += page_4kb_size ) {
                memset( page_buf, 0, page_4kb_size );

                const auto src_va = target_va + offset;
                const auto dst_va = hyperspace_va + offset;

                virt_addr_t src{ src_va };
                virt_addr_t dst{ dst_va };

                pml4e pml4{ };
                if ( !dpm::read_physical( target_dtb + ( src.pml4e_index * sizeof( pml4e ) ),
                    &pml4, sizeof( pml4e ) ) || !pml4.hard.present ) {
                    pages_skipped++; continue;
                }
                pdpte pdpt{ };
                if ( !dpm::read_physical( ( pml4.hard.pfn << page_shift ) + ( src.pdpte_index * sizeof( pdpte ) ),
                    &pdpt, sizeof( pdpte ) ) || !pdpt.hard.present ) {
                    pages_skipped++; continue;
                }
                pde pd{ };
                if ( !dpm::read_physical( ( pdpt.hard.pfn << page_shift ) + ( src.pde_index * sizeof( pde ) ),
                    &pd, sizeof( pde ) ) || !pd.hard.present ) {
                    pages_skipped++; continue;
                }

                std::uint64_t src_pa = 0;
                if ( pd.hard.page_size ) {
                    src_pa = ( static_cast< std::uint64_t >( pd.hard.pfn ) << page_2mb_shift )
                        + ( src_va & page_2mb_mask );
                }
                else {
                    pte pt{ };
                    if ( !dpm::read_physical( ( pd.hard.pfn << page_shift ) + ( src.pte_index * sizeof( pte ) ),
                        &pt, sizeof( pte ) ) || !pt.hard.present ) {
                        pages_skipped++; continue;
                    }
                    src_pa = ( static_cast< std::uint64_t >( pt.hard.pfn ) << page_shift );
                }

                pml4e dst_pml4{ };
                if ( !dpm::read_physical( clone_cr3 + ( dst.pml4e_index * sizeof( pml4e ) ),
                    &dst_pml4, sizeof( pml4e ) ) || !dst_pml4.hard.present ) {
                    pages_skipped++; continue;
                }
                pdpte dst_pdpt{ };
                if ( !dpm::read_physical( ( dst_pml4.hard.pfn << page_shift ) + ( dst.pdpte_index * sizeof( pdpte ) ),
                    &dst_pdpt, sizeof( pdpte ) ) || !dst_pdpt.hard.present ) {
                    pages_skipped++; continue;
                }
                pde dst_pd{ };
                if ( !dpm::read_physical( ( dst_pdpt.hard.pfn << page_shift ) + ( dst.pde_index * sizeof( pde ) ),
                    &dst_pd, sizeof( pde ) ) || !dst_pd.hard.present ) {
                    pages_skipped++; continue;
                }
                pte dst_pt{ };
                if ( !dpm::read_physical( ( dst_pd.hard.pfn << page_shift ) + ( dst.pte_index * sizeof( pte ) ),
                    &dst_pt, sizeof( pte ) ) || !dst_pt.hard.present ) {
                    pages_skipped++; continue;
                }

                auto dst_pa = static_cast< std::uint64_t >( dst_pt.hard.pfn ) << page_shift;
                if ( !phys::is_address_valid( src_pa, page_4kb_size ) ) continue;
                if ( !phys::is_address_valid( dst_pa, page_4kb_size ) ) continue;

                if ( !dpm::read_physical( src_pa, page_buf, page_4kb_size ) ) {
                    pages_skipped++; continue;
                }
                if ( !dpm::write_physical( dst_pa, page_buf, page_4kb_size ) ) {
                    pages_skipped++; continue;
                }

                pages_copied++;
            }

            memset( page_buf, 0, page_4kb_size );
            mmu::free_kva( reinterpret_cast< std::uint64_t >( page_buf ), page_4kb_size );

            if ( !pages_copied )
                return 0;

            const std::uint64_t mirror_dst [ ] { client_dtb, target_dtb };
            if ( !mirror_pml4_index( pml4_index, clone_cr3, mirror_dst, 2 ) )
                return 0;

            mapping.m_target_va = target_va;
            mapping.m_target_dtb = target_dtb;
            mapping.m_client_dtb = client_dtb;
            mapping.m_hyperspace_va = hyperspace_va;
            mapping.m_hyperspace_size = aligned_size;
            mapping.m_hyperspace_pml4 = pml4_index;
            mapping.m_active = true;

            return hyperspace_va;
        }

        std::uint64_t expose_clone_pages(
            eprocess_t* target_process,
            eprocess_t* client_process,
            std::uint64_t alloc_va,
            std::size_t   size
        ) {
            auto idx = find_entry( target_process );
            if ( idx == -1 )
                return 0;

            auto clone_cr3 = m_entries[ idx ].m_clone_process->m_pcb.m_directory_table_base;
            auto client_dtb = client_process->m_pcb.m_directory_table_base;
            auto target_dtb = process::get_directory_table_base( target_process );
            if ( !clone_cr3 || !client_dtb|| !target_dtb )
                return 0;

            const auto aligned_size = ( size + page_4kb_mask ) & ~page_4kb_mask;

            const std::uint64_t target_dtbs [ ] { clone_cr3, client_dtb };
            auto pml4_index = find_free_pml4_index( target_dtbs, 2 );
            if ( pml4_index == static_cast< std::uint32_t >( -1 ) )
                return 0;

            const auto hyperspace_va = static_cast< std::uint64_t >( pml4_index ) << 39;
            if ( !map_page_tables( hyperspace_va, aligned_size, clone_cr3 ) )
                return 0;

            auto page_buf = reinterpret_cast< std::uint8_t* >( mmu::alloc_kva( page_4kb_size ) );
            if ( !page_buf )
                return 0;

            std::uint32_t pages_mapped = 0;
            for ( std::uint64_t offset = 0; offset < aligned_size; offset += page_4kb_size ) {
                memset( page_buf, 0, page_4kb_size );

                const auto src_va = alloc_va + offset;
                const auto dst_va = hyperspace_va + offset;

                virt_addr_t s{ src_va };
                pml4e e0{ };
                if ( !dpm::read_physical( clone_cr3 + ( s.pml4e_index * sizeof( pml4e ) ),
                    &e0, sizeof( pml4e ) ) || !e0.hard.present ) continue;
                pdpte e1{ };
                if ( !dpm::read_physical( ( e0.hard.pfn << page_shift ) + ( s.pdpte_index * sizeof( pdpte ) ),
                    &e1, sizeof( pdpte ) ) || !e1.hard.present ) continue;
                pde e2{ };
                if ( !dpm::read_physical( ( e1.hard.pfn << page_shift ) + ( s.pde_index * sizeof( pde ) ),
                    &e2, sizeof( pde ) ) || !e2.hard.present ) continue;
                pte e3{ };
                if ( !dpm::read_physical( ( e2.hard.pfn << page_shift ) + ( s.pte_index * sizeof( pte ) ),
                    &e3, sizeof( pte ) ) || !e3.hard.present ) continue;

                auto src_pa = static_cast< std::uint64_t >( e3.hard.pfn ) << page_shift;

                virt_addr_t d{ dst_va };
                pml4e de0{ };
                if ( !dpm::read_physical( clone_cr3 + ( d.pml4e_index * sizeof( pml4e ) ),
                    &de0, sizeof( pml4e ) ) || !de0.hard.present ) continue;
                pdpte de1{ };
                if ( !dpm::read_physical( ( de0.hard.pfn << page_shift ) + ( d.pdpte_index * sizeof( pdpte ) ),
                    &de1, sizeof( pdpte ) ) || !de1.hard.present ) continue;
                pde de2{ };
                if ( !dpm::read_physical( ( de1.hard.pfn << page_shift ) + ( d.pde_index * sizeof( pde ) ),
                    &de2, sizeof( pde ) ) || !de2.hard.present ) continue;
                pte de3{ };
                if ( !dpm::read_physical( ( de2.hard.pfn << page_shift ) + ( d.pte_index * sizeof( pte ) ),
                    &de3, sizeof( pte ) ) || !de3.hard.present ) continue;

                auto dst_pa = static_cast< std::uint64_t >( de3.hard.pfn ) << page_shift;

                if ( !dpm::read_physical( src_pa, page_buf, page_4kb_size ) ) continue;
                if ( !phys::is_address_valid( src_pa, page_4kb_size ) ) continue;
                if ( !dpm::write_physical( dst_pa, page_buf, page_4kb_size ) ) continue;

                pages_mapped++;
            }

            memset( page_buf, 0, page_4kb_size );
            mmu::free_kva( reinterpret_cast< std::uint64_t >( page_buf ), page_4kb_size );

            if ( !pages_mapped )
                return 0;

            const std::uint64_t mirror_dst [ ] { client_dtb, target_dtb };
            if ( !mirror_pml4_index( pml4_index, clone_cr3, mirror_dst, 2 ) )
                return 0;

            return hyperspace_va;
        }

        bool refresh_hyperspace(
            eprocess_t* target_process,
            eprocess_t* client_process
        ) {
            auto idx = find_entry( target_process );
            if ( idx == -1 )
                return false;

            auto& mapping = m_entries[ idx ].m_hyperspace_mapping;
            if ( !mapping.m_active )
                return false;

            auto clone_cr3 = m_entries[ idx ].m_clone_process->m_pcb.m_directory_table_base;
            auto orig_dtb = process::get_directory_table_base( target_process );
            if ( !clone_cr3 || !orig_dtb )
                return false;

            auto page_buf = reinterpret_cast< std::uint8_t* >( mmu::alloc_kva( page_4kb_size ) );
            if ( !page_buf )
                return false;

            for ( std::uint64_t offset = 0; offset < mapping.m_hyperspace_size; offset += page_4kb_size ) {
                memset( page_buf, 0, page_4kb_size );

                const auto src_va = mapping.m_target_va + offset;
                const auto dst_va = mapping.m_hyperspace_va + offset;

                std::uint64_t src_pa = 0;
                {
                    virt_addr_t s{ src_va };

                    pml4e e0{ };
                    if ( !dpm::read_physical( orig_dtb + ( s.pml4e_index * sizeof( pml4e ) ),
                        &e0, sizeof( pml4e ) ) || !e0.hard.present ) continue;
                    pdpte e1{ };
                    if ( !dpm::read_physical( ( e0.hard.pfn << page_shift ) + ( s.pdpte_index * sizeof( pdpte ) ),
                        &e1, sizeof( pdpte ) ) || !e1.hard.present ) continue;
                    pde e2{ };
                    if ( !dpm::read_physical( ( e1.hard.pfn << page_shift ) + ( s.pde_index * sizeof( pde ) ),
                        &e2, sizeof( pde ) ) || !e2.hard.present ) continue;

                    if ( e2.hard.page_size ) {
                        src_pa = ( static_cast< std::uint64_t >( e2.hard.pfn ) << page_2mb_shift )
                            + ( src_va & page_2mb_mask );
                    }
                    else {
                        pte e3{ };
                        if ( !dpm::read_physical( ( e2.hard.pfn << page_shift ) + ( s.pte_index * sizeof( pte ) ),
                            &e3, sizeof( pte ) ) || !e3.hard.present ) continue;
                        src_pa = ( static_cast< std::uint64_t >( e3.hard.pfn ) << page_shift );
                    }
                }

                if ( !src_pa )
                    continue;

                virt_addr_t d{ dst_va };

                pml4e e0{ };
                if ( !dpm::read_physical( clone_cr3 + ( d.pml4e_index * sizeof( pml4e ) ),
                    &e0, sizeof( pml4e ) ) || !e0.hard.present ) continue;
                pdpte e1{ };
                if ( !dpm::read_physical( ( e0.hard.pfn << page_shift ) + ( d.pdpte_index * sizeof( pdpte ) ),
                    &e1, sizeof( pdpte ) ) || !e1.hard.present ) continue;
                pde e2{ };
                if ( !dpm::read_physical( ( e1.hard.pfn << page_shift ) + ( d.pde_index * sizeof( pde ) ),
                    &e2, sizeof( pde ) ) || !e2.hard.present ) continue;
                pte e3{ };
                if ( !dpm::read_physical( ( e2.hard.pfn << page_shift ) + ( d.pte_index * sizeof( pte ) ),
                    &e3, sizeof( pte ) ) || !e3.hard.present ) continue;

                auto dst_pa = static_cast< std::uint64_t >( e3.hard.pfn ) << page_shift;
                if ( !dpm::read_physical( src_pa, page_buf, page_4kb_size ) )
                    continue;

                if ( !dpm::write_physical( dst_pa, page_buf, page_4kb_size ) )
                    return false;
            }

            memset( page_buf, 0, page_4kb_size );
            mmu::free_kva( reinterpret_cast< std::uint64_t >( page_buf ), page_4kb_size );
            return true;
        }

        std::uint64_t remap_to_hyperspace(
            eprocess_t* process,
            std::uint64_t image_base,
            std::uint64_t image_size,
            bool high_address = true
        ) {
            auto idx = find_entry( process );
            if ( idx == -1 )
                return 0;

            auto hyperspace_cr3 = m_entries[ idx ].m_clone_process->m_pcb.m_directory_table_base;
            if ( !hyperspace_cr3 )
                return 0;

            const auto aligned_size = ( image_size + page_2mb_mask ) & ~page_2mb_mask;
            const auto large_page_count = aligned_size >> page_2mb_shift;

            auto orig_cr3 = swap_context( hyperspace_cr3 );
            auto pml4_index = find_non_present_pml4e( high_address );
            swap_context( orig_cr3 );

            if ( pml4_index == static_cast< std::uint32_t >( -1 ) ) {
                kernel::dbg_print( oxorany( "[divinity] no free PML4 slot\n" ) );
                return 0;
            }

            auto remap_base = create_virtual_address( pml4_index, high_address );
            for ( auto i = 0; i < large_page_count; i++ ) {
                auto src_va = image_base + ( i * page_2mb_size );
                auto dest_va = remap_base + ( i * page_2mb_size );
                auto copy_size = min( page_2mb_size, image_base + image_size - src_va );

                auto large_va = mmu::alloc_large_page( page_2mb_size );
                if ( !large_va ) {
                    kernel::dbg_print( oxorany( "[divinity] failed to allocate large page\n" ) );
                    return 0;
                }

                auto large_pa = phys::virtual_to_physical( large_va );
                if ( !large_pa || ( large_pa & page_2mb_mask ) ) {
                    kernel::dbg_print( oxorany( "[divinity] failed to get physical large page\n" ) );
                    return 0;
                }

                std::memcpy( reinterpret_cast< void* >( large_va ), reinterpret_cast< void* >( src_va ), copy_size );

                virt_addr_t va{ dest_va };

                pml4e pml4_entry{ };
                auto pml4e_pa = hyperspace_cr3 + ( va.pml4e_index * sizeof( pml4e ) );
                if ( !dpm::read_physical( pml4e_pa, &pml4_entry, sizeof( pml4e ) ) )
                    return 0;

                if ( !pml4_entry.hard.present ) {
                    auto pdpt_va = mmu::alloc_kva( page_4kb_size );
                    if ( !pdpt_va ) return 0;

                    auto pdpt_pa = phys::virtual_to_physical( pdpt_va );
                    if ( !pdpt_pa ) return 0;

                    if ( !hide::hide_pages( pdpt_va, page_4kb_size, true ) )
                        return 0;

                    pml4e new_pml4e{ 0 };
                    new_pml4e.hard.present = 1;
                    new_pml4e.hard.read_write = 1;
                    new_pml4e.hard.user_supervisor = 0;
                    new_pml4e.hard.no_execute = 0;
                    new_pml4e.hard.pfn = pdpt_pa >> page_shift;
                    if ( !dpm::write_physical( pml4e_pa, &new_pml4e, sizeof( pml4e ) ) )
                        return 0;

                    mmu::flush_caches( pdpt_va );
                    pml4_entry = new_pml4e;
                }

                pdpte pdpt_entry{ };
                auto pdpte_pa = ( pml4_entry.hard.pfn << page_shift ) + ( va.pdpte_index * sizeof( pdpte ) );
                if ( !dpm::read_physical( pdpte_pa, &pdpt_entry, sizeof( pdpte ) ) )
                    return 0;

                if ( !pdpt_entry.hard.present ) {
                    auto pd_va = mmu::alloc_kva( page_4kb_size );
                    if ( !pd_va ) return 0;

                    auto pd_pa = phys::virtual_to_physical( pd_va );
                    if ( !pd_pa ) return 0;

                    if ( !hide::hide_pages( pd_va, page_4kb_size, true ) )
                        return 0;

                    pdpte new_pdpte{ 0 };
                    new_pdpte.hard.present = 1;
                    new_pdpte.hard.read_write = 1;
                    new_pdpte.hard.user_supervisor = 0;
                    new_pdpte.hard.no_execute = 0;
                    new_pdpte.hard.pfn = pd_pa >> page_shift;
                    if ( !dpm::write_physical( pdpte_pa, &new_pdpte, sizeof( pdpte ) ) )
                        return 0;

                    mmu::flush_caches( pd_va );
                    pdpt_entry = new_pdpte;
                }

                pde new_pde{ 0 };
                new_pde.hard.present = 1;
                new_pde.hard.read_write = 1;
                new_pde.hard.user_supervisor = 0;
                new_pde.hard.page_size = 1;
                new_pde.hard.no_execute = 0;
                new_pde.hard.pfn = large_pa >> page_2mb_shift;

                auto pde_pa = ( pdpt_entry.hard.pfn << page_shift ) + ( va.pde_index * sizeof( pde ) );
                if ( !dpm::write_physical( pde_pa, &new_pde, sizeof( pde ) ) )
                    return 0;
            }

            kernel::dbg_print(
                oxorany( "[divinity] remap complete: base=0x%llx size=0x%llx pages=%llu high=%d\n" ),
                remap_base, aligned_size, large_page_count, high_address );

            return remap_base;
        }

        std::uint64_t allocate_large_pages( eprocess_t* process, std::size_t size, bool high_address = false ) {
            auto idx = find_entry( process );
            if ( idx == -1 )
                return 0;

            auto& entry = m_entries[ idx ];
            auto clone_cr3 = m_entries[ idx ].m_clone_process->m_pcb.m_directory_table_base;
            if ( !clone_cr3 )
                return 0;

            const std::uint64_t target_dtbs [ ] { clone_cr3 };
            auto pml4_index = find_free_pml4_index( target_dtbs, 1, high_address );
            if ( pml4_index == static_cast< std::uint32_t >( -1 ) )
                return 0;

            auto base_va = create_virtual_address( pml4_index, high_address );
            const auto aligned_size = ( size + page_2mb_mask ) & ~page_2mb_mask;
            const auto page_count = aligned_size >> page_2mb_shift;
            if ( !map_large_page_tables( base_va, aligned_size, clone_cr3 ) )
                return 0;

            auto orig_dtb = process::get_directory_table_base( process );
            auto shadow_cr3 = entry.m_hyperspace_cr3;

            const std::uint64_t mirror_dst [ ] { orig_dtb, shadow_cr3 };
            if ( !mirror_pml4_index( pml4_index, clone_cr3, mirror_dst, 2 ) )
                return 0;

            return base_va;
        }

        std::uint64_t allocate_virtual( eprocess_t* process, std::size_t size, bool high_address = false ) {
            auto idx = find_entry( process );
            if ( idx == -1 )
                return 0;

            auto& entry = m_entries[ idx ];
            auto clone_cr3 = entry.m_clone_process->m_pcb.m_directory_table_base;
            if ( !clone_cr3 )
                return 0;

            const std::uint64_t target_dtbs [ ] { clone_cr3 };
            auto pml4_index = find_free_pml4_index( target_dtbs, 1, high_address );
            if ( pml4_index == static_cast< std::uint32_t >( -1 ) )
                return 0;

            auto base_va = create_virtual_address( pml4_index, high_address );
            auto aligned_size = ( size + page_4kb_mask ) & ~page_4kb_mask;
            if ( !map_page_tables( base_va, aligned_size, clone_cr3 ) )
                return 0;

            auto orig_dtb = process::get_directory_table_base( process );
            auto shadow_cr3 = entry.m_hyperspace_cr3;

            const std::uint64_t mirror_dst [ ] { orig_dtb, shadow_cr3 };
            if ( !mirror_pml4_index( pml4_index, clone_cr3, mirror_dst, 2 ) )
                return 0;

            return base_va;
        }

        bool free_virtual( eprocess_t* process, std::uint64_t base_va ) {
            auto idx = find_entry( process );
            if ( idx == -1 )
                return false;

            auto& entry = m_entries[ idx ];
            auto clone_cr3 = entry.m_clone_process->m_pcb.m_directory_table_base;
            if ( !clone_cr3 )
                return false;

            virt_addr_t virt{ base_va };
            auto pml4e_pa = clone_cr3 + ( virt.pml4e_index * sizeof( pml4e ) );

            pml4e e0{ };
            if ( !dpm::read_physical( pml4e_pa, &e0, sizeof( pml4e ) ) || !e0.hard.present )
                return false;

            auto pdpt_pa = e0.hard.pfn << page_shift;
            for ( auto pi = 0; pi < 512; pi++ ) {
                pdpte e1{ };
                auto pdpte_pa = pdpt_pa + ( pi * sizeof( pdpte ) );
                if ( !dpm::read_physical( pdpte_pa, &e1, sizeof( pdpte ) ) || !e1.hard.present ) continue;

                auto pd_pa = e1.hard.pfn << page_shift;
                for ( auto di = 0; di < 512; di++ ) {
                    pde e2{ };
                    auto pde_pa = pd_pa + ( di * sizeof( pde ) );
                    if ( !dpm::read_physical( pde_pa, &e2, sizeof( pde ) ) || !e2.hard.present ) continue;

                    auto pt_kva = phys::physical_to_virtual( e2.hard.pfn << page_shift );
                    if ( pt_kva ) {
                        memset( reinterpret_cast< void* >( pt_kva ), 0, page_4kb_size );
                        mmu::free_kva( pt_kva, page_4kb_size );
                    }
                }

                auto pd_kva = phys::physical_to_virtual( pd_pa );
                if ( pd_kva ) {
                    memset( reinterpret_cast< void* >( pd_kva ), 0, page_4kb_size );
                    mmu::free_kva( pd_kva, page_4kb_size );
                }
            }

            auto pdpt_kva = phys::physical_to_virtual( pdpt_pa );
            if ( pdpt_kva ) {
                memset( reinterpret_cast< void* >( pdpt_kva ), 0, page_4kb_size );
                mmu::free_kva( pdpt_kva, page_4kb_size );
            }

            auto orig_dtb = process::get_directory_table_base( process );
            auto shadow_cr3 = entry.m_hyperspace_cr3;

            const std::uint64_t to_zero [ ] { clone_cr3, orig_dtb, shadow_cr3 };
            zero_pml4_index( virt.pml4e_index, to_zero, 3 );
            return true;
        }

        bool setup_hyperspace( ) {
            std::uint8_t shellcode[ sizeof( routine_shellcode ) ];
            std::memcpy( shellcode, routine_shellcode, sizeof( shellcode ) );
            *reinterpret_cast< std::uint64_t* >( shellcode + 17 ) =
                reinterpret_cast< std::uint64_t >( cleanup_callback );

            std::size_t size_of_image;
            kldr_data_table_entry_t* ldr_entry;

            auto target_address = module::allocate_between_modules( sizeof( shellcode ), &ldr_entry, &size_of_image );
            if ( !target_address ) {
                kernel::dbg_print( oxorany( "[divinity] could not allocate large page\n" ) );
                return false;
            }

            std::memcpy(
                reinterpret_cast< void* >( target_address ),
                shellcode,
                sizeof( shellcode )
            );

            if ( auto result = kernel::ps_set_create_process_notify_routine(
                reinterpret_cast< p_create_process_notify_routine >( target_address ), false ) ) {
                kernel::dbg_print( oxorany( "[divinity] could not create callback: %i\n" ), result );
                return false;
            }

            ldr_entry->m_size_of_image = size_of_image;
            return true;
        }

        bool create_hyperspace( eprocess_t* process ) {
            if ( find_entry( process ) != -1 )
                return true;

            return clone_process( process );
        }

        bool cleanup_hyperspace( std::uint32_t idx ) {
            auto& entry   = m_entries[ idx ];
            auto& mapping = entry.m_hyperspace_mapping;
            if ( !mapping.m_active )
                return false;

            auto clone_dtb  = entry.m_clone_process->m_pcb.m_directory_table_base;
            auto target_dtb = mapping.m_target_dtb;
            auto client_dtb = mapping.m_client_dtb;
            if ( !clone_dtb || !mapping.m_hyperspace_size )
                return false;

            for ( std::uint64_t offset = 0; offset < mapping.m_hyperspace_size; offset += page_4kb_size ) {
                virt_addr_t d{ mapping.m_hyperspace_va + offset };

                pml4e e0{ };
                if ( !dpm::read_physical( clone_dtb + ( d.pml4e_index * sizeof( pml4e ) ),
                    &e0, sizeof( pml4e ) ) || !e0.hard.present ) continue;
                pdpte e1{ };
                if ( !dpm::read_physical( ( e0.hard.pfn << page_shift ) + ( d.pdpte_index * sizeof( pdpte ) ),
                    &e1, sizeof( pdpte ) ) || !e1.hard.present ) continue;
                pde e2{ };
                if ( !dpm::read_physical( ( e1.hard.pfn << page_shift ) + ( d.pde_index * sizeof( pde ) ),
                    &e2, sizeof( pde ) ) || !e2.hard.present ) continue;

                pte zero{ };
                auto pte_pa = ( e2.hard.pfn << page_shift ) + ( d.pte_index * sizeof( pte ) );
                dpm::write_physical( pte_pa, &zero, sizeof( pte ) );
            }

            const std::uint64_t to_zero[] = { clone_dtb, client_dtb, target_dtb };
            zero_pml4_index( mapping.m_hyperspace_pml4, to_zero, 3 );
            mapping = { };

            return true;
        }

        void cleanup_callback( void* parent_id, void* process_id, bool create ) {
            if ( create )
                return;

            auto current_process = process::get_eprocess(
                reinterpret_cast< std::uint32_t >( process_id ) );
            if ( !current_process )
                return;

            for ( auto idx = 0; idx < max_entries; idx++ ) {
                auto& entry = m_entries[ idx ];
                if ( !entry.m_active )
                    continue;

                if ( entry.m_orig_process != current_process )
                    continue;

                if ( entry.m_hyperspace_mapping.m_active )
                    cleanup_hyperspace( idx );

                if ( entry.m_hyperspace_va ) {
                    memset( reinterpret_cast< void* >( entry.m_hyperspace_va ), 0, page_4kb_size );
                    mmu::free_kva( entry.m_hyperspace_va, page_4kb_size );
                    entry.m_hyperspace_va = 0;
                    entry.m_hyperspace_cr3 = 0;
                }

                entry.m_active = false;
                entry.m_clone_base = 0;
                entry.m_orig_process = nullptr;
                entry.m_clone_process = nullptr;
            }
        }

        //bool resolve_thread_start(
        //    PKSTART_ROUTINE start_routine,
        //    PKSTART_ROUTINE* resolved_start_routine
        //) {
        //    if ( !start_routine || !resolved_start_routine )
        //        return false;

        //    const auto start_va = reinterpret_cast< std::uint64_t >( start_routine );
        //    if ( module::is_inside_module( start_va ) ) {
        //        *resolved_start_routine = start_routine;
        //        return true;
        //    }

        //    std::uint8_t shellcode[ sizeof( routine_shellcode ) ];
        //    std::memcpy( shellcode, routine_shellcode, sizeof( shellcode ) );
        //    *reinterpret_cast< std::uint64_t* >( shellcode + 17 ) = start_va;

        //    auto stub_va = module::allocate_large_page(
        //        kernel::m_ntoskrnl_base,
        //        sizeof( shellcode ) );

        //    if ( !stub_va ) {
        //        stub_va = module::allocate_cow_pages( sizeof( shellcode ) );
        //    }

        //    if ( stub_va && !paging::set_page_protection( stub_va, paging::page_protection::readwrite_execute ) ) {
        //        stub_va = 0;
        //    }

        //    if ( !stub_va ) {
        //        kernel::dbg_print(
        //            oxorany( "[divinity] Could not allocate loaded-image thread stub for 0x%llx\n" ),
        //            start_va );
        //        return false;
        //    }

        //    std::memcpy(
        //        reinterpret_cast< void* >( stub_va ),
        //        shellcode,
        //        sizeof( shellcode ) );

        //    mmu::flush_caches( stub_va );

        //    kernel::dbg_print(
        //        oxorany( "[divinity] Using thread stub 0x%llx -> 0x%llx\n" ),
        //        stub_va,
        //        start_va );

        //    *resolved_start_routine = reinterpret_cast< PKSTART_ROUTINE >( stub_va );
        //    return true;
    }
}