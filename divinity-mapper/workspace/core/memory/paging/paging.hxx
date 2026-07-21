#pragma once

namespace paging {
    constexpr auto page_4kb_size = 0x1000ull;
    constexpr auto page_2mb_size = 0x200000ull;
    constexpr auto page_1gb_size = 0x40000000ull;

    constexpr auto page_shift = 12ull;
    constexpr auto page_2mb_shift = 21ull;
    constexpr auto page_1gb_shift = 30ull;

    constexpr auto page_4kb_mask = 0xFFFull;
    constexpr auto page_2mb_mask = 0x1FFFFFull;
    constexpr auto page_1gb_mask = 0x3FFFFFFFull;

    enum class e_pt_protection {
        none,
        read_write,
        read_write_execute
    };

    struct pt_entries_t {
        pml4e m_pml4e;
        pdpte m_pdpte;
        pde m_pde;
        pte m_pte;
    };

    class c_paging {
    public:
        c_paging( ) { }
        ~c_paging( ) { }

        std::uint64_t m_directory_table_base{ };
        std::uint64_t m_physical_mask{ };

        bool setup( ) {
            const auto ntos_base = g_pdb->m_module_base;
            if ( !ntos_base ) {
                logging::print( oxorany( "ntoskrnl base unavailable for cr3 discovery" ) );
                return false;
            }

            virt_addr_t ntos_va{ ntos_base };
            constexpr std::uint64_t max_scan = 0x400000000ULL;

            for ( std::uint64_t cr3 = 0; cr3 < max_scan; cr3 += page_4kb_size ) {
                pml4e pml4_entry{};
                if ( !g_driver->read_physical_memory(
                    cr3 + ( ntos_va.pml4e_index * sizeof( pml4e ) ),
                    &pml4_entry, sizeof( pml4e ) ) )
                    continue;

                if ( !pml4_entry.hard.present )
                    continue;

                this->m_directory_table_base = cr3;

                std::uint16_t mz = 0;
                if ( !read_virtual_memory( ntos_base, &mz, sizeof( mz ) ) || mz != IMAGE_DOS_SIGNATURE )
                    continue;

                std::uint32_t lfanew = 0;
                if ( !read_virtual_memory( ntos_base + 0x3C, &lfanew, sizeof( lfanew ) ) )
                    continue;

                std::uint32_t pe_sig = 0;
                if ( !read_virtual_memory( ntos_base + lfanew, &pe_sig, sizeof( pe_sig ) ) ||
                    pe_sig != IMAGE_NT_SIGNATURE )
                    continue;

                logging::print( oxorany( "found system cr3: 0x%llx" ), cr3 );
                return true;
            }

            this->m_directory_table_base = 0;
            logging::print( oxorany( "could not discover system cr3" ) );
            return false;
        }

        std::uint64_t translate_linear( std::uint64_t addr, std::uint32_t* page_size = 0 ) {
            pt_entries_t pt_entries;
            if ( !hyperspace_entries( pt_entries, addr ) )
                return false;

            if ( pt_entries.m_pdpte.hard.page_size ) {
                if ( page_size ) *page_size = page_1gb_size;
                return ( pt_entries.m_pdpte.hard.pfn << 12 ) + ( addr & page_1gb_mask );
            }

            if ( pt_entries.m_pde.hard.page_size ) {
                if ( page_size ) *page_size = page_2mb_size;
                return ( pt_entries.m_pde.hard.pfn << 12 ) + ( addr & page_2mb_mask );
            }

            if ( page_size ) *page_size = page_4kb_size;
            return ( pt_entries.m_pte.hard.pfn << 12 ) + ( addr & page_4kb_mask );
        }

        std::uint64_t get_pte_address( std::uint64_t addr ) {
            pt_entries_t entries{};
            if ( !hyperspace_entries( entries, addr ) )
                return 0;

            if ( entries.m_pdpte.hard.page_size || entries.m_pde.hard.page_size )
                return 0;

            return ( entries.m_pde.hard.pfn << page_shift ) +
                ( virt_addr_t{ addr }.pte_index * sizeof( pte ) );
        }

        std::uint32_t get_page_size( std::uint64_t addr ) {
            pt_entries_t pt_entries;
            if ( !hyperspace_entries( pt_entries, addr ) )
                return false;

            if ( pt_entries.m_pdpte.hard.page_size )
                return page_1gb_size;

            if ( pt_entries.m_pde.hard.page_size )
                return page_2mb_size;
            return page_4kb_size;
        }

        e_pt_protection get_page_protect( std::uint64_t addr ) {
            pt_entries_t pt_entries;
            if ( !hyperspace_entries( pt_entries, addr ) )
                return e_pt_protection::none;

            if ( pt_entries.m_pte.hard.read_write )
                return e_pt_protection::read_write;
            if ( !pt_entries.m_pte.hard.no_execute )
                return e_pt_protection::read_write_execute;

            return e_pt_protection::none;
        }

        bool split_2mb_to_4kb( std::uint64_t address ) {
            pt_entries_t entries{};
            if ( !hyperspace_entries( entries, address ) )
                return false;

            if ( !entries.m_pde.hard.present || !entries.m_pde.hard.page_size )
                return false;

            auto new_pt_va = nt::mm_allocate_independent_pages( page_4kb_size );
            if ( !new_pt_va ) return false;
            nt::memset( new_pt_va, 0, page_4kb_size );

            const auto new_pt_pa = mmu::virtual_to_physical(
                reinterpret_cast< std::uint64_t >( new_pt_va ) );
            if ( !new_pt_pa ) return false;

            const auto base_pfn = entries.m_pde.hard.pfn;
            for ( auto idx = 0u; idx < 512u; ++idx ) {
                pte entry{};
                entry.hard.present = 1;
                entry.hard.read_write = entries.m_pde.hard.read_write;
                entry.hard.user_supervisor = entries.m_pde.hard.user_supervisor;
                entry.hard.page_write_through = entries.m_pde.hard.page_write_through;
                entry.hard.cached_disable = entries.m_pde.hard.cached_disable;
                entry.hard.global = entries.m_pde.hard.global;
                entry.hard.no_execute = 0;
                entry.hard.pfn = base_pfn + idx;

                const auto pte_pa = new_pt_pa + ( idx * sizeof( pte ) );
                if ( !g_driver->write_physical_memory( pte_pa, &entry, sizeof( pte ) ) )
                    return false;
            }

            pde new_pde{};
            new_pde.hard.present = 1;
            new_pde.hard.read_write = entries.m_pde.hard.read_write;
            new_pde.hard.user_supervisor = entries.m_pde.hard.user_supervisor;
            new_pde.hard.page_write_through = entries.m_pde.hard.page_write_through;
            new_pde.hard.cached_disable = entries.m_pde.hard.cached_disable;
            new_pde.hard.page_size = 0;
            new_pde.hard.no_execute = 0;
            new_pde.hard.pfn = new_pt_pa >> page_shift;

            virt_addr_t va{ address };
            if ( !write_pt_entry( entries.m_pdpte, va.pde_index, new_pde ) )
                return false;

            nt::flush_caches( new_pt_va );
            return true;
        }

        bool split_1gb_to_4kb( std::uint64_t address ) {
            pt_entries_t entries{};
            if ( !hyperspace_entries( entries, address ) )
                return false;

            if ( !entries.m_pdpte.hard.present || !entries.m_pdpte.hard.page_size )
                return false;

            auto new_pd_va = nt::mm_allocate_independent_pages( page_4kb_size );
            if ( !new_pd_va ) return false;

            const auto new_pd_pa = mmu::virtual_to_physical(
                reinterpret_cast< std::uint64_t >( new_pd_va ) );
            if ( !new_pd_pa ) return false;

            const auto base_pfn = entries.m_pdpte.hard.pfn;
            for ( auto pd_idx = 0u; pd_idx < 512u; ++pd_idx ) {
                auto new_pt_va = nt::mm_allocate_independent_pages( page_4kb_size );
                if ( !new_pt_va ) return false;

                const auto new_pt_pa = mmu::virtual_to_physical(
                    reinterpret_cast< std::uint64_t >( new_pt_va ) );
                if ( !new_pt_pa ) return false;

                const auto pd_base_pfn = base_pfn + ( pd_idx * 512u );
                for ( auto pt_idx = 0u; pt_idx < 512u; ++pt_idx ) {
                    pte entry{};
                    entry.hard.present = 1;
                    entry.hard.read_write = entries.m_pdpte.hard.read_write;
                    entry.hard.user_supervisor = entries.m_pdpte.hard.user_supervisor;
                    entry.hard.page_write_through = entries.m_pdpte.hard.page_write_through;
                    entry.hard.cached_disable = entries.m_pdpte.hard.cached_disable;
                    entry.hard.no_execute = 0;
                    entry.hard.pfn = pd_base_pfn + pt_idx;

                    const auto pte_pa = new_pt_pa + ( pt_idx * sizeof( pte ) );
                    if ( !g_driver->write_physical_memory( pte_pa, &entry, sizeof( pte ) ) )
                        return false;
                }

                pde pd_entry{};
                pd_entry.hard.present = 1;
                pd_entry.hard.read_write = entries.m_pdpte.hard.read_write;
                pd_entry.hard.user_supervisor = entries.m_pdpte.hard.user_supervisor;
                pd_entry.hard.page_write_through = entries.m_pdpte.hard.page_write_through;
                pd_entry.hard.cached_disable = entries.m_pdpte.hard.cached_disable;
                pd_entry.hard.page_size = 0;
                pd_entry.hard.no_execute = 0;
                pd_entry.hard.pfn = new_pt_pa >> page_shift;

                const auto pde_pa = new_pd_pa + ( pd_idx * sizeof( pde ) );
                if ( !g_driver->write_physical_memory( pde_pa, &pd_entry, sizeof( pde ) ) )
                    return false;
            }

            pdpte new_pdpte{};
            new_pdpte.hard.present = 1;
            new_pdpte.hard.read_write = entries.m_pdpte.hard.read_write;
            new_pdpte.hard.user_supervisor = entries.m_pdpte.hard.user_supervisor;
            new_pdpte.hard.page_write_through = entries.m_pdpte.hard.page_write_through;
            new_pdpte.hard.cached_disable = entries.m_pdpte.hard.cached_disable;
            new_pdpte.hard.page_size = 0;
            new_pdpte.hard.no_execute = 0;
            new_pdpte.hard.pfn = new_pd_pa >> page_shift;

            virt_addr_t va{ address };
            if ( !write_pt_entry( entries.m_pml4e, va.pdpte_index, new_pdpte ) )
                return false;

            return true;
        }

        bool read_virtual_memory( std::uint64_t addr, void* buf, std::size_t size ) {
            auto remaining = size;
            auto dst = reinterpret_cast< std::uint8_t* >( buf );
            auto current_va = addr;

            while ( remaining > 0 ) {
                auto pa = translate_linear( current_va );
                if ( !pa ) return false;

                const auto page_offset = current_va & 0xFFF;
                const auto chunk = min( remaining, 0x1000 - page_offset );

                if ( !g_driver->read_physical_memory( pa, dst, chunk ) )
                    return false;

                current_va += chunk;
                dst += chunk;
                remaining -= chunk;
            }

            return true;
        }

        bool hyperspace_entries( pt_entries_t& entries, std::uint64_t address ) {
            virt_addr_t va{ address };

            if ( !g_driver->read_physical_memory(
                m_directory_table_base + ( va.pml4e_index * sizeof( pml4e ) ),
                &entries.m_pml4e, sizeof( pml4e ) ) )
                return false;

            if ( !entries.m_pml4e.hard.present )
                return false;

            if ( !g_driver->read_physical_memory(
                ( entries.m_pml4e.hard.pfn << 12 ) + ( sizeof( pdpte ) * va.pdpte_index ),
                &entries.m_pdpte, sizeof( pdpte ) ) )
                return false;

            if ( !entries.m_pdpte.hard.present )
                return false;

            if ( entries.m_pdpte.hard.page_size )
                return true;

            if ( !g_driver->read_physical_memory(
                ( entries.m_pdpte.hard.pfn << 12 ) + ( sizeof( pde ) * va.pde_index ),
                &entries.m_pde, sizeof( pde ) ) )
                return false;

            if ( !entries.m_pde.hard.present )
                return false;

            if ( entries.m_pde.hard.page_size )
                return true;

            if ( !g_driver->read_physical_memory(
                ( entries.m_pde.hard.pfn << page_shift ) + ( va.pte_index * sizeof( pte ) ),
                &entries.m_pte, sizeof( pte ) ) )
                return false;

            if ( !entries.m_pte.hard.present )
                return false;

            return true;
        }

    private:
        template<typename parent_t, typename entry_t>
        bool write_pt_entry( const parent_t& parent, std::size_t index, const entry_t& entry ) {
            const auto pa = ( parent.hard.pfn << 12 ) + ( index * sizeof( entry_t ) );
            return g_driver->write_physical_memory( pa, &entry, sizeof( entry_t ) );
        }

        void thread_worker( const std::uint64_t& start, const std::uint64_t& end,
            const virt_addr_t& va, std::atomic<std::uint64_t>& found_cr3,
            std::atomic<bool>& found ) {

            if ( found.load( std::memory_order_acquire ) )
                return;

            const auto count = end - start;
            for ( auto idx = 0; idx < count; ++idx ) {
                if ( found.load( std::memory_order_acquire ) )
                    return;

                const auto current_pfn = start + idx;
                const auto current_pa = current_pfn << 12;

                if ( !current_pa )
                    continue;

                ::pml4e pml4e;
                if ( !g_driver->read_physical_memory( current_pa + ( va.pml4e_index * sizeof( pml4e ) ),
                    &pml4e, sizeof( pml4e ) ) )
                    continue;

                if ( !pml4e.hard.present )
                    continue;

                if ( !pml4e.hard.pfn || pml4e.hard.pfn >= end )
                    continue;

                auto pdpte_pa = pml4e.hard.pfn << 12;
                if ( !utility::is_physical_address_valid( pdpte_pa, sizeof( ::pdpte ) ) )
                    continue;

                ::pdpte pdpte;
                if ( !g_driver->read_physical_memory( pdpte_pa + ( va.pdpte_index * sizeof( pdpte ) ),
                    &pdpte, sizeof( pdpte ) ) )
                    continue;

                if ( !pdpte.hard.present )
                    continue;

                if ( !pdpte.hard.pfn || pdpte.hard.pfn >= end )
                    continue;

                auto pde_pa = pdpte.hard.pfn << 12;
                if ( !utility::is_physical_address_valid( pde_pa, sizeof( ::pde ) ) )
                    continue;

                ::pde pde;
                if ( !g_driver->read_physical_memory( pde_pa + ( va.pde_index * sizeof( pde ) ),
                    &pde, sizeof( pde ) ) )
                    continue;

                if ( !pde.hard.present )
                    continue;

                if ( !pde.hard.pfn || pde.hard.pfn >= end )
                    continue;

                auto pte_pa = pde.hard.pfn << 12;
                if ( !utility::is_physical_address_valid( pte_pa, sizeof( ::pte ) ) )
                    continue;

                ::pte pte;
                if ( !g_driver->read_physical_memory( pte_pa + ( va.pte_index * sizeof( pte ) ),
                    &pte, sizeof( pte ) ) )
                    continue;

                if ( !pte.hard.present )
                    continue;

                if ( !pte.hard.pfn || pte.hard.pfn >= end )
                    continue;

                std::uint64_t expected = 0;
                if ( found_cr3.compare_exchange_strong( expected, current_pa,
                    std::memory_order_release, std::memory_order_relaxed ) ) {
                    found.store( true, std::memory_order_release );
                }

                return;
            }
        }
    };
}