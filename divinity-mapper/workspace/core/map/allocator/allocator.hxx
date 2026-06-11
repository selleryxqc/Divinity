#pragma once

namespace module {
    class c_page_candidate {
    public:
        c_page_candidate( ) { }
        ~c_page_candidate( ) { }

        std::uint64_t m_base_address;
        std::uint32_t m_unused_space;
        bool          m_1gb_page;
        bool          m_2mb_page;
        bool          m_executable;
        bool          m_writable;
    };

    std::uint64_t find_unused_space( std::uint64_t section_base, std::uint32_t section_size, std::size_t space_size ) {
        if ( section_size < space_size )
            return 0;

        auto section_data = std::make_unique<std::uint8_t [ ]>( section_size );
        nt::memcpy( section_data.get( ),
            reinterpret_cast< void* >( section_base ),
            section_size );

        for ( auto idx = 0u; idx <= section_size - space_size; ) {
            bool found_space = true;
            for ( auto j = 0u; j < space_size; ++j ) {
                if ( section_data[ idx + j ] != 0x00 ) {
                    found_space = false;
                    idx += j + 1;
                    break;
                }
            }

            if ( found_space )
                return section_base + idx;
        }

        return 0;
    }

    std::uint64_t allocate_large_page( std::size_t size ) {
        std::vector < c_page_candidate > page_candidates;
        const auto module_base = g_pdb->m_module_base;

        dos_header_t dos_header;
        nt::memcpy( &dos_header,
            reinterpret_cast< void* >( module_base ),
            sizeof( dos_header ) );
        if ( dos_header.m_magic != pe_magic_t::dos_header ) {
            logging::print( oxorany( "invalid dos header at 0x%llx" ), module_base );
            return 0;
        }

        nt_headers_t nt_headers;
        nt::memcpy( &nt_headers,
            reinterpret_cast< void* >( module_base + dos_header.m_lfanew ),
            sizeof( nt_headers ) );
        if ( nt_headers.m_signature != pe_magic_t::nt_headers
            || nt_headers.m_magic != pe_magic_t::opt_header ) {
            logging::print( oxorany( "invalid pe header at 0x%llx" ), module_base );
            return 0;
        }

        auto section_headers_va = ( module_base + dos_header.m_lfanew )
            + nt_headers.m_size_of_optional_header + 0x18;
        for ( auto idx = 0; idx < nt_headers.m_number_of_sections; idx++ ) {
            section_header_t section_header;
            nt::memcpy( &section_header,
                reinterpret_cast< void* >( section_headers_va + ( idx * sizeof( section_header_t ) ) ),
                sizeof( section_header ) );
            if ( section_header.m_characteristics & 0x20000000 )
                continue;

            auto section_base = module_base + section_header.m_virtual_address;
            auto section_size = section_header.m_virtual_size;

            std::vector <std::uint8_t> section_data;
            section_data.resize( section_size );
            nt::memcpy( section_data.data( ),
                reinterpret_cast< void* >( section_base ),
                section_size );

            auto target_address = find_unused_space( section_base, section_size, size );
            if ( target_address ) {
                const auto page_size = g_paging->get_page_size( target_address );
                const auto page_protect = g_paging->get_page_protect( target_address );
                const auto zero_count = std::count( section_data.begin( ), section_data.end( ), 0x00 );

                c_page_candidate page_candidate;
                page_candidate.m_base_address = target_address;
                page_candidate.m_unused_space = zero_count;
                page_candidate.m_1gb_page = page_size == paging::page_1gb_size;
                page_candidate.m_2mb_page = page_size == paging::page_2mb_size;
                page_candidate.m_executable = page_protect == paging::e_pt_protection::read_write_execute;
                page_candidate.m_writable = page_protect == paging::e_pt_protection::read_write ? true :
                    page_protect == paging::e_pt_protection::read_write_execute;

                page_candidates.emplace_back( page_candidate );
            }
        }

        for ( auto& candidate : page_candidates ) {
            const auto target_address = candidate.m_base_address;
            if ( !candidate.m_executable )
                logging::print( oxorany( "candidate is not executable!" ) );

            if ( candidate.m_1gb_page ) {
                if ( !g_paging->split_1gb_to_4kb( target_address ) ) {
                    logging::print( oxorany( "could not split huge page." ) );
                    return false;
                }
            }
            else if ( candidate.m_2mb_page ) {
                if ( !g_paging->split_2mb_to_4kb( target_address ) ) {
                    logging::print( oxorany( "could not split large page." ) );
                    return false;
                }
            }

            auto pte_address = g_paging->get_pte_address( target_address );
            if ( !pte_address )
                continue;

            if ( !g_paging->translate_linear( target_address ) )
                continue;

            logging::print( oxorany( "allocated at 0x%llx (size:0x%x)" ), target_address, candidate.m_unused_space );
            return target_address;
        }

        logging::print( oxorany( "no suitable space found in %d sections" ), nt_headers.m_number_of_sections );
        logging::print( oxorany( "please restart your system if you have already mapped." ) );
        return 0;
    }
}