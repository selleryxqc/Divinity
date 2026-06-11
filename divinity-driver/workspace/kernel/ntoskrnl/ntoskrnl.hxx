#pragma once

namespace kernel {
	extern "C" std::uint64_t get_ntoskrnl_base( void );
	std::uint64_t m_ntoskrnl_base;

    std::uint64_t get_export( std::uint64_t module_base, const char* export_name ) {
        auto dos_header{ reinterpret_cast< dos_header_t* > ( module_base ) };
        auto nt_headers{ reinterpret_cast< nt_headers_t* > ( module_base + dos_header->m_lfanew ) };
        if ( !dos_header->is_valid( ) || !nt_headers->is_valid( ) )
            return { };

        auto exp_dir{ nt_headers->m_export_table.as_rva< export_directory_t* >( module_base ) };
        if ( !exp_dir->m_address_of_functions
            || !exp_dir->m_address_of_names
            || !exp_dir->m_address_of_names_ordinals )
            return { };

        auto name{ reinterpret_cast< std::int32_t* > ( module_base + exp_dir->m_address_of_names ) };
        auto functions{ reinterpret_cast< std::int32_t* > ( module_base + exp_dir->m_address_of_functions ) };
        auto ordinals{ reinterpret_cast< std::int16_t* > ( module_base + exp_dir->m_address_of_names_ordinals ) };

        for ( auto idx = 0; idx < exp_dir->m_number_of_names; idx++ ) {
            auto cur_name{ module_base + name[ idx ] };
            auto cur_func{ module_base + functions[ ordinals[ idx ] ] };
            if ( !cur_name || !cur_func )
                continue;

            if ( std::strcmp( export_name, reinterpret_cast< char* >( cur_name ) ) )
                return cur_func;
        }

        return 0;
    }

    bool find_section( const char* section_name, std::uint64_t* exec_base, std::uint64_t* exec_size ) {
        auto dos_header{ reinterpret_cast< dos_header_t* > ( m_ntoskrnl_base ) };
        auto nt_headers{ reinterpret_cast< nt_headers_t* > ( m_ntoskrnl_base + dos_header->m_lfanew ) };
        if ( !dos_header->is_valid( )
            || !nt_headers->is_valid( ) )
            return false;

        auto section_header = reinterpret_cast< section_header_t* >(
            reinterpret_cast< std::uintptr_t >( nt_headers ) +
            nt_headers->m_size_of_optional_header + 0x18 );

        for ( int i = 0; i < nt_headers->m_number_of_sections; i++ ) {
            auto current_section_base = reinterpret_cast< std::uint64_t >( dos_header ) + section_header[ i ].m_virtual_address;
            if ( !strcmp( section_header[ i ].m_name, section_name ) ) {
                *exec_base = current_section_base;
                *exec_size = section_header[ i ].m_size_of_raw_data;
                break;
            }
        }

        return *exec_base && *exec_size;
    }
}