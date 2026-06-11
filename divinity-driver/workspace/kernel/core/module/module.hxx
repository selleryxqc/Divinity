#pragma once

namespace module {
    std::uint64_t get_module_base( const wchar_t* module_name, std::uint64_t* module_size = nullptr ) {
        unicode_string_t module_name_string{ };
        kernel::rtl_init_unicode_string( &module_name_string, module_name );

        auto ps_loaded_module_list = reinterpret_cast< list_entry_t* >(
            kernel::get_export( kernel::m_ntoskrnl_base, oxorany( "PsLoadedModuleList" ) )
            );
        if ( !ps_loaded_module_list )
            return false;

        auto iter_ldr_entry = reinterpret_cast< kldr_data_table_entry_t* >(
            ps_loaded_module_list->m_flink
            );

        while ( reinterpret_cast< list_entry_t* >( iter_ldr_entry ) != ps_loaded_module_list ) {
            if ( !kernel::rtl_compare_unicode_string( &iter_ldr_entry->m_base_dll_name, &module_name_string, true ) ) {
                if ( module_size )
                    *module_size = iter_ldr_entry->m_size_of_image;
                return reinterpret_cast< std::uintptr_t >( iter_ldr_entry->m_dll_base );
            }

            iter_ldr_entry = reinterpret_cast< kldr_data_table_entry_t* >(
                iter_ldr_entry->m_in_load_order_links.m_flink
                );
        }

        return 0;
    }

    std::uint64_t is_inside_module( std::uint64_t address ) {
        auto ps_loaded_module_list = reinterpret_cast< list_entry_t* >(
            kernel::get_export( kernel::m_ntoskrnl_base, oxorany( "PsLoadedModuleList" ) )
            );
        if ( !ps_loaded_module_list )
            return false;

        auto iter_ldr_entry = reinterpret_cast< kldr_data_table_entry_t* >(
            ps_loaded_module_list->m_flink
            );

        while ( reinterpret_cast< list_entry_t* >( iter_ldr_entry ) != ps_loaded_module_list ) {
            auto size_of_image = iter_ldr_entry->m_size_of_image;
            auto dll_base = reinterpret_cast< std::uint64_t >( iter_ldr_entry->m_dll_base );
            if ( address >= dll_base &&
                address < ( dll_base + size_of_image ) ) {
                return dll_base;
            }

            iter_ldr_entry = reinterpret_cast< kldr_data_table_entry_t* >(
                iter_ldr_entry->m_in_load_order_links.m_flink
                );
        }

        return 0;
    }

    std::uint64_t allocate_large_page( std::uint64_t module_base, std::size_t space_size ) {
        auto dos_header = reinterpret_cast< dos_header_t* >( module_base );
        if ( !dos_header->is_valid( ) )
            return 0;

        auto nt_headers = reinterpret_cast< nt_headers_t* >( module_base + dos_header->m_lfanew );
        if ( !nt_headers->is_valid( ) )
            return 0;

        auto section_header = reinterpret_cast< section_header_t* >(
            reinterpret_cast< std::uintptr_t >( nt_headers ) +
            nt_headers->m_size_of_optional_header + 0x18 );

        for ( auto idx = 0; idx < nt_headers->m_number_of_sections; idx++ ) {
            if ( ( section_header[ idx ].m_characteristics & 0x20000000 ) )
                continue;

            auto section_base = module_base + section_header[ idx ].m_virtual_address;
            auto section_size = section_header[ idx ].m_virtual_size;

            auto target_address = mmu::find_unused_space(
                reinterpret_cast < void* >( section_base ),
                section_size,
                space_size
            );

            if ( !target_address )
                continue;

            paging::pt_entries_t pt_entries;
            if ( !paging::hyperspace_entries( pt_entries, target_address ) )
                continue;

            if ( pt_entries.m_pdpte.hard.page_size ) {
                kernel::dbg_print( oxorany( "[divinity] splitting 1gb page to 4kb\n" ) );

                if ( !paging::split_1gb_to_4kb( target_address ) ) {
                    kernel::dbg_print( oxorany( "[divinity] could not split 1gb page to 4kb\n" ) );
                    continue;
                }
            }

            if ( pt_entries.m_pde.hard.page_size ) {
                kernel::dbg_print( oxorany( "[divinity] splitting 2mb page to 4kb\n" ) );

                if ( !paging::split_2mb_to_4kb( target_address ) ) {
                    kernel::dbg_print( oxorany( "[divinity] could not split 2mb page to 4kb\n" ) );
                    continue;
                }
            }

            auto pte_address = paging::get_pte_address( target_address );
            if ( !pte_address )
                continue;

            if ( !paging::set_page_protection( target_address, paging::page_protection::readwrite_execute ) ) {
                kernel::dbg_print( oxorany( "[divinity] could not change 2mb page protection\n" ) );
                continue;
            }

            return target_address;
        }

        return 0;
    }

    std::uint64_t allocate_between_modules( std::uint32_t size, kldr_data_table_entry_t** ldr_entry = nullptr, std::size_t* module_size = nullptr ) {
        const auto page_mask = paging::page_4kb_size - 1;
        const auto aligned_size = ( size + page_mask ) & ~page_mask;
        const auto page_count = aligned_size >> paging::page_shift;

        auto ps_loaded_module_list = reinterpret_cast< list_entry_t* >(
            kernel::get_export( kernel::m_ntoskrnl_base, oxorany( "PsLoadedModuleList" ) )
            );
        if ( !ps_loaded_module_list )
            return 0;

        auto iter_ldr_entry = reinterpret_cast< kldr_data_table_entry_t* >(
            ps_loaded_module_list->m_flink
            );

        std::uint64_t allocation_base = 0;
        kldr_data_table_entry_t* prev_ldr_entry = nullptr;

        while ( reinterpret_cast< list_entry_t* >( iter_ldr_entry ) != ps_loaded_module_list ) {
            auto module_start = reinterpret_cast< std::uint64_t >( iter_ldr_entry->m_dll_base );

            if ( prev_ldr_entry ) {
                auto prev_module_end = reinterpret_cast< std::uint64_t >( prev_ldr_entry->m_dll_base ) +
                    prev_ldr_entry->m_size_of_image;
                auto gap_start = ( prev_module_end + 0xFFF ) & ~0xFFF;

                if ( gap_start < module_start ) {
                    auto gap_size = module_start - gap_start;

                    if ( gap_size >= aligned_size ) {
                        allocation_base = gap_start;

                        auto new_module_end = allocation_base + aligned_size;
                        auto new_size = new_module_end -
                            reinterpret_cast< std::uint64_t >( prev_ldr_entry->m_dll_base );
                        new_size = ( new_size + 0xFFF ) & ~0xFFF;

                        if ( ldr_entry ) *ldr_entry = prev_ldr_entry;
                        if ( module_size ) *module_size = prev_ldr_entry->m_size_of_image;

                        prev_ldr_entry->m_size_of_image = static_cast< std::uint32_t >( new_size );
                        break;
                    }
                }
            }

            prev_ldr_entry = iter_ldr_entry;
            iter_ldr_entry = reinterpret_cast< kldr_data_table_entry_t* >(
                iter_ldr_entry->m_in_load_order_links.m_flink
                );
        }

        if ( !allocation_base ) {
            kernel::dbg_print( oxorany( "[c_module] allocate_between_modules: Could not find gap between modules\n" ) );
            return 0;
        }

        if ( !paging::map_pte_entry( allocation_base, size ) ) {
            kernel::dbg_print( oxorany( "[c_module] allocate_between_modules: Could not map page tables\n" ) );
            return 0;
        }

        return allocation_base;
    }

    std::uint64_t allocate_cow_pages( std::size_t space_size ) {
        auto ps_loaded_module_list = reinterpret_cast< list_entry_t* >(
            kernel::get_export( kernel::m_ntoskrnl_base, oxorany( "PsLoadedModuleList" ) )
            );
        if ( !ps_loaded_module_list )
            return 0;

        auto iter_entry = reinterpret_cast< kldr_data_table_entry_t* >(
            ps_loaded_module_list->m_flink
            );

        while ( reinterpret_cast< list_entry_t* >( iter_entry ) != ps_loaded_module_list ) {
            auto module_base = reinterpret_cast< std::uint64_t >( iter_entry->m_dll_base );
            if ( module_base != kernel::m_ntoskrnl_base )
                continue;

            auto dos_header = reinterpret_cast< dos_header_t* >( module_base );
            if ( !dos_header->is_valid( ) ) {
                iter_entry = reinterpret_cast< kldr_data_table_entry_t* >(
                    iter_entry->m_in_load_order_links.m_flink );
                continue;
            }

            auto nt_headers = reinterpret_cast< nt_headers_t* >( module_base + dos_header->m_lfanew );
            if ( !nt_headers->is_valid( ) ) {
                iter_entry = reinterpret_cast< kldr_data_table_entry_t* >(
                    iter_entry->m_in_load_order_links.m_flink );
                continue;
            }

            auto section_header = reinterpret_cast< section_header_t* >(
                reinterpret_cast< std::uintptr_t >( nt_headers ) +
                nt_headers->m_size_of_optional_header + 0x18 );

            for ( auto idx = 0; idx < nt_headers->m_number_of_sections; idx++ ) {
                if ( section_header[ idx ].m_characteristics & 0x20000000 )
                    continue;

                auto section_base = module_base + section_header[ idx ].m_virtual_address;
                auto section_size = section_header[ idx ].m_virtual_size;

                if ( section_size < space_size )
                    continue;

                auto target_address = mmu::find_unused_space(
                    reinterpret_cast< void* >( section_base ),
                    section_size,
                    space_size
                );

                if ( !target_address )
                    continue;

                paging::pt_entries_t pt_entries;
                if ( !paging::hyperspace_entries( pt_entries, target_address ) )
                    continue;

                if ( pt_entries.m_pdpte.hard.page_size ) {
                    if ( !paging::split_1gb_to_4kb( target_address ) )
                        continue;
                    if ( !paging::hyperspace_entries( pt_entries, target_address ) )
                        continue;
                    continue;
                }

                if ( pt_entries.m_pde.hard.page_size ) {
                    if ( !paging::split_2mb_to_4kb( target_address ) )
                        continue;
                    if ( !paging::hyperspace_entries( pt_entries, target_address ) )
                        continue;
                    continue;
                }

                if ( !pt_entries.m_pte.hard.present )
                    continue;

                auto pte_address = paging::get_pte_address( target_address );
                if ( !pte_address )
                    continue;

                std::uint64_t physical_address;
                if ( !paging::translate_linear( target_address, &physical_address ) )
                    continue;

                auto result = kernel::mi_copy_on_write(
                    target_address,
                    reinterpret_cast< std::uint64_t* >( pte_address ),
                    static_cast< std::uint64_t >( -1 )
                );

                if ( result ) {
                    kernel::dbg_print( oxorany( "[COW] MiCopyOnWrite failed for %llx: %x\n" ),
                        target_address, result );
                    continue;
                }

                kernel::dbg_print( oxorany( "[COW] success at %llx in %wZ\n" ),
                    target_address, &iter_entry->m_base_dll_name );

                return target_address;
            }

            iter_entry = reinterpret_cast< kldr_data_table_entry_t* >(
                iter_entry->m_in_load_order_links.m_flink );
        }

        return 0;
    }
}