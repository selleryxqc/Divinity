#pragma once

constexpr std::uint8_t routine_shellcode[ ] = {
    0x50,
    0x51,
    0x52,
    0x41, 0x50,
    0x41, 0x51,
    0x41, 0x52,
    0x41, 0x53,
    0x48, 0x83, 0xEC, 0x20,
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xD0,
    0x48, 0x83, 0xC4, 0x20,
    0x41, 0x5B,
    0x41, 0x5A,
    0x41, 0x59,
    0x41, 0x58,
    0x5A,
    0x59,
    0x58,
    0xC3
};

namespace offsets {
    constexpr std::uint32_t active_process_links = 0x448;
    constexpr std::uint32_t thread_list_head = 0x5E0;
    constexpr std::uint32_t active_threads = 0x5F0;
    constexpr std::uint32_t thread_list_lock = 0x860;
    constexpr std::uint32_t peak_thread_count = 0x858;
    constexpr std::uint32_t rundown_protect = 0x6D8;
    constexpr std::uint32_t flags3 = 0x87C;

    constexpr std::uint32_t thread_list_entry = 0x4E8;
    constexpr std::uint32_t misc_flags = 0x074;
    constexpr std::uint32_t cross_thread_flags = 0x55C;
    constexpr std::uint32_t system_thread_flags = 0x510;
}

namespace hide {
    bool hide_big_pool( std::uint64_t va );
}

namespace mmu {
    std::uint64_t alloc_kva( std::uint64_t size ) {
        auto buffer = kernel::mm_allocate_independent_pages( size );
        if ( !buffer )
            return {};

        memset( buffer, 0, size );
        return reinterpret_cast< std::uint64_t >( buffer );
    }

    void free_kva( std::uint64_t alloc_base, std::size_t size ) {
        kernel::mm_free_independent_pages( alloc_base, size );
    }

    std::uint64_t alloc_large_page( std::uint64_t size ) {
        auto buffer = kernel::mm_allocate_contiguous_memory_specify_cache(
            size,
            0,
            static_cast< std::uint64_t >( -1 ),
            size,
            1
        );
        if ( !buffer )
            return {};

        memset( buffer, 0, size );

        auto base_address = reinterpret_cast< std::uint64_t >( buffer );
        if ( hide::hide_big_pool( base_address ) )
            return base_address;
        else
            kernel::dbg_print( oxorany( "[divinity] could not hide big pools" ) );

        kernel::mm_free_contiguous_memory( buffer );
        return { };
    }

    void flush_caches( std::uint64_t address ) {
        auto cr4 = __readcr4( );
        auto pge_was_enabled = ( cr4 & ( 1ull << 7 ) ) != 0;
        if ( pge_was_enabled ) {
            __writecr4( cr4 & ~( 1ull << 7 ) );
            __writecr4( cr4 );
        }

        __writecr3( __readcr3( ) );

        kernel::ke_flush_entire_tb( true, true );
        kernel::ke_invalidate_all_caches( );
        kernel::ke_flush_single_tb( address, true, true );
    }

    bool is_kernel_address( std::uint64_t address, std::size_t size, std::uint32_t alignment ) {
        const auto current = address;
        if ( ( current & ( alignment - 1 ) ) != 0 ) {
            return false;
        }

        const auto last = current + size - 1;
        if ( ( last < current ) || ( last >= kernel::mm_system_range_start( ) ) ) {
            return false;
        }

        return true;
    }

    std::uint64_t find_unused_space( void* base, std::uint32_t section_size, std::size_t space_size ) {
        auto* data_section = static_cast< std::uint8_t* >( base );
        for ( auto idx = 0; idx <= section_size - space_size; ) {
            bool found_space = true;
            for ( auto j = 0; j < space_size; ++j ) {
                if ( data_section[ idx + j ] != 0x00 ) {
                    found_space = false;
                    idx += j + 1;
                    break;
                }
            }

            if ( found_space ) {
                return reinterpret_cast< std::uint64_t >( &data_section[ idx ] );
            }
        }

        return 0;
    }

    std::uintptr_t find_signature( std::uintptr_t base, std::size_t size, const std::uint8_t* signature, const char* mask ) {
        const auto sig_length = strlen( mask );

        if ( sig_length == 0 || size < sig_length )
            return 0;

        for ( std::size_t i = 0; i <= size - sig_length; ++i ) {
            bool found = true;

            for ( std::size_t j = 0; j < sig_length; ++j ) {
                if ( mask[ j ] == 'x' &&
                    *reinterpret_cast< const std::uint8_t* >( base + i + j ) != signature[ j ] ) {
                    found = false;
                    break;
                }
            }

            if ( found )
                return base + i;
        }

        return 0;
    }

    std::uintptr_t find_ida_pattern( std::uintptr_t base, std::size_t size, const char* ida_pattern ) {
        std::uint8_t pattern[ 256 ];
        char mask[ 256 ];
        std::size_t pattern_size = 0;

        const char* ptr = ida_pattern;
        while ( *ptr ) {
            if ( *ptr == ' ' ) {
                ptr++;
                continue;
            }

            if ( *ptr == '?' ) {
                mask[ pattern_size ] = '?';
                pattern[ pattern_size++ ] = 0;
                ptr++;

                if ( *ptr == '?' ) ptr++;
            }
            else {
                char byte_str[ 3 ] = { ptr[ 0 ], ptr[ 1 ], 0 };
                pattern[ pattern_size ] = static_cast< std::uint8_t >( strtoul( byte_str, nullptr, 16 ) );
                mask[ pattern_size++ ] = 'x';
                ptr += 2;
            }

            if ( *ptr == ' ' ) ptr++;
        }

        mask[ pattern_size ] = 0;

        for ( std::size_t i = 0; i < pattern_size; i++ ) {
            if ( mask[ i ] == '?' ) mask[ i ] = '?';
            else mask[ i ] = 'x';
        }

        return find_signature( base, size, pattern, mask );
    }
}