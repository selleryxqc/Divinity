#pragma once

namespace portal {
    struct clone_allocation_t {
        std::uint64_t m_target_va;
        std::uint64_t m_exposed_va;
        std::size_t   m_size;
    };

    class c_portal {
    public:
        std::uint64_t m_base_address = 0;
        std::uint64_t m_image_base = 0;
        std::uint32_t m_image_size = 0;

        bool clone_process( eprocess_t* process ) {
            auto current_pid = GetCurrentProcessId( );
            this->m_client_process = g_driver->get_eprocess( current_pid );
            if ( !m_client_process ) {
                logging::print( oxorany( "Could not get client process." ) );
                return false;
            }

            this->m_target_process = process;
            if ( !g_driver->clone_in_hyperspace( m_target_process ) ) {
                logging::print( oxorany( "Could not portal to process." ) );
                return false;
            }

            // We should never need to context swap to the clone directory table base.
            // This is because we always want to stay inside of the process context for stability.
            const auto [ clone_process, directory_table_base ] = g_driver->get_hyperspace_context( m_target_process );
            if ( !clone_process || !directory_table_base ) {
                logging::print( oxorany( "Could not get portal context." ) );
                return false;
            }

            this->m_clone_process = clone_process;
            logging::print( oxorany( "Cloned virtual address space" ) );
            return true;
        }

        bool expose_memory( std::uint64_t image_base ) {
            auto image_size = this->get_image_size( image_base );
            if ( !image_size )
                return false;

            this->m_image_base = image_base;
            this->m_image_size = image_size;

            this->m_base_address = g_driver->expose_pages(
                m_target_process,
                m_client_process,
                image_base,
                image_size
            );

            if ( !m_base_address )
                return false;

            this->m_exposed_memory = true;
            logging::print( oxorany( "Clone exposed: 0x%llx (0x%x)" ), m_base_address, m_image_size );
            return true;
        }

        bool update_memory( ) {
            if ( !m_exposed_memory )
                return false;

            return g_driver->rexpose_pages(
                m_target_process,
                m_client_process
            );
        }

        std::uint64_t allocate_virtual( std::size_t size ) {
            auto base_address = g_driver->allocate_virtual( m_target_process, size );
            if ( !base_address )
                return 0;

            auto clone_address = expose_clone_memory( base_address, size );
            if ( !clone_address ) {
                g_driver->free_virtual( m_target_process, base_address );
                return 0;
            }

            m_clone_allocations.push_back( { base_address, clone_address, size } );
            return clone_address;
        }

        bool free_virtual( std::uint64_t exposed_va ) {
            if ( !exposed_va )
                return false;

            auto it = std::find_if( m_clone_allocations.begin( ), m_clone_allocations.end( ),
                [ & ]( const clone_allocation_t& a ) { return a.m_exposed_va == exposed_va; } );

            if ( it == m_clone_allocations.end( ) ) {
                logging::print( oxorany( "free_virtual: no allocation found for 0x%llx\n" ), exposed_va );
                return false;
            }

            g_driver->free_virtual( m_target_process, it->m_target_va );
            m_clone_allocations.erase( it );
            return true;
        }

        std::uint32_t find_thread_id( bool best_delta ) const {
            if ( !m_clone_process )
                return 0;

            auto target_pid = g_driver->get_process_id( m_clone_process );
            if ( !target_pid )
                return 0;

            auto result_tid  = 0;
            auto best_value  = best_delta ? MAXDWORD : 0;

            auto snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
            if ( snapshot == INVALID_HANDLE_VALUE )
                return 0;

            THREADENTRY32 te32{ .dwSize = sizeof( THREADENTRY32 ) };
            if ( Thread32First( snapshot, &te32 ) ) {
                do {
                    if ( te32.th32OwnerProcessID != target_pid )
                        continue;

                    if ( best_delta ) {
                        if ( te32.tpDeltaPri < best_value ) {
                            best_value  = te32.tpDeltaPri;
                            result_tid  = te32.th32ThreadID;
                        }
                    } else {
                        if ( te32.tpBasePri > best_value ) {
                            best_value  = te32.tpBasePri;
                            result_tid  = te32.th32ThreadID;
                        }
                    }
                } while ( Thread32Next( snapshot, &te32 ) );
            }

            logging::print( oxorany( "Thread TID: %d" ), result_tid );
            CloseHandle( snapshot );
            return result_tid;
        }

        ethread_t* find_thread( bool best_delta = true ) const {
            auto tid = find_thread_id( best_delta );
            if ( !tid )
                return nullptr;

            return g_driver->lookup_thread( tid );
        }

        std::uint64_t scan( const char* pattern ) const {
            if ( !m_exposed_memory || !m_base_address )
                return 0;

            std::uint8_t bytes[ 256 ] = {};
            std::string  mask;
            if ( !parse_pattern( pattern, bytes, mask ) )
                return 0;

            auto data = reinterpret_cast< const std::uint8_t* >( m_base_address );
            auto pattern_len = mask.size( );

            for ( std::size_t i = 0; i < m_image_size - pattern_len; i++ ) {
                if ( match( data + i, bytes, mask.c_str( ) ) )
                    return m_image_base + i;
            }

            return 0;
        }

        std::vector< std::uint64_t > scan_all( const char* pattern ) const {
            std::vector< std::uint64_t > results;
            if ( !m_exposed_memory || !m_base_address )
                return results;

            std::uint8_t bytes[ 256 ] = {};
            std::string  mask;
            if ( !parse_pattern( pattern, bytes, mask ) )
                return results;

            auto data = reinterpret_cast< const std::uint8_t* >( m_base_address );
            auto pattern_len = mask.size( );

            for ( std::size_t i = 0; i < m_image_size - pattern_len; i++ ) {
                if ( match( data + i, bytes, mask.c_str( ) ) )
                    results.push_back( m_base_address + i );
            }

            return results;
        }

        std::uint64_t resolve_rip( std::uint64_t target_va, std::uint32_t rel32_offset, std::uint32_t instr_size ) const {
            if ( !m_exposed_memory || !m_base_address )
                return 0;

            auto exposed_va = to_exposed_va( target_va );
            if ( !exposed_va )
                return 0;

            auto rel32 = *reinterpret_cast< std::int32_t* >( exposed_va + rel32_offset );
            auto result = target_va + instr_size + rel32;
            return result;
        }

        std::uint64_t find_gadget(
            const char* pattern,
            std::size_t len
        ) {
            auto data = reinterpret_cast< std::uint8_t* >( m_base_address );
            for ( std::size_t i = 0; i < m_image_size - len; i++ ) {
                if ( std::memcmp( data + i, pattern, len ) == 0 ) {
                    return to_target_va( m_base_address + i );
                }
            }
            return 0;
        }

        template< typename type >
        type read( std::uint64_t target_va ) const {
            auto exposed_va = to_exposed_va( target_va );
            if ( !exposed_va )
                return type{ };
            return *reinterpret_cast< type* >( exposed_va );
        }

        template< typename type >
        void write( std::uint64_t target_va, type value ) {
            auto exposed_va = to_exposed_va( target_va );
            if ( !exposed_va )
                return;
            *reinterpret_cast< type* >( exposed_va ) = value;
        }

        std::uint64_t to_target_va( std::uint64_t exposed_va ) const {
            if ( !exposed_va || exposed_va < m_base_address ||
                exposed_va >= m_base_address + m_image_size )
                return 0;
            return m_image_base + ( exposed_va - m_base_address );
        }

        std::uint64_t to_exposed_va( std::uint64_t target_va ) const {
            if ( !target_va || target_va < m_image_base ||
                target_va >= m_image_base + m_image_size )
                return 0;
            return m_base_address + ( target_va - m_image_base );
        }

        std::uint32_t get_image_size( std::uint64_t image_base ) {
            auto dos_header = g_driver->read< dos_header_t >( image_base );
            if ( !dos_header.is_valid( ) ) return 0;

            auto nt_headers = g_driver->read< nt_headers_t >( image_base + dos_header.m_lfanew );
            if ( !nt_headers.is_valid( ) ) return 0;
            return nt_headers.m_size_of_image;
        }

    private:
        eprocess_t* m_target_process{ nullptr };
        eprocess_t* m_client_process{ nullptr };
        eprocess_t* m_clone_process{ nullptr };
        bool m_exposed_memory = false;
        ethread_t* m_exposed_thread{ nullptr };
        std::vector< clone_allocation_t > m_clone_allocations;

        static bool parse_pattern( const char* pattern, std::uint8_t* bytes, std::string& mask ) {
            mask.clear( );
            auto p = pattern;
            while ( *p ) {
                while ( *p == ' ' ) p++;
                if ( !*p ) break;
                if ( *p == '?' ) {
                    bytes[ mask.size( ) ] = 0x00;
                    mask += '?';
                    p++;
                    if ( *p == '?' ) p++;
                }
                else {
                    char hex[ 3 ] = { p[ 0 ], p[ 1 ], 0 };
                    bytes[ mask.size( ) ] = static_cast< std::uint8_t >( std::strtoul( hex, nullptr, 16 ) );
                    mask += 'x';
                    p += 2;
                }
            }
            return !mask.empty( );
        }

        static bool match( const std::uint8_t* data, const std::uint8_t* bytes, const char* mask ) {
            for ( ; *mask; ++data, ++bytes, ++mask ) {
                if ( *mask == 'x' && *data != *bytes )
                    return false;
            }
            return true;
        }

        std::uint64_t expose_memory( std::uint64_t address, std::size_t size ) {
            return g_driver->expose_pages(
                m_target_process, m_client_process,
                address, size
            );
        }

        std::uint64_t expose_clone_memory( std::uint64_t address, std::size_t size ) {
            return g_driver->expose_clone_pages(
                m_target_process, m_client_process,
                address, size
            );
        }
    };
}