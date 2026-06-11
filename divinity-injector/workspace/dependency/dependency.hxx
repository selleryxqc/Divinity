#pragma once
#include <random>

namespace dependency {
    struct thread_context_t {
        CONTEXT m_context = {};
        bool m_executed = false;
        bool m_result = false;
    };

    struct exec_context_t {
        std::uint32_t m_status;
        std::uint64_t m_result;
    };

    struct module_range_t {
        std::uint64_t m_base;
        std::uint64_t m_size;
    };

    static std::unordered_map<std::wstring, std::uint64_t> m_mapped_modules;
    static SRWLOCK m_mapped_modules_lock = SRWLOCK_INIT;

    class c_dependency {
    public:
        c_dependency( const std::string& file_path ) {
            m_dependency_name = utility::ansi_to_wstring( file_path );

            std::ifstream file( file_path, std::ios::binary | std::ios::ate );
            if ( !file.is_open( ) ) {
                logging::print( oxorany( "Failed to open file: %s" ), file_path.c_str( ) );
                return;
            }

            const auto file_size = file.tellg( );
            m_dependency.resize( static_cast< size_t >( file_size ) );

            file.seekg( 0, std::ios::beg );
            if ( !file.read( reinterpret_cast< char* >( m_dependency.data( ) ), file_size ) ) {
                logging::print( oxorany( "Failed to read file: %s" ), file_path.c_str( ) );
                m_dependency.clear( );
                return;
            }

            this->m_dos_header = reinterpret_cast
                < dos_header_t* >( m_dependency.data( ) );
            if ( !m_dos_header->is_valid( ) ) {
                logging::print( oxorany( "Invalid DOS signature in: %s" ), file_path.c_str( ) );
                m_dependency.clear( );
                return;
            }

            this->m_nt_headers = reinterpret_cast
                < nt_headers_t* >( m_dependency.data( ) + m_dos_header->m_lfanew );
            if ( !m_nt_headers->is_valid( ) ) {
                logging::print( oxorany( "Invalid NT headers in: %s" ), file_path.c_str( ) );
                m_dependency.clear( );
                return;
            }

            this->m_section_header = reinterpret_cast< section_header_t* >( reinterpret_cast
                < std::uintptr_t >( m_nt_headers ) + m_nt_headers->m_size_of_optional_header + 0x18 );
            return;
        }

        bool is_dll( ) const {
            if ( !m_nt_headers )
                return false;

            return ( m_nt_headers->m_characteristics & 0x2000 );
        }

        bool map( ) {
            if ( !this->add_section( oxorany( ".exec" ), sizeof( exec_context_t ) ) ||
                !this->add_section( oxorany( ".ctx" ), sizeof( thread_context_t ) ) ) {
                logging::print( oxorany( "Could not allocate sections\n" ) );
                return false;
            }

            this->m_dependency_size = this->size_of_image( );
            this->m_dependency_base  = g_portal->allocate_virtual( m_dependency_size );
            if ( !m_dependency_base ) {
                logging::print( oxorany( "Failed to allocate virtual\n" ) );
                return false;
            }

            logging::print( oxorany( "Allocated base: 0x%llx (0x%x)" ), m_dependency_base, m_dependency_size );

            if ( !this->map_relocs( m_dependency_base ) ) {
                logging::print( oxorany( "Failed to map relocs\n" ) );
                return false;
            }

            logging::print( oxorany( "Relocations applied" ) );

            if ( !this->map_imports( ) ) {
                logging::print( oxorany( "Failed to map imports\n" ) );
                return false;
            }

            logging::print( oxorany( "Imports resolved" ) );

            if ( !this->map_sections( m_dependency_base ) ) {
                logging::print( oxorany( "Failed to map sections\n" ) );
                return false;
            }

            logging::print( oxorany( "Sections mapped" ) );

            return true;
        }

        bool inject( ) {
            static int reinject_attempts = 0;
            constexpr int max_reinject_attempts = 3;

            auto entry_point = this->get_export( oxorany( "DllMain" ) );
            if ( !entry_point ) {
                logging::print( oxorany( "Failed to find DllMain\n" ) );
                return false;
            }

            entry_point += m_dependency_base;
            logging::print( oxorany( "Entry point: 0x%llx\n" ), entry_point );

        reinject:
            auto status_initializing = 1;
            auto status_executing = 2;
            auto status_complete = 3;

            auto thread_id = g_portal->find_thread_id( false );
            if ( !thread_id ) {
                logging::print( oxorany( "Failed to find thread id" ) );
                return false;
            }

            auto thread_object = g_driver->lookup_thread( thread_id );
            if ( !thread_object ) {
                logging::print( oxorany( "Failed to lookup thread object" ) );
                return false;
            }

            if ( !g_driver->suspend_thread( thread_object ) ) {
                logging::print( oxorany( "Failed to suspend thread" ) );
                return false;
            }

            logging::print( oxorany( "Thread suspended" ) );

            thread_context_t thread_context;
            if ( !g_driver->get_thread_context( thread_object, &thread_context.m_context ) ) {
                logging::print( oxorany( "Failed to get thread context" ) );
                g_driver->resume_thread( thread_object );
                return false;
            }

            /*
            *    .ctx allocated section
            * Dlls can find this section through the reserved parameter
            * this is used to restore the thread context in DllMain

            * restoring the thread context through DllMain leads to early return but is more reliable than handling it in shellcode
            * the thread returns early so we track execution through the context

            *    .exec allocated section
            * Dlls don't need to handle restoring the thread context through DllMain
            * if they do not we track the execution state through the shellcode
            */

            auto context_va = reinterpret_cast< thread_context_t* >(
                m_dependency_base + get_section_by_name( oxorany( ".ctx" ) )->m_virtual_address );
            *context_va = thread_context;

            auto original_rip = thread_context.m_context.Rip;
            logging::print( oxorany( "Original RIP: 0x%llX" ), original_rip );

            const auto shellcode_size = 256;
            auto shellcode_address = g_portal->allocate_virtual( shellcode_size );
            if ( !shellcode_address ) {
                logging::print( oxorany( "Failed to allocate shellcode memory" ) );
                g_driver->resume_thread( thread_object );
                return false;
            }

            auto section_va = m_dependency_base + get_section_by_name( oxorany( ".exec" ) )->m_virtual_address;
            auto flags_va = reinterpret_cast< std::uint32_t* >( section_va + offsetof( exec_context_t, m_status ) );
            auto result_va = reinterpret_cast< std::uint32_t* >( section_va + offsetof( exec_context_t, m_result ) );

            std::vector<std::uint8_t> shellcode;
            shellcode.insert( shellcode.end( ), { 0x50 } );
            shellcode.insert( shellcode.end( ), { 0x51 } );
            shellcode.insert( shellcode.end( ), { 0x52 } );
            shellcode.insert( shellcode.end( ), { 0x41, 0x50 } );
            shellcode.insert( shellcode.end( ), { 0x41, 0x51 } );
            shellcode.insert( shellcode.end( ), { 0x41, 0x52 } );
            shellcode.insert( shellcode.end( ), { 0x41, 0x53 } );
            shellcode.insert( shellcode.end( ), { 0x48, 0x89, 0xE5 } );

            shellcode.insert( shellcode.end( ), { 0x48, 0x83, 0xE4, 0xF0 } );
            shellcode.insert( shellcode.end( ), { 0x48, 0x83, 0xEC, 0x20 } );

            shellcode.insert( shellcode.end( ), { 0x48, 0xB8 } );
            shellcode.insert( shellcode.end( ),
                reinterpret_cast < std::uint8_t* >( &flags_va ),
                reinterpret_cast < std::uint8_t* >( &flags_va ) + sizeof( flags_va ) );

            shellcode.insert( shellcode.end( ), { 0xC7, 0x00 } );
            shellcode.insert( shellcode.end( ),
                reinterpret_cast < std::uint8_t* >( &status_initializing ),
                reinterpret_cast < std::uint8_t* >( &status_initializing ) + sizeof( status_initializing ) );

            shellcode.insert( shellcode.end( ), { 0x49, 0xB8 } );
            shellcode.insert(
                shellcode.end( ),
                reinterpret_cast< std::uint8_t* >( &context_va ),
                reinterpret_cast< std::uint8_t* >( &context_va ) + sizeof( context_va ) );

            shellcode.insert( shellcode.end( ), { 0x48, 0xB9 } );
            shellcode.insert(
                shellcode.end( ),
                reinterpret_cast< std::uint8_t* >( &m_dependency_base ),
                reinterpret_cast< std::uint8_t* >( &m_dependency_base ) + sizeof( m_dependency_base ) );

            shellcode.insert( shellcode.end( ), { 0x48, 0xB8 } );
            shellcode.insert( shellcode.end( ),
                reinterpret_cast < std::uint8_t* >( &flags_va ),
                reinterpret_cast < std::uint8_t* >( &flags_va ) + sizeof( flags_va ) );

            shellcode.insert( shellcode.end( ), { 0xC7, 0x00 } );
            shellcode.insert( shellcode.end( ),
                reinterpret_cast < std::uint8_t* >( &status_executing ),
                reinterpret_cast < std::uint8_t* >( &status_executing ) + sizeof( status_executing ) );

            shellcode.insert( shellcode.end( ), { 0x48, 0xB8 } );
            shellcode.insert( shellcode.end( ),
                reinterpret_cast < std::uint8_t* >( &entry_point ),
                reinterpret_cast < std::uint8_t* >( &entry_point ) + sizeof( entry_point ) );
            shellcode.insert( shellcode.end( ), { 0xFF, 0xD0 } );

            shellcode.insert( shellcode.end( ), { 0x48, 0xA3 } );
            shellcode.insert( shellcode.end( ),
                reinterpret_cast < std::uint8_t* >( &result_va ),
                reinterpret_cast < std::uint8_t* >( &result_va ) + sizeof( result_va ) );

            shellcode.insert( shellcode.end( ), { 0x48, 0xB8 } );
            shellcode.insert( shellcode.end( ),
                reinterpret_cast < std::uint8_t* >( &flags_va ),
                reinterpret_cast < std::uint8_t* >( &flags_va ) + sizeof( flags_va ) );

            shellcode.insert( shellcode.end( ), { 0xC7, 0x00 } );
            shellcode.insert( shellcode.end( ),
                reinterpret_cast < std::uint8_t* >( &status_complete ),
                reinterpret_cast < std::uint8_t* >( &status_complete ) + sizeof( status_complete ) );

            shellcode.insert( shellcode.end( ), { 0x48, 0x89, 0xEC } );
            shellcode.insert( shellcode.end( ), { 0x41, 0x5B } );
            shellcode.insert( shellcode.end( ), { 0x41, 0x5A } );
            shellcode.insert( shellcode.end( ), { 0x41, 0x59 } );
            shellcode.insert( shellcode.end( ), { 0x41, 0x58 } );
            shellcode.insert( shellcode.end( ), { 0x5A } );
            shellcode.insert( shellcode.end( ), { 0x59 } );
            shellcode.insert( shellcode.end( ), { 0x58 } );

            shellcode.insert( shellcode.end( ), { 0x48, 0xB8 } );
            shellcode.insert( shellcode.end( ),
                reinterpret_cast < std::uint8_t* >( &original_rip ),
                reinterpret_cast < std::uint8_t* >( &original_rip ) + sizeof( original_rip ) );
            shellcode.insert( shellcode.end( ), { 0xFF, 0xE0 } );

            std::memcpy(
                reinterpret_cast< void* >( shellcode_address ),
                shellcode.data( ), shellcode.size( )
            );

            logging::print( oxorany( "Shellcode written: 0x%llX (%zu bytes)" ),
                shellcode_address, shellcode.size( ) );

            thread_context.m_context.Rip = shellcode_address;
            if ( !g_driver->set_thread_context( thread_object, &thread_context.m_context ) ) {
                logging::print( oxorany( "Failed to set thread context" ) );
                g_driver->resume_thread( thread_object );
                g_portal->free_virtual( shellcode_address );
                return false;
            }

            logging::print( oxorany( "RIP hijacked: 0x%llX -> 0x%llX" ), original_rip, shellcode_address );
            logging::print( oxorany( "Thread RIP: 0x%llX" ),shellcode_address  );

            auto thread_handle = OpenThread( THREAD_QUERY_INFORMATION | SYNCHRONIZE, FALSE, thread_id );
            if ( !thread_handle ) {
                logging::print( oxorany( "Failed to open thread handle (err=%u)" ), GetLastError( ) );
                g_driver->resume_thread( thread_object );
                g_portal->free_virtual( shellcode_address );
                return false;
            }

            if ( !g_driver->resume_thread( thread_object ) ) {
                logging::print( oxorany( "Failed to resume thread" ) );
                CloseHandle( thread_handle ); 
                g_portal->free_virtual( shellcode_address );
                return false;
            }

            logging::print( oxorany( "Thread resumed, executing DllMain..." ) );

            auto watchdog_start = std::chrono::steady_clock::now( );
            auto watchdog_timeout = std::chrono::seconds( 10 );
            bool watchdog_success = true;

            while ( true ) {
                auto flags = *flags_va;
                if ( flags == status_complete || context_va->m_executed ) {
                    auto result = ( flags == status_complete ) ? *result_va : context_va->m_result;
                    if ( !result ) {
                        logging::print( oxorany( "DllMain unexpectedly failed" ) );
                        goto try_reinjection;
                    }

                    logging::print( oxorany( "DllMain returned: %llu" ), result );
                    break;
                }

                if ( !( flags == status_initializing || flags == status_executing ) ) {
                    if ( std::chrono::steady_clock::now( ) - watchdog_start > watchdog_timeout ) {
                        logging::print( oxorany( "Thread timeout during injection" ) );

                    try_reinjection:
                        reinject_attempts++;
                        if ( reinject_attempts >= max_reinject_attempts ) {
                            logging::print( oxorany( "Injection max attempts reached" ) );
                            CloseHandle( thread_handle );
                            return false;
                        }

                        logging::print( oxorany( "Reattempting injection (%d/%d)...\n" ),
                            reinject_attempts + 1, max_reinject_attempts );

                        g_portal->free_virtual( shellcode_address );
                        CloseHandle( thread_handle );
                        Sleep( 2000 );
                        goto reinject;
                    }
                }

                auto exit_code = STILL_ACTIVE;
                if ( !GetExitCodeThread( thread_handle, &exit_code ) ) {
                    logging::print( oxorany( "Could not get thread status: 0x%08X" ),
                        GetLastError( ) );
                    watchdog_success = false;
                    break;
                }

                if ( exit_code != STILL_ACTIVE ) {
                    if ( exit_code ) {
                        logging::print( oxorany( "Thread exited unexpectedly during injection: 0x%08X" ),
                            exit_code );
                    }

                    watchdog_success = !exit_code;
                    break;
                }

                if ( !g_driver->get_process_id( oxorany( process_name ) ) ) {
                    logging::print( oxorany( "Process exited unexpectedly during injection" ) );
                    watchdog_success = false;
                    break;
                }

                Sleep( 1 );
            }

            g_portal->free_virtual( shellcode_address );
            CloseHandle( thread_handle );

            if ( !watchdog_success )
                return false;

            logging::print( oxorany( "Injection complete" ) );
            logging::print( oxorany( "Press enter to continue" ) );
            return true;
        }

        bool cleanup( ) {
            auto section = m_section_header;
            for ( auto idx = 0; idx < m_nt_headers->m_number_of_sections; idx++, section++ ) {
                if ( section->m_characteristics & 0x02000000 ) {
                    auto size = section->m_virtual_size;
                    if ( !size )
                        continue;

                    auto dst = reinterpret_cast< void* >(
                        m_dependency_base + section->m_virtual_address );
                    std::memset( dst, 0, size );

                    char section_name[ 9 ] = { 0 };
                    memcpy( section_name, section->m_name, 8 );
                    logging::print( oxorany( "Erased: %.8s (0x%X bytes)" ), section_name, size );
                }
            }

            this->erase_strings( 64 );

            logging::print( oxorany( "Cleanup complete\n" ) );
            return true;
        }

        std::uint64_t get_base( ) const {
            return m_dependency_base;
        }

    private:
        std::wstring m_dependency_name{ };
        dos_header_t* m_dos_header{ nullptr };
        nt_headers_t* m_nt_headers{ nullptr };
        section_header_t* m_section_header{ nullptr };
        std::uint32_t m_dependency_size{ };
        std::uint64_t m_dependency_base{ };
        std::uint64_t m_section_base{ };
        std::vector<uint8_t> m_dependency{ };

        std::uint32_t size_of_image( ) const {
            return m_nt_headers->m_size_of_image;
        }

        bool map_relocs( std::uint64_t new_image_base ) {
            struct reloc_entry {
                std::uint32_t m_to_rva;
                std::uint32_t m_size;
                struct {
                    std::int16_t m_offset : 0xc;
                    std::int16_t m_type : 0x4;
                } m_item[ 0x1 ];
                std::int8_t m_pad0[ 0x2 ];
            };

            auto delta_offset{ new_image_base - m_nt_headers->m_image_base };
            auto reloc_ent{ reinterpret_cast< reloc_entry* >( rva_va( m_nt_headers->m_base_relocation_table.m_virtual_address ) ) };
            auto reloc_end{ reinterpret_cast< std::uintptr_t >( reloc_ent ) + m_nt_headers->m_base_relocation_table.m_size };
            if ( !reloc_ent ) {
                logging::print( oxorany( "No relocation table found" ) );
                return false;
            }

            std::uint32_t reloc_count = 0;
            while ( reinterpret_cast< std::uintptr_t >( reloc_ent ) < reloc_end && reloc_ent->m_size ) {
                auto records_count{ ( reloc_ent->m_size - sizeof( std::int8_t* ) ) >> 0x1 };
                for ( std::size_t i{}; i < records_count; i++ ) {
                    auto fix_type{ reloc_ent->m_item[ i ].m_type };
                    auto shift_delta{ reloc_ent->m_item[ i ].m_offset % 0x1000 };

                    if ( fix_type == 0x3 || fix_type == 0xa ) {
                        auto fix_va{ rva_va( reloc_ent->m_to_rva ) };
                        if ( !fix_va )
                            fix_va = reinterpret_cast< std::int8_t* >( m_dos_header );
                        *reinterpret_cast< std::uint64_t* >( fix_va + shift_delta ) += delta_offset;
                        reloc_count++;
                    }
                }

                reloc_ent = ( reloc_entry* )( ( std::uint8_t* )reloc_ent + reloc_ent->m_size );
            }

            logging::print( oxorany( "Applied relocations (delta: 0x%llX)" ), delta_offset );
            return true;
        }

        bool map_imports( ) {
            if ( !m_nt_headers->m_import_table.m_virtual_address ) {
                logging::print( oxorany( "No imports to resolve" ) );
                return true;
            }

            auto import_desc = reinterpret_cast< import_descriptor_t* >(
                rva_va( m_nt_headers->m_import_table.m_virtual_address ) );

            if ( !import_desc ) {
                logging::print( oxorany( "Failed to resolve import table RVA" ) );
                return false;
            }

            std::uint32_t module_count = 0;
            std::uint32_t import_count = 0;

            for ( auto descriptor = import_desc; descriptor->m_name; descriptor++ ) {
                auto module_name = reinterpret_cast< char* >( rva_va( descriptor->m_name ) );
                if ( !module_name ) {
                    logging::print( oxorany( "Failed to resolve module name RVA" ) );
                    return false;
                }

                module_count++;

                auto module_lib = LoadLibraryA( module_name );
                if ( !module_lib ) {
                    logging::print( oxorany( "Failed to load library: %s" ), module_name );
                    return false;
                }

                auto module_path = get_module_path( module_name, m_dependency_name );
                if ( module_path.empty( ) ) {
                    FreeLibrary( module_lib );
                    return false;
                }

                auto file_name = utility::strip_path( module_path );
                if ( file_name.empty( ) ) {
                    logging::print( oxorany( "Empty file name for module path: %ws" ), module_path.c_str( ) );
                    FreeLibrary( module_lib );
                    return false;
                }

                std::wstring file_name_lower = file_name;
                std::transform( file_name_lower.begin( ), file_name_lower.end( ),
                    file_name_lower.begin( ), ::towlower );

                auto module_base = g_driver->get_process_module( file_name.c_str( ) );
                if ( !module_base ) {
                    {
                        AcquireSRWLockShared( &m_mapped_modules_lock );
                        auto it = m_mapped_modules.find( file_name_lower );
                        if ( it != m_mapped_modules.end( ) ) {
                            if ( it->second == 0 ) {
                                ReleaseSRWLockShared( &m_mapped_modules_lock );
                                logging::print( oxorany( "Circular dependency detected: %ws, skipping" ), file_name.c_str( ) );
                                FreeLibrary( module_lib );
                                return false;
                            }
                            module_base = it->second;
                            ReleaseSRWLockShared( &m_mapped_modules_lock );
                            logging::print( oxorany( "Reusing already-mapped dependency: %ws at 0x%llX" ),
                                file_name.c_str( ), module_base );
                        }
                        else {
                            ReleaseSRWLockShared( &m_mapped_modules_lock );
                        }
                    }

                    if ( !module_base ) {
                        {
                            AcquireSRWLockExclusive( &m_mapped_modules_lock );
                            m_mapped_modules[ file_name_lower ] = 0;
                            ReleaseSRWLockExclusive( &m_mapped_modules_lock );
                        }

                        logging::print( oxorany( "Module not in target, mapping dependency: %ws" ),
                            file_name.c_str( ) );

                        auto dep_path_ansi = utility::wstring_to_ansi( module_path );
                        c_dependency dep( dep_path_ansi );

                        if ( !dep.map( ) ) {
                            logging::print( oxorany( "Failed to map dependency: %ws" ), file_name.c_str( ) );

                            AcquireSRWLockExclusive( &m_mapped_modules_lock );
                            m_mapped_modules.erase( file_name_lower );
                            ReleaseSRWLockExclusive( &m_mapped_modules_lock );

                            FreeLibrary( module_lib );
                            return false;
                        }

                        module_base = dep.get_base( );
                        if ( !module_base ) {
                            logging::print( oxorany( "Mapped dependency has no base: %ws" ), file_name.c_str( ) );

                            AcquireSRWLockExclusive( &m_mapped_modules_lock );
                            m_mapped_modules.erase( file_name_lower );
                            ReleaseSRWLockExclusive( &m_mapped_modules_lock );

                            FreeLibrary( module_lib );
                            return false;
                        }

                        logging::print( oxorany( "Dependency mapped at: 0x%llX" ), module_base );

                        {
                            AcquireSRWLockExclusive( &m_mapped_modules_lock );
                            m_mapped_modules[ file_name_lower ] = module_base;
                            ReleaseSRWLockExclusive( &m_mapped_modules_lock );
                        }
                    }
                }

                auto thunk = reinterpret_cast< image_thunk_data_t* >( rva_va( descriptor->m_first_thunk ) );
                if ( !thunk ) {
                    logging::print( oxorany( "Failed to resolve first thunk RVA" ) );
                    FreeLibrary( module_lib );
                    return false;
                }

                auto original_thunk_rva = descriptor->m_original_first_thunk ?
                    descriptor->m_original_first_thunk : descriptor->m_first_thunk;
                auto original_thunk = reinterpret_cast< image_thunk_data_t* >( rva_va( original_thunk_rva ) );

                if ( !original_thunk ) {
                    logging::print( oxorany( "Failed to resolve original thunk RVA" ) );
                    FreeLibrary( module_lib );
                    return false;
                }

                std::uint32_t func_count = 0;
                for ( auto current_thunk = thunk; original_thunk->m_u1.m_address_of_data; original_thunk++, current_thunk++ ) {
                    std::uint64_t function = 0;

                    if ( original_thunk->m_u1.m_ordinal & IMAGE_ORDINAL_FLAG64 ) {
                        auto ordinal = ( std::uint16_t )( original_thunk->m_u1.m_ordinal & 0xFFFF );
                        function = reinterpret_cast< std::uint64_t >( GetProcAddress( module_lib, ( LPCSTR )ordinal ) );
                    }
                    else {
                        auto import_name = reinterpret_cast< image_import_name_t* >(
                            rva_va( original_thunk->m_u1.m_address_of_data ) );

                        if ( !import_name ) {
                            logging::print( oxorany( "Failed to resolve import name RVA" ) );
                            FreeLibrary( module_lib );
                            return false;
                        }

                        function = reinterpret_cast< std::uint64_t >( GetProcAddress( module_lib, import_name->m_name ) );
                    }

                    if ( !function ) {
                        logging::print( oxorany( "Failed to resolve import in: %s" ), module_name );
                        FreeLibrary( module_lib );
                        return false;
                    }

                    auto target_base = module_base;
                    auto local_base = reinterpret_cast< std::uint64_t >( module_lib );

                    auto offset = function - local_base;
                    current_thunk->m_u1.m_function = target_base + offset;

                    func_count++;
                    import_count++;
                }

                FreeLibrary( module_lib );
            }

            logging::print( oxorany( "Resolved %u imports from %u modules" ), import_count, module_count );
            return true;
        }

        bool add_section( const char* section_name, std::uint32_t size ) {
            auto& num_sections = m_nt_headers->m_number_of_sections;

            auto last_section = m_section_header + num_sections - 1;
            auto new_header = m_section_header + num_sections;

            memset( new_header, 0, sizeof( section_header_t ) );
            strncpy_s( reinterpret_cast< char* >( new_header->m_name ), 8, section_name, 8 );

            auto sec_align = m_nt_headers->m_section_alignment;
            auto file_align = m_nt_headers->m_file_alignment;

            auto aligned_va = [ ] ( std::uint32_t base, std::uint32_t align ) {
                return ( base + align - 1 ) & ~( align - 1 );
                };

            new_header->m_virtual_size = size;
            new_header->m_virtual_address = aligned_va(
                last_section->m_virtual_address + last_section->m_virtual_size, sec_align );

            new_header->m_pointer_to_raw_data = 0;
            new_header->m_size_of_raw_data = 0;

            new_header->m_characteristics = 0xC0000040; 

            m_nt_headers->m_size_of_image = aligned_va(
                new_header->m_virtual_address + new_header->m_virtual_size, sec_align );

            num_sections++;
            return true;
        }

        bool map_sections( uint64_t new_image_base ) {
            auto section = m_section_header;
            std::uint32_t mapped_count = 0;
            std::uint32_t total_size   = 0;

            for ( auto idx = 0; idx < m_nt_headers->m_number_of_sections; idx++, section++ ) {
                auto raw_size  = section->m_size_of_raw_data;
                auto virt_size = section->m_virtual_size;

                if ( raw_size > 0 ) {
                    auto src        = reinterpret_cast< void* >(
                        m_dependency.data( ) + section->m_pointer_to_raw_data );
                    auto write_size = min( raw_size, virt_size );

                    std::memcpy(
                        reinterpret_cast< void* >( m_dependency_base + section->m_virtual_address ),
                        src,
                        write_size );
                }

                char name[ 9 ] = {};
                memcpy( name, section->m_name, 8 );
                logging::print( oxorany( "%-8s -> 0x%llX" ), name,
                    new_image_base + section->m_virtual_address );
                mapped_count++;
                total_size += virt_size;
            }

            logging::print( oxorany( "Mapped %u sections (%u bytes total)" ),
                mapped_count, total_size );
            return true;
        }

        bool erase_discarded_sec( uint64_t mapped_image_base ) {
            auto section = m_section_header;
            std::uint32_t erased_count = 0;

            for ( auto idx = 0; idx < m_nt_headers->m_number_of_sections; idx++, section++ ) {
                if ( section->m_characteristics & 0x02000000 ) {
                    auto size = section->m_virtual_size;
                    if ( !size )
                        continue;

                    auto dst = mapped_image_base + section->m_virtual_address;

                    std::vector<uint8_t> zero_buffer( size, 0 );
                    if ( !g_driver->write_memory( dst, zero_buffer.data( ), size ) ) {
                        char section_name[ 9 ] = { 0 };
                        memcpy( section_name, section->m_name, 8 );
                        logging::print( oxorany( "Could not erase section: %.8s" ), section_name );
                        return false;
                    }

                    char section_name[ 9 ] = { 0 };
                    memcpy( section_name, section->m_name, 8 );
                    logging::print( oxorany( "Erased: %.8s (0x%X bytes)" ), section_name, size );
                    erased_count++;
                }
            }

            if ( erased_count > 0 ) {
                logging::print( oxorany( "Erased %u discardable sections" ), erased_count );
            }

            return true;
        }

        std::uint32_t erase_strings( std::uint32_t max_length = 64 ) {
            auto rdata = get_section_by_name( ".rdata" );
            if ( !rdata ) {
                logging::print( oxorany( ".rdata section not found" ) );
                return 0;
            }

            auto payload = m_dependency.data( );
            std::uint32_t count = 0;

            for ( std::uint32_t idx = 0x1000;
                idx < rdata->m_virtual_address + rdata->m_virtual_size; idx++ ) {

                std::uint32_t length = 0;
                std::uint64_t mapped_address = 0;

                for ( std::uint32_t len = 0; len < max_length; len++ ) {
                    const char& character = payload[ idx + len ];
                    if ( character < 0x20 || character > 0x7E ) {
                        if ( payload[ max( idx - 1, 1u ) ] != 0 || payload[ idx + len ] != 0 )
                            break;
                        length = len;
                        mapped_address = m_dependency_base + idx;
                        idx += len;
                        break;
                    }
                }

                if ( length > 4 ) {
                    count++;
                    std::memset( reinterpret_cast< void* >( mapped_address ), 0, length );
                }
            }

            logging::print( oxorany( "Erased %u strings from .rdata" ), count );
            return count;
        }

        std::uint64_t get_export( const char* export_name ) {
            if ( !m_nt_headers->m_export_table.m_virtual_address )
                return 0;

            auto export_dir = reinterpret_cast< export_directory_t* >(
                rva_va( m_nt_headers->m_export_table.m_virtual_address ) );

            if ( !export_dir )
                return 0;

            auto functions = reinterpret_cast< std::uint32_t* >(
                rva_va( export_dir->m_address_of_functions ) );
            auto names = reinterpret_cast< std::uint32_t* >(
                rva_va( export_dir->m_address_of_names ) );
            auto ordinals = reinterpret_cast< std::uint16_t* >(
                rva_va( export_dir->m_address_of_names_ordinals ) );

            if ( !functions || !names || !ordinals )
                return 0;

            for ( auto idx = 0; idx < export_dir->m_number_of_names; idx++ ) {
                auto name = reinterpret_cast< const char* >( rva_va( names[ idx ] ) );
                if ( !name )
                    continue;

                if ( !std::strcmp( name, export_name ) ) {
                    auto ordinal = ordinals[ idx ];
                    if ( ordinal >= export_dir->m_number_of_functions )
                        return 0;

                    return functions[ ordinal ];
                }
            }

            return 0;
        }

        std::int8_t* rva_va( const std::ptrdiff_t rva ) {
            for ( auto p_section{ m_section_header }; p_section < m_section_header + m_nt_headers->m_number_of_sections; p_section++ )
                if ( rva >= p_section->m_virtual_address && rva < p_section->m_virtual_address + p_section->m_virtual_size )
                    return ( std::int8_t* )m_dos_header + p_section->m_pointer_to_raw_data + ( rva - p_section->m_virtual_address );
            return {};
        }

        section_header_t* get_section_by_name( const char* name ) {
            auto section = m_section_header;
            for ( auto idx = 0; idx < m_nt_headers->m_number_of_sections; idx++, section++ ) {
                if ( strncmp( reinterpret_cast< const char* >( section->m_name ), name, 8 ) == 0 ) {
                    return section;
                }
            }
            return nullptr;
        }
    };
}