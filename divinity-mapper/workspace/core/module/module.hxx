#pragma once

namespace module {
	class c_module {
	public:
		std::uint64_t m_module_base;
		char m_module_path[ 64 ]{ };

		c_module( ) { }
		~c_module( ) { }

		c_module( std::uint64_t module_base, char* module_path ) : m_module_base( module_base ) {
			if ( module_path ) {
				strcpy( m_module_path, module_path );
			}
		}

		std::uintptr_t get_export( const char* export_name ) const {
			return g_pdb->get_symbol_address( export_name );
		}

		std::uint64_t rva( std::uint64_t instruction, int size, int offset ) {
			auto h_module = LoadLibraryExA( m_module_path, nullptr, DONT_RESOLVE_DLL_REFERENCES );
			if ( !h_module ) {
				return 0;
			}

			const auto module_base = reinterpret_cast< std::uint64_t >( h_module );
			const auto local_instruction = module_base + ( instruction - m_module_base );

			const auto p_displacement = reinterpret_cast< int32_t* >( local_instruction + size );
			const auto local_target = ( local_instruction + offset ) + *p_displacement;

			const auto target_address = m_module_base + ( local_target - module_base );

			FreeLibrary( h_module );
			return target_address;
		}
	};

	std::unique_ptr< c_module > get_kernel_module( const char* module_name ) {
		char full_path[ 64 ]{ };

		unsigned long buffer_size = 0;
		auto status = NtQuerySystemInformation(
			static_cast< SYSTEM_INFORMATION_CLASS >( 11 ),
			nullptr,
			0,
			&buffer_size
		);

		if ( status != 0xC0000004L )
			return nullptr;

		auto buffer = std::make_unique< std::uint8_t[ ] >( buffer_size );
		status = NtQuerySystemInformation(
			static_cast< SYSTEM_INFORMATION_CLASS >( 11 ),
			buffer.get( ),
			buffer_size,
			&buffer_size
		);

		if ( !NT_SUCCESS( status ) ) {
			return nullptr;
		}

		std::uint64_t module_base = 0;
		const auto modules = reinterpret_cast< rtl_process_modules_t* >( buffer.get( ) );
		for ( auto idx = 0u; idx < modules->m_count; ++idx ) {
			const auto current_module_name = std::string(
				reinterpret_cast< char* >( modules->m_modules[ idx ].m_full_path ) +
				modules->m_modules[ idx ].m_offset_to_file_name
			);

			if ( !_stricmp( current_module_name.c_str( ), module_name ) ) {
				GetWindowsDirectoryA( full_path, 64 );
				strcat( full_path, oxorany( "\\" ) );
				strcat( full_path, ( char* )&modules->m_modules[ idx ].m_full_path[ 12 ] );
				module_base = reinterpret_cast< std::uint64_t >( modules->m_modules[ idx ].m_image_base );
				break;
			}
		}

		return std::make_unique< c_module >( module_base, full_path );
	}
}