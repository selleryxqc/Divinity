#pragma once

namespace paging {
	namespace ptm {
		struct page_mapping_t {
			std::uint64_t m_virtual_address;
			pte* m_pte_address;
			std::uint64_t m_original_pfn;
			std::uint16_t m_pml4e_index;
			std::uint16_t m_pdpte_index;
			std::uint16_t m_pde_index;
			std::uint16_t m_pte_index;
		};

		constexpr std::size_t max_mappings = 512;
		page_mapping_t m_page_mappings[ max_mappings ] = {};
		std::uint16_t m_next_mapping_index = 0;
		bool m_is_initialized = false;

		std::uint64_t m_new_pdpt{ 0 };
		std::uint64_t m_new_pd{ 0 };
		std::uint64_t m_new_pt{ 0 };
		std::uint64_t m_new_pdpt_pfn{ 0 };
		std::uint64_t m_new_pd_pfn{ 0 };
		std::uint64_t m_new_pt_pfn{ 0 };
		std::uint16_t m_pml4e_index = 0;

		pte* get_pte_for_address( std::uint64_t address ) {
			virt_addr_t va{ address };

			auto pml4_va = phys::physical_to_virtual( m_directory_table_base & ~0xf );
			if ( !pml4_va ) return nullptr;

			auto pml4 = reinterpret_cast< pml4e* >( pml4_va );
			auto pml4_entry = &pml4[ va.pml4e_index ];
			if ( !pml4_entry->hard.present ) return nullptr;

			auto pdpt_va = phys::physical_to_virtual( pml4_entry->hard.pfn << 12 );
			if ( !pdpt_va ) return nullptr;

			auto pdpt = reinterpret_cast< pdpte* >( pdpt_va );
			auto pdpt_entry = &pdpt[ va.pdpte_index ];
			if ( !pdpt_entry->hard.present ) return nullptr;

			auto pd_va = phys::physical_to_virtual( pdpt_entry->hard.pfn << 12 );
			if ( !pd_va ) return nullptr;

			auto pd = reinterpret_cast< pde* >( pd_va );
			auto pd_entry = &pd[ va.pde_index ];
			if ( !pd_entry->hard.present ) return nullptr;

			auto pt_va = phys::physical_to_virtual( pd_entry->hard.pfn << 12 );
			if ( !pt_va ) return nullptr;

			auto pt = reinterpret_cast< pte* >( pt_va );
			return &pt[ va.pte_index ];
		}

		bool initialize( ) {
			if ( m_is_initialized )
				return true;

			cr3 target_cr3{ m_directory_table_base };
			const auto current_pml4 = reinterpret_cast< pml4e* >(
				phys::physical_to_virtual( target_cr3.dirbase << 12 )
				);

			for ( auto idx = 100u; idx < 256u; ++idx ) {
				if ( !current_pml4[ idx ].hard.present ) {
					m_pml4e_index = idx;
					break;
				}
			}

			if ( m_pml4e_index == 0 ) {
				kernel::dbg_print( oxorany( "[ptm] initialize: No free PML4 entry found\n" ) );
				return false;
			}

			m_new_pdpt = mmu::alloc_kva( page_4kb_size );
			if ( !m_new_pdpt )
				return false;

			if ( !hide::hide_pages( m_new_pdpt, page_4kb_size ) )
				return false;

			pt_entries_t pt_entries;
			if ( !hyperspace_entries( pt_entries, m_new_pdpt ) )
				return false;

			m_new_pdpt_pfn = pt_entries.m_pte.hard.pfn << 12;

			pml4e new_pml4e = { 0 };
			new_pml4e.hard.present = true;
			new_pml4e.hard.read_write = true;
			new_pml4e.hard.user_supervisor = true;
			new_pml4e.hard.pfn = pt_entries.m_pte.hard.pfn;

			auto pml4_entry_phys = ( target_cr3.dirbase << 12 ) + ( m_pml4e_index * sizeof( pml4e ) );
			std::memcpy(
				reinterpret_cast< void* >( phys::physical_to_virtual( pml4_entry_phys ) ),
				&new_pml4e,
				sizeof( pml4e )
			);

			m_new_pd = mmu::alloc_kva( page_4kb_size );
			if ( !m_new_pd )
				return false;

			if ( !hide::hide_pages( m_new_pd, page_4kb_size ) )
				return false;

			if ( !hyperspace_entries( pt_entries, m_new_pd ) )
				return false;

			m_new_pd_pfn = pt_entries.m_pte.hard.pfn << 12;

			m_new_pt = mmu::alloc_kva( page_4kb_size );
			if ( !m_new_pt )
				return false;

			if ( !hide::hide_pages( m_new_pt, page_4kb_size ) )
				return false;

			if ( !hyperspace_entries( pt_entries, m_new_pt ) )
				return false;

			m_new_pt_pfn = pt_entries.m_pte.hard.pfn << 12;

			pdpte new_pdpte = { 0 };
			new_pdpte.hard.present = true;
			new_pdpte.hard.read_write = true;
			new_pdpte.hard.pfn = m_new_pd_pfn >> 12;
			new_pdpte.hard.user_supervisor = true;
			*reinterpret_cast< pdpte* >( m_new_pdpt ) = new_pdpte;

			pde new_pde = { 0 };
			new_pde.hard.present = true;
			new_pde.hard.read_write = true;
			new_pde.hard.pfn = m_new_pt_pfn >> 12;
			new_pde.hard.user_supervisor = true;
			*reinterpret_cast< pde* >( m_new_pd ) = new_pde;

			for ( auto idx = 0; idx < max_mappings; idx++ ) {
				virt_addr_t new_addr{ };
				new_addr.pml4e_index = m_pml4e_index;
				new_addr.pdpte_index = 0;
				new_addr.pde_index = 0;
				new_addr.pte_index = idx;
				new_addr.offset = 0;

				m_page_mappings[ idx ].m_virtual_address = new_addr.value;
				m_page_mappings[ idx ].m_pml4e_index = m_pml4e_index;
				m_page_mappings[ idx ].m_pdpte_index = 0;
				m_page_mappings[ idx ].m_pde_index = 0;
				m_page_mappings[ idx ].m_pte_index = idx;

				m_page_mappings[ idx ].m_pte_address = reinterpret_cast< pte* >( m_new_pt + ( idx * sizeof( pte ) ) );
				m_page_mappings[ idx ].m_pte_address->value = 0;
				m_page_mappings[ idx ].m_original_pfn = 0;
			}

			m_is_initialized = true;
			return true;
		}

		void clean_cache( ) {
			if ( !m_is_initialized )
				return;

			for ( auto i = 0; i < max_mappings; i++ ) {
				if ( m_page_mappings[ i ].m_pte_address ) {
					_disable( );
					m_page_mappings[ i ].m_pte_address->value = 0;
					__invlpg( reinterpret_cast< void* >( m_page_mappings[ i ].m_virtual_address ) );
					_enable( );
				}
			}

			memset( m_page_mappings, 0, sizeof( m_page_mappings ) );
			m_next_mapping_index = 0;
			m_is_initialized = false;
		}

		void* map_page( std::uint64_t physical_address, page_protection protection = page_protection::readwrite, bool supervisor = false ) {
			if ( !m_is_initialized || !physical_address || !phys::is_address_valid( physical_address, page_4kb_size ) )
				return nullptr;

			const auto page_offset = physical_address & page_4kb_mask;
			const auto pfn = ( physical_address & ~page_4kb_mask ) >> 12;

			auto processor = kernel::ke_get_current_processor_number( );
			if ( processor >= max_mappings )
				processor = 0;

			auto& mapping = m_page_mappings[ processor ];

			pte new_pte = { 0 };
			new_pte.hard.present = true;
			new_pte.hard.read_write = ( protection != page_protection::inaccessible );
			new_pte.hard.pfn = pfn;
			new_pte.hard.user_supervisor = true;
			new_pte.hard.no_execute = ( protection != page_protection::readwrite_execute );

			_disable( );
			*mapping.m_pte_address = new_pte;
			__invlpg( reinterpret_cast< void* >( mapping.m_virtual_address ) );
			_enable( );

			return reinterpret_cast< void* >( mapping.m_virtual_address + page_offset );
		}

		void* remap_page( std::uint16_t mapping_index, std::uint64_t physical_address, page_protection protection = page_protection::readwrite ) {
			if ( !m_is_initialized || mapping_index >= max_mappings )
				return nullptr;

			if ( !physical_address || !phys::is_address_valid( physical_address, page_4kb_size ) )
				return nullptr;

			const auto page_offset = physical_address & page_4kb_mask;
			const auto pfn = ( physical_address & ~page_4kb_mask ) >> 12;

			auto& mapping = m_page_mappings[ mapping_index ];

			_disable( );

			mapping.m_pte_address->hard.pfn = pfn;
			mapping.m_pte_address->hard.read_write = ( protection != page_protection::inaccessible );
			mapping.m_pte_address->hard.no_execute = ( protection != page_protection::readwrite_execute );

			__invlpg( reinterpret_cast< void* >( mapping.m_virtual_address ) );

			_enable( );

			return reinterpret_cast< void* >( mapping.m_virtual_address + page_offset );
		}
	}
}