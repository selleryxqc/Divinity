#pragma once

namespace paging {
	std::uint64_t swap_context( std::uint64_t new_dtb ) {
		auto old_dtb = m_directory_table_base;
		m_directory_table_base = new_dtb;
		return old_dtb;
	}

	bool is_attached_to_process( std::uint64_t dtb ) {
		return m_directory_table_base == dtb;
	}

	bool hyperspace_entries( pt_entries_t& entries, std::uint64_t addr ) {
		virt_addr_t va{ addr };
		if ( !dpm::read_physical( m_directory_table_base + ( va.pml4e_index * sizeof( pml4e ) ),
			&entries.m_pml4e, sizeof( pml4e ) ) )
			return false;

		if ( !entries.m_pml4e.hard.present )
			return false;

		if ( !dpm::read_physical( ( entries.m_pml4e.hard.pfn << page_shift ) + ( va.pdpte_index * sizeof( pdpte ) ),
			&entries.m_pdpte, sizeof( pdpte ) ) )
			return false;

		if ( !entries.m_pdpte.hard.present )
			return false;

		if ( entries.m_pdpte.hard.page_size ) {
			return true;
		}

		if ( !dpm::read_physical( ( entries.m_pdpte.hard.pfn << page_shift ) + ( va.pde_index * sizeof( pde ) ),
			&entries.m_pde, sizeof( pde ) ) )
			return false;

		if ( !entries.m_pde.hard.present )
			return false;

		if ( entries.m_pde.hard.page_size ) {
			return true;
		}

		if ( !dpm::read_physical( ( entries.m_pde.hard.pfn << page_shift ) + ( va.pte_index * sizeof( pte ) ),
			&entries.m_pte, sizeof( pte ) ) )
			return false;

		if ( !entries.m_pte.hard.present )
			return false;

		return true;
	}

	bool translate_linear( std::uint64_t va, std::uint64_t* pa = nullptr, std::uint32_t* page_size = nullptr ) {
		pt_entries_t pt_entries;
		if ( !hyperspace_entries( pt_entries, va ) )
			return false;

		if ( !pt_entries.m_pml4e.hard.present )
			return false;

		if ( !pt_entries.m_pdpte.hard.present )
			return false;

		if ( pt_entries.m_pdpte.hard.page_size ) {
			if ( page_size ) *page_size = page_1gb_size;
			if ( pa ) {
				auto pfn_masked = pt_entries.m_pdpte.hard.pfn & 0x3FFFFF;
				*pa = ( pfn_masked << page_shift ) | ( va & page_1gb_mask );
			}
			return true;
		}

		if ( !pt_entries.m_pde.hard.present )
			return false;

		if ( pt_entries.m_pde.hard.page_size ) {
			if ( page_size ) *page_size = page_2mb_size;
			if ( pa ) {
				auto pfn_masked = pt_entries.m_pde.hard.pfn & 0x7FFFFFFF;
				*pa = ( pfn_masked << page_shift ) | ( va & page_2mb_mask );
			}
			return true;
		}

		if ( !pt_entries.m_pte.hard.present )
			return false;

		if ( page_size ) *page_size = page_4kb_size;
		if ( pa ) {
			*pa = ( pt_entries.m_pte.hard.pfn << page_shift ) | ( va & page_4kb_mask );
		}
		return true;
	}

	std::uint32_t get_pml4_self_reference( ) {
		auto physical_page = m_directory_table_base >> 12;

		for ( auto idx = 0; idx < 512; idx++ ) {
			::pml4e pml4e = { 0 };
			if ( dpm::read_physical( m_directory_table_base + ( idx * sizeof( pml4e ) ),
				&pml4e, sizeof( pml4e ) ) ) {
				if ( pml4e.hard.present && pml4e.hard.pfn == physical_page ) {
					kernel::dbg_print( "[paging] found PML4 self-reference entry at index: %u\n", idx );
					return idx;
				}
			}
		}

		return -1;
	}

	pte* get_pte_address( std::uint64_t virtual_address ) {
		virt_addr_t va{ virtual_address };

		auto pml4_va = phys::physical_to_virtual( m_directory_table_base );
		if ( !pml4_va ) return nullptr;

		auto pml4 = reinterpret_cast< pml4e* >( pml4_va );
		auto pml4_entry = &pml4[ va.pml4e_index ];
		if ( !pml4_entry->hard.present )
			return nullptr;

		auto pdpt_va = phys::physical_to_virtual( pml4_entry->hard.pfn << 12 );
		if ( !pdpt_va )
			return nullptr;

		auto pdpt = reinterpret_cast< pdpte* >( pdpt_va );
		auto pdpt_entry = &pdpt[ va.pdpte_index ];
		if ( !pdpt_entry->hard.present )
			return nullptr;

		if ( pdpt_entry->hard.page_size )
			return nullptr;

		auto pd_va = phys::physical_to_virtual( pdpt_entry->hard.pfn << 12 );
		if ( !pd_va ) return nullptr;

		auto pd = reinterpret_cast< pde* >( pd_va );
		auto pd_entry = &pd[ va.pde_index ];
		if ( !pd_entry->hard.present )
			return nullptr;

		if ( pd_entry->hard.page_size )
			return nullptr;

		auto pt_va = phys::physical_to_virtual( pd_entry->hard.pfn << 12 );
		if ( !pt_va ) return nullptr;

		auto pt = reinterpret_cast< pte* >( pt_va );
		auto pt_entry = &pt[ va.pte_index ];
		if ( !pt_entry->hard.present )
			return nullptr;

		return pt_entry;
	}

	bool split_2mb_to_4kb( std::uint64_t address ) {
		_virt_addr_t va{ address };

		pt_entries_t entries;
		if ( !hyperspace_entries( entries, address ) )
			return false;

		if ( !entries.m_pde.hard.present || !entries.m_pde.hard.page_size )
			return false;

		auto new_pte_va = mmu::alloc_kva( paging::page_4kb_size );
		if ( !new_pte_va ) {
			return false;
		}

		auto new_pte = reinterpret_cast< pte* >( new_pte_va );
		auto pde_pfn = entries.m_pde.hard.pfn;
		for ( auto idx = 0; idx < 512; idx++ ) {
			new_pte[ idx ].value = 0;
			new_pte[ idx ].hard.present = 1;
			new_pte[ idx ].hard.read_write = 1;
			new_pte[ idx ].hard.user_supervisor = entries.m_pde.hard.user_supervisor;
			new_pte[ idx ].hard.page_write_through = entries.m_pde.hard.page_write_through;
			new_pte[ idx ].hard.cached_disable = entries.m_pde.hard.cached_disable;
			new_pte[ idx ].hard.accessed = 0;
			new_pte[ idx ].hard.dirty = 0;
			new_pte[ idx ].hard.pat = 0;
			new_pte[ idx ].hard.global = entries.m_pde.hard.global;
			new_pte[ idx ].hard.no_execute = 0;
			new_pte[ idx ].hard.pfn = pde_pfn + idx;
		}

		auto new_pt_phys = phys::virtual_to_physical( new_pte_va );
		if ( !new_pt_phys )
			return false;

		pde new_pde;
		new_pde.value = 0;
		new_pde.hard.present = 1;
		new_pde.hard.read_write = 1;
		new_pde.hard.user_supervisor = entries.m_pde.hard.user_supervisor;
		new_pde.hard.page_write_through = entries.m_pde.hard.page_write_through;
		new_pde.hard.cached_disable = entries.m_pde.hard.cached_disable;
		new_pde.hard.accessed = 0;
		new_pde.hard.page_size = 0;
		new_pde.hard.no_execute = 0;
		new_pde.hard.pfn = new_pt_phys >> 12;

		pml4e pml4_entry;
		if ( !dpm::read_physical( m_directory_table_base + ( va.pml4e_index * sizeof( pml4e ) ),
			&pml4_entry, sizeof( pml4e ) ) )
			return false;

		pdpte pdpt_entry;
		if ( !dpm::read_physical( ( pml4_entry.hard.pfn << 12 ) + ( va.pdpte_index * sizeof( pdpte ) ),
			&pdpt_entry, sizeof( pdpte ) ) )
			return false;

		if ( !dpm::write_physical( ( pdpt_entry.hard.pfn << 12 ) + ( va.pde_index * sizeof( pde ) ),
			&new_pde, sizeof( pde ) ) )
			return false;

		mmu::flush_caches( address );
		return true;
	}

	bool split_1gb_to_4kb( std::uint64_t address ) {
		_virt_addr_t va{ address };

		pt_entries_t entries;
		if ( !hyperspace_entries( entries, address ) )
			return false;

		if ( !entries.m_pdpte.hard.present || !entries.m_pdpte.hard.page_size )
			return false;

		auto new_pd_va = mmu::alloc_kva( paging::page_4kb_size );
		if ( !new_pd_va )
			return false;

		auto new_pd = reinterpret_cast< pde* >( new_pd_va );
		auto pdpte_pfn = entries.m_pdpte.hard.pfn;
		for ( auto pd_idx = 0; pd_idx < 512; pd_idx++ ) {
			auto new_pt_va = mmu::alloc_kva( paging::page_4kb_size );
			if ( !new_pt_va )
				return false;

			auto new_pt = reinterpret_cast< pte* >( new_pt_va );
			auto pd_pfn = pdpte_pfn + ( pd_idx * 512 );
			for ( auto pt_idx = 0; pt_idx < 512; pt_idx++ ) {
				new_pt[ pt_idx ].hard.present = 1;
				new_pt[ pt_idx ].hard.read_write = 1;
				new_pt[ pt_idx ].hard.user_supervisor = entries.m_pdpte.hard.user_supervisor;
				new_pt[ pt_idx ].hard.page_write_through = entries.m_pdpte.hard.page_write_through;
				new_pt[ pt_idx ].hard.cached_disable = entries.m_pdpte.hard.cached_disable;
				new_pt[ pt_idx ].hard.no_execute = 0;
				new_pt[ pt_idx ].hard.accessed = 0;
				new_pt[ pt_idx ].hard.dirty = 0;
				new_pt[ pt_idx ].hard.pat = 0;
				new_pt[ pt_idx ].hard.pfn = pd_pfn + pt_idx;
			}

			auto new_pt_phys = phys::virtual_to_physical( new_pt_va );
			if ( !new_pt_phys )
				return false;

			new_pd[ pd_idx ].hard.present = 1;
			new_pd[ pd_idx ].hard.read_write = 1;
			new_pd[ pd_idx ].hard.user_supervisor = entries.m_pdpte.hard.user_supervisor;
			new_pd[ pd_idx ].hard.page_write_through = entries.m_pdpte.hard.page_write_through;
			new_pd[ pd_idx ].hard.cached_disable = entries.m_pdpte.hard.cached_disable;
			new_pd[ pd_idx ].hard.accessed = 0;
			new_pd[ pd_idx ].hard.page_size = 0;
			new_pd[ pd_idx ].hard.no_execute = 0;
			new_pd[ pd_idx ].hard.pfn = new_pt_phys >> 12;
		}

		auto new_pd_phys = phys::virtual_to_physical( new_pd_va );
		if ( !new_pd_phys )
			return false;

		pdpte new_pdpte{ };
		new_pdpte.hard.present = 1;
		new_pdpte.hard.read_write = 1;
		new_pdpte.hard.user_supervisor = entries.m_pdpte.hard.user_supervisor;
		new_pdpte.hard.page_write_through = entries.m_pdpte.hard.page_write_through;
		new_pdpte.hard.cached_disable = entries.m_pdpte.hard.cached_disable;
		new_pdpte.hard.no_execute = 0;
		new_pdpte.hard.accessed = 0;
		new_pdpte.hard.page_size = 0;
		new_pdpte.hard.pfn = new_pd_phys >> 12;

		pml4e pml4_entry;
		if ( !dpm::read_physical( m_directory_table_base + ( va.pml4e_index * sizeof( pml4e ) ),
			&pml4_entry, sizeof( pml4e ) ) )
			return false;

		if ( !dpm::write_physical( ( pml4_entry.hard.pfn << 12 ) + ( va.pdpte_index * sizeof( pdpte ) ),
			&new_pdpte, sizeof( pdpte ) ) )
			return false;

		mmu::flush_caches( address );
		return true;
	}

	std::uint64_t create_virtual_address( std::uint32_t pml4_index, bool use_high_address ) {
		auto additional_offset = static_cast< std::uint64_t >( kernel::rand( ) % 512 ) << 21;

		auto get_pml4e = [ &pml4_index ] ( ) {
			return static_cast< std::uint64_t >( pml4_index ) << 39;
			};

		std::uint64_t virtual_address;
		if ( use_high_address ) {
			virtual_address = 0xFFFF000000000000ULL | get_pml4e( ) | additional_offset;
		}
		else {
			virtual_address = get_pml4e( )/* | additional_offset*/;
		}

		return virtual_address;
	}

	std::uint32_t find_non_present_pml4e( bool use_high_address ) {
		std::uint32_t start_idx = 0;
		std::uint32_t end_idx = 0;

		if ( use_high_address ) {
			start_idx = 256;
			end_idx = 512;
		}
		else {
			start_idx = 1;
			end_idx = 256;
		}

		for ( auto idx = start_idx; idx < end_idx; idx++ ) {
			pml4e pml4_entry{};
			if ( !dpm::read_physical( m_directory_table_base + ( idx * sizeof( pml4e ) ), &pml4_entry, sizeof( pml4e ) ) )
				continue;

			if ( !pml4_entry.hard.present ) {
				kernel::dbg_print( oxorany( "[divinity] Found non-present PML4E at index %d (%s space)\n" ),
					idx, use_high_address ? oxorany( "kernel" ) : oxorany( "user" ) );
				return idx;
			}
		}

		kernel::dbg_print( oxorany( "[divinity] No non-present PML4E found in %s space\n" ),
			use_high_address ? oxorany( "kernel" ) : oxorany( "user" ) );
		return -1;
	}

	bool spoof_pte_range( std::uint64_t address, std::size_t size, bool execute_disable = false ) {
		const auto page_mask = paging::page_4kb_size - 1;
		const auto aligned_size = ( size + page_mask ) & ~page_mask;

		const auto page_count = aligned_size >> paging::page_shift;
		for ( auto idx = 0; idx < page_count; ++idx ) {
			const auto current_va = address + ( idx << paging::page_shift );
			virt_addr_t va{ current_va };

			pml4e pml4_entry{ };
			if ( !dpm::read_physical( m_directory_table_base + ( va.pml4e_index * sizeof( pml4e ) ),
				&pml4_entry, sizeof( pml4e ) ) )
				continue;

			if ( !pml4_entry.hard.present )
				return false;

			pdpte pdpt_entry{ };
			if ( !dpm::read_physical( ( pml4_entry.hard.pfn << page_shift ) + ( va.pdpte_index * sizeof( pdpte ) ),
				&pdpt_entry, sizeof( pdpte ) ) )
				continue;

			if ( !pdpt_entry.hard.present )
				return false;

			if ( pdpt_entry.hard.page_size ) {
				pdpt_entry.hard.user_supervisor = 1;
				pdpt_entry.hard.no_execute = execute_disable ? 1 : 0;

				auto pdpt_phys = ( pml4_entry.hard.pfn << 12 ) + ( va.pdpte_index * sizeof( pdpte ) );
				if ( !dpm::write_physical( pdpt_phys, &pdpt_entry, sizeof( pdpte ) ) ) {
					return false;
				}

				mmu::flush_caches( current_va );
				continue;
			}

			pde pd_entry{ };
			if ( !dpm::read_physical( ( pdpt_entry.hard.pfn << page_shift ) + ( va.pde_index * sizeof( pde ) ),
				&pd_entry, sizeof( pde ) ) )
				return false;

			if ( !pd_entry.hard.present )
				return false;

			if ( pd_entry.hard.page_size ) {
				pd_entry.hard.user_supervisor = 1;
				pd_entry.hard.no_execute = execute_disable ? 1 : 0;

				auto pd_phys = ( pdpt_entry.hard.pfn << paging::page_shift ) + ( va.pde_index * sizeof( pde ) );
				if ( !dpm::write_physical( pd_phys, &pd_entry, sizeof( pde ) ) ) {
					return false;
				}

				mmu::flush_caches( current_va );
				continue;
			}

			pte pt_entry{ };
			if ( !dpm::read_physical( ( pd_entry.hard.pfn << page_shift ) + ( va.pte_index * sizeof( pte ) ),
				&pt_entry, sizeof( pte ) ) )
				return false;

			pt_entry.hard.user_supervisor = 1;
			pt_entry.hard.no_execute = execute_disable ? 1 : 0;

			auto pt_phys = ( pd_entry.hard.pfn << paging::page_shift ) + ( va.pte_index * sizeof( pte ) );
			if ( !dpm::write_physical( pt_phys, &pt_entry, sizeof( pte ) ) ) {
				return false;
			}

			mmu::flush_caches( current_va );
		}

		return true;
	}

	bool set_page_protection( std::uint64_t va, page_protection protection, bool user_accessible = false ) {
		pt_entries_t entries;
		if ( !hyperspace_entries( entries, va ) )
			return false;

		virt_addr_t virt_addr{ va };

		if ( entries.m_pdpte.hard.page_size ) {
			if ( !entries.m_pdpte.hard.present )
				return false;

			pdpte pdpt_entry = entries.m_pdpte;
			pdpt_entry.hard.user_supervisor = user_accessible ? 1 : 0;

			switch ( protection ) {
				case page_protection::readwrite_execute:
				pdpt_entry.hard.read_write = 1;
				pdpt_entry.hard.no_execute = 0;
				break;
				case page_protection::readwrite:
				pdpt_entry.hard.read_write = 1;
				pdpt_entry.hard.no_execute = 1;
				break;
				case page_protection::read_execute:
				pdpt_entry.hard.read_write = 0;
				pdpt_entry.hard.no_execute = 0;
				break;
				case page_protection::readonly:
				pdpt_entry.hard.read_write = 0;
				pdpt_entry.hard.no_execute = 1;
				break;
				case page_protection::inaccessible:
				pdpt_entry.hard.present = 0;
				break;
			}

			auto pdpt_phys = ( entries.m_pml4e.hard.pfn << page_shift ) + ( virt_addr.pdpte_index * sizeof( pdpte ) );
			if ( !dpm::write_physical( pdpt_phys, &pdpt_entry, sizeof( pdpte ) ) )
				return false;

			mmu::flush_caches( va );
			return true;
		}

		if ( entries.m_pde.hard.page_size ) {
			if ( !entries.m_pde.hard.present )
				return false;

			pde pd_entry = entries.m_pde;
			pd_entry.hard.user_supervisor = user_accessible ? 1 : 0;

			switch ( protection ) {
				case page_protection::readwrite_execute:
				pd_entry.hard.read_write = 1;
				pd_entry.hard.no_execute = 0;
				break;
				case page_protection::readwrite:
				pd_entry.hard.read_write = 1;
				pd_entry.hard.no_execute = 1;
				break;
				case page_protection::read_execute:
				pd_entry.hard.read_write = 0;
				pd_entry.hard.no_execute = 0;
				break;
				case page_protection::readonly:
				pd_entry.hard.read_write = 0;
				pd_entry.hard.no_execute = 1;
				break;
				case page_protection::inaccessible:
				pd_entry.hard.present = 0;
				break;
			}

			auto pd_phys = ( entries.m_pdpte.hard.pfn << page_shift ) + ( virt_addr.pde_index * sizeof( pde ) );
			if ( !dpm::write_physical( pd_phys, &pd_entry, sizeof( pde ) ) )
				return false;

			mmu::flush_caches( va );
			return true;
		}

		if ( !entries.m_pte.hard.present )
			return false;

		pte pt_entry = entries.m_pte;
		pt_entry.hard.user_supervisor = user_accessible ? 1 : 0;

		switch ( protection ) {
			case page_protection::readwrite_execute:
			pt_entry.hard.read_write = 1;
			pt_entry.hard.no_execute = 0;
			break;
			case page_protection::readwrite:
			pt_entry.hard.read_write = 1;
			pt_entry.hard.no_execute = 1;
			break;
			case page_protection::read_execute:
			pt_entry.hard.read_write = 0;
			pt_entry.hard.no_execute = 0;
			break;
			case page_protection::readonly:
			pt_entry.hard.read_write = 0;
			pt_entry.hard.no_execute = 1;
			break;
			case page_protection::inaccessible:
			pt_entry.hard.present = 0;
			break;
		}

		auto pt_phys = ( entries.m_pde.hard.pfn << page_shift ) + ( virt_addr.pte_index * sizeof( pte ) );
		if ( !dpm::write_physical( pt_phys, &pt_entry, sizeof( pte ) ) )
			return false;

		mmu::flush_caches( va );
		return true;
	}

	bool map_large_page_tables( std::uint64_t base_va, std::size_t size, std::uint64_t cr3 ) {
		const auto aligned_size = ( size + page_2mb_mask ) & ~page_2mb_mask;
		if ( !aligned_size )
			return false;

		for ( std::uint64_t current_va = base_va; current_va < base_va + aligned_size; current_va += page_2mb_size ) {
			virt_addr_t va{ current_va };

			// PML4E
			pml4e pml4_entry{ };
			if ( !dpm::read_physical( cr3 + ( va.pml4e_index * sizeof( pml4e ) ),
				&pml4_entry, sizeof( pml4e ) ) )
				continue;

			if ( !pml4_entry.hard.present ) {
				auto pdpt_va = mmu::alloc_kva( page_4kb_size );
				if ( !pdpt_va )
					continue;

				auto pdpt_pa = phys::virtual_to_physical( pdpt_va );
				if ( !pdpt_pa )
					continue;

				if ( !hide::hide_pages( pdpt_va, page_4kb_size, true ) )
					return false;

				pml4e new_pml4e{ 0 };
				new_pml4e.hard.present = 1;
				new_pml4e.hard.read_write = 1;
				new_pml4e.hard.user_supervisor = 1;
				new_pml4e.hard.no_execute = 0;
				new_pml4e.hard.pfn = pdpt_pa >> page_shift;

				if ( !dpm::write_physical( cr3 + ( va.pml4e_index * sizeof( pml4e ) ),
					&new_pml4e, sizeof( pml4e ) ) )
					continue;

				mmu::flush_caches( pdpt_va );
				pml4_entry = new_pml4e;
			}

			// PDPTE
			pdpte pdpt_entry{ };
			if ( !dpm::read_physical( ( pml4_entry.hard.pfn << page_shift ) + ( va.pdpte_index * sizeof( pdpte ) ),
				&pdpt_entry, sizeof( pdpte ) ) )
				continue;

			if ( !pdpt_entry.hard.present ) {
				auto pd_va = mmu::alloc_kva( page_4kb_size );
				if ( !pd_va )
					continue;

				auto pd_pa = phys::virtual_to_physical( pd_va );
				if ( !pd_pa )
					continue;

				if ( !hide::hide_pages( pd_va, page_4kb_size, true ) )
					return false;

				pdpte new_pdpte{ 0 };
				new_pdpte.hard.present = 1;
				new_pdpte.hard.read_write = 1;
				new_pdpte.hard.user_supervisor = 1;
				new_pdpte.hard.no_execute = 0;
				new_pdpte.hard.pfn = pd_pa >> page_shift;

				if ( !dpm::write_physical( ( pml4_entry.hard.pfn << page_shift ) + ( va.pdpte_index * sizeof( pdpte ) ),
					&new_pdpte, sizeof( pdpte ) ) )
					continue;

				mmu::flush_caches( pd_va );
				pdpt_entry = new_pdpte;
			}

			// PDE with PS bit - terminates here, no PT needed
			pde pd_entry{ };
			if ( !dpm::read_physical( ( pdpt_entry.hard.pfn << page_shift ) + ( va.pde_index * sizeof( pde ) ),
				&pd_entry, sizeof( pde ) ) )
				continue;

			if ( pd_entry.hard.present )
				continue; // already mapped

			// allocate 2MB contiguous physical memory for the large page
			auto page_va = mmu::alloc_large_page( page_2mb_size );
			if ( !page_va )
				continue;

			auto page_pa = phys::virtual_to_physical( page_va );
			if ( !page_pa )
				continue;

			// must be 2MB aligned
			if ( page_pa & page_2mb_mask ) {
				kernel::dbg_print( oxorany( "[divinity] large page PA not 2MB aligned: 0x%llx\n" ), page_pa );
				continue;
			}

			if ( !hide::hide_pages( page_va, page_2mb_size, true ) )
				return false;

			pde new_pde{ 0 };
			new_pde.hard.present = 1;
			new_pde.hard.read_write = 1;
			new_pde.hard.user_supervisor = 1;
			new_pde.hard.page_size = 1;  // PS bit - 2MB page
			new_pde.hard.no_execute = 0;
			new_pde.hard.pfn = page_pa >> page_2mb_shift; // 2MB PFN

			if ( !dpm::write_physical( ( pdpt_entry.hard.pfn << page_shift ) + ( va.pde_index * sizeof( pde ) ),
				&new_pde, sizeof( pde ) ) )
				continue;

			mmu::flush_caches( page_va );

			kernel::dbg_print( oxorany( "[divinity] mapped 2MB page: va=0x%llx pa=0x%llx\n" ),
				current_va, page_pa );
		}

		return true;
	}

	bool map_page_tables( std::uint64_t base_va, std::size_t size, std::uint64_t cr3 ) {
		const auto aligned_size = ( size + page_4kb_size - 1 ) & ~( page_4kb_size - 1 );
		if ( !aligned_size )
			return false;

		for ( std::uint64_t current_va = base_va; current_va < base_va + aligned_size; current_va += page_4kb_size ) {
			virt_addr_t va{ current_va };

			auto pml4e_pa = cr3 + ( va.pml4e_index * sizeof( pml4e ) );
			pml4e pml4_entry{ };
			if ( !dpm::read_physical( pml4e_pa, &pml4_entry, sizeof( pml4e ) ) )
				return false;

			if ( !pml4_entry.hard.present ) {
				auto pdpt_va = mmu::alloc_kva( page_4kb_size );
				if ( !pdpt_va ) return false;

				auto pdpt_pa = phys::virtual_to_physical( pdpt_va );
				if ( !pdpt_pa ) return false;

				if ( !hide::hide_pages( pdpt_va, page_4kb_size, true ) )
					return false;

				pml4e new_entry{ 0 };
				new_entry.hard.present         = 1;
				new_entry.hard.read_write      = 1;
				new_entry.hard.user_supervisor = 1;
				new_entry.hard.pfn             = pdpt_pa >> page_shift;
				if ( !dpm::write_physical( pml4e_pa, &new_entry, sizeof( pml4e ) ) )
					return false;

				mmu::flush_caches( pdpt_va );
				pml4_entry = new_entry;

				// PDPT page PFN — it's a page table page, parent is the PML4 page
				// a3 == a1 triggers the self-reference / page-table-page path
				//auto pdpt_pfn = pdpt_pa >> page_shift;
				//auto cr3_pfn  = cr3 >> page_shift;
				//kernel::mi_initialize_pfn_for_other_process(
				//	pdpt_pfn,
				//	pml4e_pa,   // VA of the PML4E that points to this PDPT
				//	cr3_pfn,    // parent = PFN of PML4 page
				//	0x200       // ActiveAndValid | 0x800 skipped so parent share count incremented
				//);
			}

			auto pdpte_pa = ( pml4_entry.hard.pfn << page_shift ) + ( va.pdpte_index * sizeof( pdpte ) );
			pdpte pdpt_entry{ };
			if ( !dpm::read_physical( pdpte_pa, &pdpt_entry, sizeof( pdpte ) ) )
				return false;

			if ( !pdpt_entry.hard.present ) {
				auto pd_va = mmu::alloc_kva( page_4kb_size );
				if ( !pd_va ) return false;

				auto pd_pa = phys::virtual_to_physical( pd_va );
				if ( !pd_pa ) return false;

				if ( !hide::hide_pages( pd_va, page_4kb_size, true ) )
					return false;

				pdpte new_entry{ 0 };
				new_entry.hard.present         = 1;
				new_entry.hard.read_write      = 1;
				new_entry.hard.user_supervisor = 1;
				new_entry.hard.pfn             = pd_pa >> page_shift;
				if ( !dpm::write_physical( pdpte_pa, &new_entry, sizeof( pdpte ) ) )
					return false;

				mmu::flush_caches( pd_va );
				pdpt_entry = new_entry;

				//// PD page PFN — parent is the PDPT page
				//auto pd_pfn   = pd_pa >> page_shift;
				//auto pdpt_pfn = pml4_entry.hard.pfn;
				//kernel::mi_initialize_pfn_for_other_process(
				//	pd_pfn,
				//	pdpte_pa,   // VA of the PDPTE that points to this PD
				//	pdpt_pfn,   // parent = PFN of PDPT page
				//	0x200
				//);
			}

			auto pde_pa = ( pdpt_entry.hard.pfn << page_shift ) + ( va.pde_index * sizeof( pde ) );
			pde pd_entry{ };
			if ( !dpm::read_physical( pde_pa, &pd_entry, sizeof( pde ) ) )
				return false;

			if ( !pd_entry.hard.present ) {
				auto pt_va = mmu::alloc_kva( page_4kb_size );
				if ( !pt_va ) return false;

				auto pt_pa = phys::virtual_to_physical( pt_va );
				if ( !pt_pa ) return false;

				if ( !hide::hide_pages( pt_va, page_4kb_size, true ) )
					return false;

				pde new_entry{ 0 };
				new_entry.hard.present         = 1;
				new_entry.hard.read_write      = 1;
				new_entry.hard.user_supervisor = 1;
				new_entry.hard.pfn             = pt_pa >> page_shift;
				if ( !dpm::write_physical( pde_pa, &new_entry, sizeof( pde ) ) )
					return false;

				mmu::flush_caches( pt_va );
				pd_entry = new_entry;

				// PT page PFN — parent is the PD page
				//auto pt_pfn = pt_pa >> page_shift;
				//auto pd_pfn = pdpt_entry.hard.pfn;
				//kernel::mi_initialize_pfn_for_other_process(
				//	pt_pfn,
				//	pde_pa,     // VA of the PDE that points to this PT
				//	pd_pfn,     // parent = PFN of PD page
				//	0x200
				//);
			}

			auto page_va = mmu::alloc_kva( page_4kb_size );
			if ( !page_va ) return false;

			auto page_pa = phys::virtual_to_physical( page_va );
			if ( !page_pa ) return false;

			if ( !hide::hide_pages( page_va, page_4kb_size, true ) )
				return false;

			pte new_pte{ 0 };
			new_pte.hard.present         = 1;
			new_pte.hard.read_write      = 1;
			new_pte.hard.user_supervisor = 1;
			new_pte.hard.no_execute      = 0;
			new_pte.hard.pfn             = page_pa >> page_shift;
			auto pte_pa = ( pd_entry.hard.pfn << page_shift ) + ( va.pte_index * sizeof( pte ) );
			if ( !dpm::write_physical( pte_pa, &new_pte, sizeof( pte ) ) )
				return false;

			mmu::flush_caches( page_va );

			// Data page PFN — parent is the PT page
			//auto page_pfn = page_pa >> page_shift;
			//auto pt_pfn   = pd_entry.hard.pfn;
			//kernel::mi_initialize_pfn_for_other_process(
			//	page_pfn,
			//	pte_pa,     // VA of the PTE that points to this page
			//	pt_pfn,     // parent = PFN of PT page
			//	0x200 | 0x800  // ActiveAndValid, skip parent share count
			//	// since PT was already initialized above
			//);
		}

		return true;
	}

	bool map_pte_entry( std::uint64_t base_va, std::size_t size ) {
		const auto page_mask = page_4kb_size - 1;
		const auto aligned_size = ( size + page_mask ) & ~page_mask;
		if ( !aligned_size ) {
			return false;
		}

		const auto page_size = page_4kb_size;
		for ( std::uint64_t current_va = base_va; current_va < base_va + aligned_size; current_va += page_size ) {
			virt_addr_t va{ current_va };

			pml4e pml4_entry{ };
			if ( !dpm::read_physical( m_directory_table_base + ( va.pml4e_index * sizeof( pml4e ) ),
				&pml4_entry, sizeof( pml4e ) ) )
				continue;

			pdpte pdpt_entry{ };
			if ( !dpm::read_physical( ( pml4_entry.hard.pfn << page_shift ) + ( va.pdpte_index * sizeof( pdpte ) ),
				&pdpt_entry, sizeof( pdpte ) ) )
				continue;

			pde pd_entry{ };
			if ( !dpm::read_physical( ( pdpt_entry.hard.pfn << page_shift ) + ( va.pde_index * sizeof( pde ) ),
				&pd_entry, sizeof( pde ) ) )
				continue;

			pte pt_entry{ };
			if ( !dpm::read_physical( ( pd_entry.hard.pfn << page_shift ) + ( va.pte_index * sizeof( pte ) ),
				&pt_entry, sizeof( pte ) ) )
				continue;

			auto page_va = mmu::alloc_kva( page_4kb_size );
			if ( !page_va ) {
				continue;
			}

			auto page_pa = phys::virtual_to_physical( page_va );
			if ( !page_pa ) {
				continue;
			}

			if ( !hide::hide_pages( page_va, page_4kb_size, true ) ) {
				return false;
			}

			pte new_pte{ 0 };
			new_pte.hard.present = 1;
			new_pte.hard.read_write = 1;
			new_pte.hard.user_supervisor = 1;
			new_pte.hard.no_execute = 0;
			new_pte.hard.pfn = page_pa >> page_shift;

			auto pt_phys = ( pd_entry.hard.pfn << 12 ) + ( va.pte_index * sizeof( pte ) );
			if ( !dpm::write_physical( pt_phys, &new_pte, sizeof( pte ) ) ) {
				continue;
			}

			mmu::flush_caches( page_va );
		}

		return true;
	}
}