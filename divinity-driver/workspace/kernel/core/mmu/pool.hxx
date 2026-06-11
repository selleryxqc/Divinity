#pragma once

namespace mmu {
	namespace pool {
        list_entry_t m_list_head;

        struct pool_entry_t {
            list_entry_t  m_list;
            unsigned long m_tag;
        };

        unsigned long random_tag( ) {
            auto r1 = kernel::rand( );
            auto r2 = kernel::rand( );
            return ( r1 & 0xFFFF0000 ) | ( r2 & 0x0000FFFF );
        }

        void setup( ) {
            list_init( &m_list_head );
        }

        template <typename result_t>
        result_t alloc( size_t size, int type ) {
            auto tag = random_tag( );
            auto pool = reinterpret_cast< uintptr_t >( 
                kernel::ex_allocate_pool_with_tag( type, size + sizeof( pool_entry_t ), tag ) );
            if ( !pool ) return nullptr;

            auto entry = reinterpret_cast< pool_entry_t* >( pool );
            entry->m_tag = tag;

            list_insert_tail( &m_list_head, &entry->m_list );
            return reinterpret_cast< result_t >( pool + sizeof( pool_entry_t ) );
        }

        void free( unsigned long tag ) {
            for ( auto e = m_list_head.m_flink; e != &m_list_head; e = e->m_flink ) {
                auto entry = reinterpret_cast< pool_entry_t* >( e );
                if ( entry->m_tag != tag ) continue;

                list_remove( e );
                kernel::ex_free_pool_with_tag( entry, tag );
                return;
            }
        }

        void cleanup( ) {
            while ( !list_empty( &m_list_head ) ) {
                list_entry_t* e = nullptr;
                list_remove_head( &m_list_head, e );

                auto entry = reinterpret_cast< pool_entry_t* >( e );
                kernel::ex_free_pool_with_tag( entry, entry->m_tag );
            }
        }
	}

    template <typename t = void*>
    t alloc_pool( std::size_t size, int type = 0 ) {
        return pool::alloc<t>( size, type );
    }

    template <typename t>
    void free_pool( t pool_base ) {
        auto entry = reinterpret_cast< pool::pool_entry_t* >(
            reinterpret_cast< uintptr_t >( pool_base ) - sizeof( pool::pool_entry_t )
            );
        list_remove( &entry->m_list );
        kernel::ex_free_pool_with_tag( entry, entry->m_tag );
    }
}