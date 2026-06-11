#pragma once

namespace client {
	namespace control {
		struct control_initialize_t {
			std::uint64_t m_process_id;
			std::uint64_t m_base_address;
			void* m_response_semaphore;
			void* m_request_semaphore;
		};

		enum control_type {
			none = 0,
			verify,
			get_eprocess,
			get_process_id,
			get_process_peb,
			get_base_address,
			get_directory_table_base,
			swap_directory_table_base,
			hyperspace_entries,
			hide_process_pages,
			map_process_page,
			read_physical,
			write_physical,
			read_virtual,
			write_virtual,
			lookup_thread,
			suspend_thread,
			resume_thread,
			get_thread_context,
			set_thread_context,
			clone_in_hyperspace,
			hyperspace_get_context,
			hyperspace_allocate_virtual,
			hyperspace_free_virtual,
			hyperspace_remap_pages,
			hyperspace_expose_pages,
			hyperspace_clone_pages,
			hyperspace_rexpose_pages,
			unload_driver
		};

		struct control_data_t {
			control_type m_request_type;
			paging::pt_entries_t m_pt_entries;
			pml4e m_pml4e;
			pdpte m_pdpte;
			pde m_pde;
			pte m_pte;
			std::uint32_t m_thread_id;
			std::uint32_t m_process_id;
			std::uint32_t m_protection;
			std::uint32_t m_count;
			std::uint32_t m_mode;
			CONTEXT* m_context;
			eprocess_t* m_process;
			eprocess_t* m_process2;
			ethread_t* m_thread;
			peb_t* m_process_peb;
			std::uint64_t m_address;
			std::uint64_t m_address1;
			void* m_address2;
			std::size_t m_size;
			bool m_remove;
			bool m_status;
		};

		mdl_t* m_control_mdl{ nullptr };
		control_data_t* m_control_data{ nullptr };
		ksemaphore_t* m_response_handle{ nullptr };
		ksemaphore_t* m_request_handle{ nullptr };

		bool is_valid( ) {
			return m_control_data && m_request_handle && m_response_handle;
		}
	}
}