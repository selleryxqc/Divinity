#pragma once

namespace kernel {
    struct entry_t {
        struct symbols_t {
            std::uint64_t m_mm_allocate_independent_pages;
            std::uint64_t m_mm_free_independent_pages;
            std::uint64_t m_mm_set_page_protection;
            std::uint64_t m_mi_lock_page_table_page;
            std::uint64_t m_mi_is_page_on_bad_list;
            std::uint64_t m_mi_make_page_bad;
            std::uint64_t m_mm_initialize_process_address_space;
            std::uint64_t m_po_idle;
            std::uint64_t m_ke_query_active_processor_count_ex;
            std::uint64_t m_ki_nmi_callback_list_head;
            std::uint64_t m_psp_allocate_thread;
            std::uint64_t m_ke_initialize_thread;
            std::uint64_t m_ke_start_thread;
            std::uint64_t m_ke_ready_thread;
            std::uint64_t m_mi_copy_on_write;
            std::uint64_t m_ke_set_disable_boost_thread;
            std::uint64_t m_ps_enum_process_threads;
            std::uint64_t m_ps_suspend_thread;
            std::uint64_t m_ps_resume_thread;
            std::uint64_t m_ps_get_context_thread;
            std::uint64_t m_ps_set_context_thread;
            std::uint64_t m_mi_remove_vad;
            std::uint64_t m_ex_query_big_pool_tag;
            std::uint64_t m_ex_map_handle_to_pointer;
            std::uint64_t m_ex_destroy_handle;
            std::uint64_t m_psp_thread_delete;
            std::uint64_t m_mi_initialize_pfn_for_other_process;
            std::uint64_t m_mi_allocate_vad;
            std::uint64_t m_mi_insert_vad;
            std::uint64_t m_rtlp_debug_print_callback_list;
            std::uint64_t m_kdp_trap;
            std::uint64_t m_nt_global_flag;
            std::uint64_t m_kdp_debug_routine_select;
            std::uint64_t m_kdp_report;
            std::uint64_t m_etw_trace_silo_kernel_event;
            std::uint64_t m_ke_service_descriptor_table;
            std::uint64_t m_ki_system_call64;
        } m_pdb;

        struct offsets_t {
            std::uint64_t m_thread_start_address;
        } m_offsets;

        std::uint64_t m_image_base;
        std::uint64_t m_image_size;
        std::uint64_t m_ntoskrnl_base;
        std::uint64_t m_directory_table_base;
    };

    entry_t::symbols_t m_pdb;
}
