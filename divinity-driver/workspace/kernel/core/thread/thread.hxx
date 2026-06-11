#pragma once

namespace thread {
    bool create_thread(
        eprocess_t* target_process,
        void* start_routine,
        void* start_context = nullptr,
        ethread_t** out_thread = nullptr
    ) {
        auto output_buffer = reinterpret_cast< thread_creation_output_t* >(
            mmu::alloc_kva( sizeof( thread_creation_output_t ) ) );
        if ( !output_buffer )
            return false;

        std::uint32_t flags = 0x1000;

        ethread_t* thread = nullptr;
        auto status = kernel::psp_allocate_thread(
            reinterpret_cast< std::uint64_t >( target_process ),
            0,
            false,
            nullptr,
            nullptr,
            nullptr,
            start_routine,
            start_context,
            &flags,
            &thread,
            nullptr,
            output_buffer );

        mmu::free_kva(
            reinterpret_cast< std::uint64_t >( output_buffer ),
            sizeof( thread_creation_output_t )
        );

        if ( !NT_SUCCESS( status ) || !thread ) {
            kernel::dbg_print( oxorany( "[divinity] PspAllocateThread failed: 0x%x\n" ), status );
            return false;
        }

        const auto thread_va = reinterpret_cast< std::uint64_t >( thread );
        auto thread_context = *reinterpret_cast< std::uint64_t* >( thread_va + 0x618 );
        if ( thread_context ) {
            if ( hide::hide_big_pool( thread_context ) ) {
                kernel::dbg_print(
                    oxorany( "[divinity] Hid thread context pool allocation: 0x%llx\n" ),
                    thread_context );
            }
            else {
                kernel::dbg_print(
                    oxorany( "[divinity] Failed to hide thread context pool allocation: 0x%llx\n" ),
                    thread_context );
            }
        }

        auto cid_handle = *reinterpret_cast< void** >( thread_va + 0x480 );
        if ( cid_handle ) {
            auto psp_cid_table = kernel::get_psp_cid_table( );
            auto entry = kernel::ex_map_handle_to_pointer( psp_cid_table, cid_handle );
            if ( entry ) {
                kernel::dbg_print( oxorany( "[divinity] Clearing CID handle: 0x%llx\n" ), cid_handle );
                kernel::ex_destroy_handle( psp_cid_table, cid_handle,
                    reinterpret_cast< void* >( entry ) );
                *reinterpret_cast< void** >( thread_va + 0x480 ) = nullptr;
            }
        }

        auto stack_base = *reinterpret_cast< std::uint64_t* >( thread_va + 0x28 );
        if ( stack_base ) {
            auto stack_limit = *reinterpret_cast< std::uint64_t* >( thread_va + 0x30 );
            if ( stack_limit ) {
                kernel::dbg_print(
                    oxorany( "[divinity] Stack base: 0x%llx (size: 0x%llx)\n" ),
                    stack_base, stack_base - stack_limit );
            }
        }

        _InterlockedOr( reinterpret_cast< volatile long* >(
            thread_va + offsets::misc_flags ), 2u );

        kernel::ke_start_thread( thread, nullptr, nullptr );
        kernel::obf_reference_object( thread );

        _interlockedbittestandset(
            reinterpret_cast< volatile long* >( thread_va + offsets::system_thread_flags ), 1 );
        _interlockedbittestandset(
            reinterpret_cast< volatile long* >( thread_va + offsets::cross_thread_flags ), 4 );

        _InterlockedOr( reinterpret_cast< volatile long* >( thread_va + offsets::misc_flags ), 2u );

        kernel::ke_ready_thread( thread );

        kernel::dbg_print(
            oxorany( "[divinity] Created thread 0x%llx TID: %u\n" ),
            thread,
            kernel::ps_get_thread_id( thread ) );

        if ( out_thread )
            *out_thread = thread;

        return true;
    }
}