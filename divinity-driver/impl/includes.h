#pragma once
#include <impl/std/std.h>
#include <impl/ia32/ia32.h>
#include <impl/hde/hde.h>

#include <dependencies/oxorany/include.h>

#include <workspace/kernel/ntoskrnl/symbols.h>
#include <workspace/kernel/ntoskrnl/ntoskrnl.hxx>
#include <workspace/kernel/ntoskrnl/exports/exports.hxx>

#include <workspace/kernel/core/mmu/mmu.hxx>
#include <workspace/kernel/core/mmu/pool.hxx>
#include <workspace/kernel/core/thread/thread.hxx>

#include <workspace/kernel/paging/pagetables.h>
#include <workspace/kernel/core/physical/physical.hxx>
#include <workspace/kernel/core/process/process.hxx>
#include <workspace/kernel/core/hide/hide.hxx>

#include <workspace/kernel/paging/paging.hxx>
#include <workspace/kernel/paging/dpm/dpm.hxx>
#include <workspace/kernel/paging/ptm/ptm.hxx>

#include <workspace/kernel/paging/pth/pth.hxx>
#include <workspace/kernel/paging/lbr/lbr.hxx>

#include <workspace/kernel/core/module/module.hxx>
#include <workspace/kernel/paging/hyperspace/hyperspace.hxx>

#include <workspace/client/control.h>
#include <workspace/client/client.hxx>