"""Bounded driver initialization in a modeled kernel, inside the normal worker."""

from __future__ import annotations

import io
import hashlib
import json
import ntpath
import time
from collections import deque
from pathlib import Path
from unicorn import x86_const as ux
from unicorn import UC_TLB_VIRTUAL
from speakeasy.winenv import arch as e_arch

import speakeasy
from speakeasy.windows import winemu as tracing
from speakeasy import common as se_common
from speakeasy.windows.kernel import WinKernelEmulator, EP_DRIVER_ENTRY, EP_DRIVER_UNLOAD
from speakeasy.windows.winemu import _normalize_mod_name
from speakeasy.profiler import Run

from .artifacts import ArtifactCatalog, MAX_MEMORY_SCAN
from .native import _api_coverage, _engine_error_text, _report_blob
from .pe import InvalidSample, SampleInfo
from .persona import make_speakeasy_config, materialize_virtual_files
from .image_protection import ImageProtectionBatch
from .clock import VirtualClock
from .cpu import VirtualCPU
from .pe_imports import batched_import_patching
from .kernel_context import initialize_kernel_context
from .kernel_addresses import KernelAddressSpace
from .x64_unwind import walk_exception_frames
from .driver_image import place_driver_image
from .kernel_locks import add_kernel_lock_storage
from .kernel_api import install_kernel_apis
from .kernel_provider_reads import KernelProviderReads
from . import kernel_providers
from .instruction_cache import InstructionCache
from .kernel_code_reference import KernelCodeReference, REFERENCE_PROVIDER_SPACING
from .driver_trace import (create_native_trace, bind_native_trace, sync_native_trace,
                           native_trace_error, trace_report)
from .safeio import read_regular_file
from .persona_content import oem_code_page


class DriverKernel(KernelAddressSpace, WinKernelEmulator):
    """Run explicit lifecycle calls and their guest-created System threads.

    The upstream kernel marks even a budget stop as a return, and its all-entry
    mode invents IRPs and calls unload after a failed DriverEntry. Neither is
    appropriate evidence of successful initialization.
    """

    def __init__(self, config, *, unload=False, persona=None, kernel_code_reference=None):
        self.persona_config = persona
        super().__init__(config=config)
        self.request_unload = unload
        self.budget = config.max_instructions
        self.limit_reached = False
        self.timeout_reached = False
        self.deadline = None
        self.returned_runs = set()
        self.lifecycle_errors = []
        self.loading_images = 0
        self.image_protections = ImageProtectionBatch(super().mem_protect)
        self.cpu_model = None
        self.kernel_cpu = None
        self.instruction_tail = deque(maxlen=64)
        self.control_flow_tail = deque(maxlen=512)
        self.control_flow_edges = set()
        self.control_flow_transfers = 0
        self.repeat_movsb_iterations = 0
        self.context_observations = deque(maxlen=128)
        self.previous_instruction = None
        self.evidence_range = (0, 0)
        self.written_pages = {}
        self.executed_written_pages = set()
        self.image_write_tracking_limited = False
        self.image_placement = None
        self.kernel_lock_storage = None
        self.instruction_cache = InstructionCache(self.mem_read)
        self.progress_path = None
        self.next_progress = 0
        self.next_kernel_pool = 0
        self.cancel_requested = False
        self.header_reads = []
        self.header_reads_omitted = 0
        self.data_import_addresses = {}
        self.native_memory_faults = {}
        self.driver_pointer_size = 0
        self.guest_api_depth = 0
        self.kernel_provider_spacing = REFERENCE_PROVIDER_SPACING if kernel_code_reference is not None else 0x1000000
        self.kernel_code_reference = KernelCodeReference(self, kernel_code_reference) if kernel_code_reference is not None else None
        self.native_trace = create_native_trace(self)
        if self.native_trace is not None:
            self._hook_code_tracing = self.native_trace.trace

    def set_mem_tracing_hooks(self):
        super().set_mem_tracing_hooks()
        bind_native_trace(self)

    def on_emu_complete(self):
        sync_native_trace(self)
        return super().on_emu_complete()

    def observe_header_read(self, facade, access, address, size, value):
        if len(self.header_reads) >= 128:
            self.header_reads_omitted += 1
            return True
        self.header_reads.append({"pc": hex(self.get_pc()), "address": hex(address),
            "size": size, "prefix_at_read": self.mem_read(address, min(size, 16)).hex()})
        return True

    def _checkpoint_progress(self, count, address):
        control = read_regular_file(self.progress_path.with_name("driver-control.json"), 4096,
                                    containment_root=self.progress_path.parent)
        if control is not None:
            try:
                request = json.loads(control)
                if isinstance(request, dict) and request.get("stop") is True:
                    self.cancel_requested = True
            except (ValueError, UnicodeError, RecursionError):
                pass
        progress = {"status": "running", "instruction_count": count, "pc": hex(address),
            "processor": getattr(self, "processor_id", 0),
            "registers": self.get_register_state(), "api_calls": sum(run.num_apis for run in self.runs),
            "image_pages_written_observed": len(self.written_pages),
            "image_pages_executed_after_write_observed": len(self.executed_written_pages),
            "driver_tracing": trace_report(self),
            "last_context_observation": self.context_observations[-1] if self.context_observations else None}
        if self.cpu_model is not None:
            progress["virtual_uptime_ms"] = self.cpu_model.clock.uptime_ms
            progress["virtual_tsc"] = self.cpu_model.tsc()
        try:
            self.progress_path.write_text(json.dumps(progress), encoding="utf-8")
        except OSError:
            pass  # Diagnostic checkpoints must not change guest execution.
        if self.cancel_requested:
            self.on_emu_complete()
        return self.cancel_requested

    def _execute_runs(self, *args, **kwargs):
        # Native counting includes sentinel/API machinery omitted by the trace.
        # Keep its hook active (zero changes transient-hook behavior in this
        # Unicorn build), but let our shared traced budget stop execution first.
        original = self.config
        self.config = original.model_copy(update={"max_instructions": (1 << 63) - 1})
        try:
            result = super()._execute_runs(*args, **kwargs)
            result = self.kernel_threads.execute_after_yield(result)
            native_trace_error(self)
            return result
        finally:
            sync_native_trace(self)
            # Unicorn raises again after a fault hook declines recovery. The
            # upstream catch replaces the useful access address/name with PC
            # and a generic engine string. Keep the original fault evidence.
            for run in self.runs:
                fault = self.native_memory_faults.get(id(run))
                if fault is not None:
                    run.error = fault
            self.config = original

    def handle_import_func(self,dll,name):
        self.guest_api_depth += 1
        try:
            return super().handle_import_func(dll,name)
        finally:
            self.guest_api_depth -= 1

    def mem_read(self,address,size):
        reference=getattr(self,'kernel_code_reference',None)
        if reference is not None and getattr(self,'guest_api_depth',0):
            reference.require_api_access(address,size,'read')
        catalog=getattr(self,'export_catalog',None)
        if catalog is not None and getattr(self,'guest_api_depth',0):
            catalog.require_api_access(address,size,'read')
        opaque=getattr(self,'opaque_data',None)
        if opaque is not None and getattr(self,'guest_api_depth',0):
            opaque.require_api_access(address,size,'read')
        callbacks=getattr(self,'named_callbacks',None)
        if callbacks is not None and getattr(self,'guest_api_depth',0):
            callbacks.require_api_access(address,size,'read')
        return super().mem_read(address,size)

    def mem_write(self, address, data):
        reference=getattr(self,'kernel_code_reference',None)
        if reference is not None and getattr(self,'guest_api_depth',0):
            reference.require_api_access(address,len(data),'write')
        catalog=getattr(self,'export_catalog',None)
        if catalog is not None and getattr(self,'guest_api_depth',0):
            catalog.require_api_access(address,len(data),'write')
        opaque=getattr(self,'opaque_data',None)
        if opaque is not None and getattr(self,'guest_api_depth',0):
            opaque.require_api_access(address,len(data),'write')
        callbacks=getattr(self,'named_callbacks',None)
        if callbacks is not None and getattr(self,'guest_api_depth',0):
            callbacks.require_api_access(address,len(data),'write')
        mdls = getattr(self, "mdls", None)
        if mdls is not None and getattr(self, "deadline", None) is not None:
            mdls.require_api_write(address, len(data))
        cache = getattr(self, "instruction_cache", None)
        if cache is not None:
            cache.invalidate(address, len(data))
        if getattr(self, "deadline", None) is not None:
            start, end = self.evidence_range
            if address < end and address + len(data) > start:
                self.observe_image_write(None, 0, address, len(data), 0)
        return super().mem_write(address, data)

    def pool_alloc(self, pooltype, size, tag="None"):
        pooltype = int(pooltype) & 0xFFFFFFFF  # POOL_TYPE is a 32-bit enum.
        # WDK wdm.h: COLD_ALLOCATION (0x100) is advisory and ZERO_ALLOCATION
        # (0x400) requests zeroed bytes. Fresh dedicated mappings are zeroed;
        # strip these modifiers before decoding the underlying pool type.
        base_type = pooltype & ~0x500
        names = {0: "NonPagedPool", 1: "PagedPool", 4: "NonPagedPoolCacheAligned",
                 5: "PagedPoolCacheAligned", 0x200: "NonPagedPoolNx",
                 0x204: "NonPagedPoolNxCacheAligned"}
        if base_type not in names:
            self.lifecycle_errors.append(f"Unsupported kernel pool type 0x{pooltype:x}")
            return 0
        if not 0 < size <= MAX_MEMORY_SCAN:
            return 0
        # Dedicated pages keep NX storage separate from executable small-block
        # allocations; the engine's shared small-block allocator ignores perms.
        if not self.next_kernel_pool:
            self.next_kernel_pool = 0xFFFF900000000000 if self.get_ptr_size() == 8 else 0xA0000000
        mapped_size = (size + 4095) & ~4095
        base = self.next_kernel_pool
        self.next_kernel_pool += mapped_size
        address = self.mem_map(mapped_size, base=base,
            perms=se_common.PERM_MEM_RW if base_type & 0x200 else se_common.PERM_MEM_RWX,
            tag=f"api.pool.{names[base_type]}.{tag}", process=self.get_system_process())
        self.pool_allocs.append((address, pooltype, size, tag))
        return address

    def _handle_prot_fetch(self, emu, address, size, value):
        # The upstream handler returns True for non-symbol NX memory, which
        # lets this Unicorn build execute it. Preserve the guest protection.
        return self._stop_memory_fault("invalid_execute", address, "execute")

    def _handle_prot_write(self, emu, address, size, value):
        # The stock recovery maps a temporary page and reports completion
        # without stopping the faulting instruction. Preserve native rights.
        return self._stop_memory_fault("invalid_protect_write", address, "write")

    def _hook_mem_unmapped(self, emu, access, address, size, value):
        kind = self.emu_eng.mem_access.get(access)
        if kind == se_common.INVAL_PERM_MEM_READ:
            return self._stop_memory_fault("invalid_protect_read", address, "read")
        if kind == se_common.INVALID_MEM_WRITE:
            # The inherited dispatcher maps a fake page before invoking the
            # write-fault handler. Kernel faults must preserve the original VM.
            return self._handle_invalid_write(emu, address, size, value)
        return super()._hook_mem_unmapped(emu, access, address, size, value)

    def _stop_memory_fault(self, reason, address, access):
        sync_native_trace(self)
        opaque=getattr(self,'opaque_data',None)
        unmodeled=opaque.describe(address) if opaque is not None else None
        catalog=getattr(self,'export_catalog',None)
        catalog_item=catalog.describe(address) if catalog is not None else None
        reference=getattr(self,'kernel_code_reference',None)
        reference_item=reference.describe(address) if reference is not None else None
        if catalog_item is not None:
            unmodeled=catalog_item
        if reference_item is not None:
            unmodeled=reference_item
            reference.record(reference_item,access,address,1)
            reason=('unsupported_private_kernel_api' if reference_item['kind']=='code' and access=='execute'
                    else 'unmodeled_kernel_reference_'+access)
            if reference_item.get('exported') and access=='execute':
                reason='unsupported_kernel_api'
        if unmodeled is not None:
            if reference_item is None:
                reason='unmodeled_kernel_data_'+access
            if catalog_item is not None and catalog_item['kind']=='code':
                reason='unsupported_kernel_api' if access=='execute' else 'unmodeled_kernel_function_'+access
                catalog.record(catalog_item,access,address,1)
            elif catalog_item is not None:
                catalog.record(catalog_item,access,address,1)
        self.curr_run.error = self.get_error_info(reason, address, access_type=access)
        if unmodeled is not None:
            label=('Non-executable kernel reference' if reference_item is not None else
                   'Unmodeled catalog '+catalog_item['kind']+' symbol' if catalog_item is not None else 'Unmodeled private data')
            self.curr_run.error=self.curr_run.error.model_copy(update={
                'api_name':'ntoskrnl.'+unmodeled['name'],
                'context_summary':f"{label} {unmodeled['name']} at offset {unmodeled['offset']:#x}; "+self.curr_run.error.context_summary})
        description = {"invalid_execute": "Fetch from non-executable memory",
                       "invalid_protect_write": "Write to write-protected memory",
                       "invalid_protect_read": "Read from non-readable memory"}.get(reason)
        if description:
            self.curr_run.error = self.curr_run.error.model_copy(update={
                "context_summary": description + "; " + self.curr_run.error.context_summary})
        self.native_memory_faults[id(self.curr_run)] = self.curr_run.error
        self.on_emu_complete()
        return False

    def _handle_invalid_read(self, emu, address, size, value):
        # Kernel threads do not have a user TEB/SEH chain. The inherited
        # recovery both tried that chain and mapped a fake page at the fault.
        if (address in self.import_table and
                address not in getattr(self, "modeled_function_addresses", ())):
            self.observe_import_storage_read(None, 0, address, size, value)
            return False
        return self._stop_memory_fault("invalid_read", address, "read")

    def _handle_invalid_write(self, emu, address, size, value):
        return self._stop_memory_fault("invalid_write", address, "write")

    def _handle_invalid_fetch(self, emu, address, size, value):
        # Preserve the engine's explicit return/import/callback dispatch, but
        # never enter its user-mode SEH or fake-page path for unknown code.
        if (address in (self.return_hook, self.exit_hook) or address in self.import_table or
                any(item[0] == address for item in self.callbacks) or
                address in getattr(self.curr_mod, "import_table", {})):
            return super()._handle_invalid_fetch(emu, address, size, value)
        return self._stop_memory_fault("invalid_fetch", address, "execute")

    def set_current_irql(self, irql):
        value = int(irql)
        if not 0 <= value <= (15 if self.get_ptr_size() == 8 else 31):
            raise ValueError("Invalid kernel IRQL")
        super().set_current_irql(value)
        if getattr(self, "kernel_context_initialized", False):
            address = self.gs_addr + 0x50 if self.get_ptr_size() == 8 else self.fs_addr + 0x24
            self.mem_write(address, bytes([value]))
            if self.get_ptr_size() == 8:
                self.emu_eng.emu.reg_write(ux.UC_X86_REG_CR8, value)

    def get_current_irql(self):
        if getattr(self, "kernel_context_initialized", False):
            self.irql = (int(self.emu_eng.emu.reg_read(ux.UC_X86_REG_CR8)) if self.get_ptr_size() == 8
                         else int.from_bytes(self.mem_read(self.fs_addr + 0x24, 1), "little"))
        return super().get_current_irql()

    def get_system_time(self):
        clock = getattr(self, "virtual_clock", None)
        if clock is not None:
            clock._observe()
            return clock.filetime_ticks()
        return super().get_system_time()

    def observe_image_write(self, facade, access, address, size, value):
        self.instruction_cache.invalidate(address, size)
        start, end = self.evidence_range
        stop = min(address + size, end)
        page = max(address, start) & ~0xFFF
        while page < stop:
            if page not in self.written_pages and len(self.written_pages) < 32768:
                self.written_pages[page] = hashlib.sha256(self.mem_read(page, 0x1000)).hexdigest()
            elif page not in self.written_pages:
                self.image_write_tracking_limited = True
            page += 0x1000
        return True

    def setup(self):
        install_kernel_apis(self)
        return super().setup()

    def load_module_by_name(self, name, emu_path=None, base=None):
        normalized = _normalize_mod_name(name)
        if normalized in kernel_providers.PROVIDER_EXPORTS:
            if not emu_path or base is None:
                raise ValueError('Metadata-only kernel provider requires explicit guest path and base')
            module = self.load_image(kernel_providers.metadata_image(normalized, self.get_arch(), base, emu_path))
            self.mem_protect(module.base, (module.image_size + 4095) & ~4095, se_common.PERM_MEM_READ)
            return module
        return super().load_module_by_name(name, emu_path=emu_path, base=base)

    def _init_module_group(self, modules_config, default_base=None):
        modules = []
        for definition in modules_config:
            if definition.name in kernel_providers.PROVIDER_EXPORTS:
                base = definition.base_addr or default_base
                if isinstance(base, str):
                    base = int(base, 16)
                modules.append(self.load_module_by_name(definition.name, definition.path, base))
            else:
                modules.extend(super()._init_module_group([definition], default_base))
        return modules

    def bind_data_imports(self, module):
        # The engine maps the primary image before setup installs our models.
        # Its early lookup also uses raw ntoskrnl.exe rather than ntoskrnl.
        # Rebind recognized data exports once the modeled kernel is ready.
        width = self.get_ptr_size()
        self.driver_pointer_size = width
        for imported in module._image.imports:
            name = _normalize_mod_name(imported.dll_name)
            _handler, function = self.api.get_data_export_handler(name, imported.func_name)
            if function is None:
                continue
            address = imported.iat_address
            if not module.base <= address or address + width > module.base + module.image_size:
                raise InvalidSample("Kernel data import slot lies outside its image")
            key = name, imported.func_name
            if key not in self.data_import_addresses:
                self.data_import_addresses[key] = self.handle_import_data(*key)
            pointer = self.data_import_addresses[key]
            if pointer is None:
                raise ValueError(f"Kernel data handler returned no storage for {name}.{imported.func_name}")
            previous = int.from_bytes(self.mem_read(address, width), "little")
            self.mem_write(address, int(pointer).to_bytes(width, "little"))
            self.global_data[address] = [f"{name}.{imported.func_name}", pointer]
            self.import_table.pop(previous, None)
        self.bind_code_imports(module)

    def load_image(self, image):
        # No guest code runs during image mapping. The upstream loader already
        # merges section permissions on shared pages; batch its resulting
        # adjacent equal-permission requests before entering the CPU.
        self.loading_images += 1
        try:
            if self.emu_eng and not self.emu_eng.emu:
                self.emu_eng.init_engine(e_arch.ARCH_X86, image.arch)
                if image.arch == e_arch.ARCH_AMD64:
                    # Canonical kernel addresses must reach Unicorn unchanged.
                    # The default physical TLB truncates them to 52 bits.
                    self.emu_eng.emu.ctl_set_tlb_mode(UC_TLB_VIRTUAL)
            if self.image_placement is None and getattr(image.loader, "_pe_obj", None) is not None:
                self.image_placement = place_driver_image(image)
            reference=getattr(self,'kernel_code_reference',None)
            reference_prepared=reference.prepare(image) if reference is not None else False
            locks = add_kernel_lock_storage(image)
            if locks is not None:
                self.kernel_lock_storage = locks
            debugger = getattr(self, "debugger_state", None)
            debugger_data = debugger.prepare(image) if debugger is not None else None
            initial_process = getattr(self, "initial_system_process", None)
            process_data = initial_process.prepare(image) if initial_process is not None else None
            references = getattr(self, "object_references", None)
            type_data = references.prepare(image) if references is not None else None
            environment = getattr(self, "kernel_environment", None)
            boundary_data = environment.prepare(image) if environment is not None else None
            opaque = getattr(self,'opaque_data',None)
            opaque_data = opaque.prepare(image) if opaque is not None else None
            catalog=getattr(self,'export_catalog',None)
            catalog_data=catalog.prepare(image) if catalog is not None else None
            loaded = super().load_image(image)
            if reference_prepared:
                reference.protect()
            if locks is not None:
                # ApiModuleLoader images do not receive the PE loader's section
                # protection pass. Enforce the rights of our added data page.
                self.mem_protect(locks, 4096, se_common.PERM_MEM_RW)
            if debugger_data is not None:
                self.mem_protect(debugger_data, 4096, se_common.PERM_MEM_READ)
            if process_data is not None:
                self.mem_protect(process_data, 4096, se_common.PERM_MEM_READ)
            if type_data is not None:
                self.mem_protect(type_data, 4096, se_common.PERM_MEM_READ)
            if boundary_data is not None:
                self.mem_protect(boundary_data, 4096, se_common.PERM_MEM_READ)
            if opaque_data is not None:
                self.mem_protect(opaque_data,4096,se_common.PERM_MEM_NONE)
            if catalog_data is not None:
                self.mem_protect(*catalog_data,se_common.PERM_MEM_NONE)
            return loaded
        finally:
            self.loading_images -= 1
            if not self.loading_images:
                self.image_protections.flush()

    def _prepare_run_context(self, run):
        if run.type == EP_DRIVER_ENTRY:
            self.prepare_entry_stack()
        if run.thread is None:
            system = self.get_system_process()
            if system is not None and system.threads:
                run.thread = system.threads[0]
                run.process_context = system
        result = super()._prepare_run_context(run)
        if run.type == EP_DRIVER_ENTRY:
            run.thread.stack_base = self.stack_base
            run.thread.stack_commit = self.kernel_entry_stack
        self.kernel_cpu.prepare_run(run)
        return result

    def observe_import_storage_read(self, _facade, access, address, size, value):
        if address in getattr(self, "modeled_function_addresses", ()):
            return True
        imported = self.import_table.get(address)
        if imported is not None:
            module, name = imported
            error = self.get_error_info("unresolved_kernel_import_read", address, access_type="read")
            self.curr_run.error = error.model_copy(update={"api_name": f"{module}.{name}"[:256]})
            self.native_memory_faults[id(self.curr_run)] = self.curr_run.error
            self.on_emu_complete()
        return True

    def mem_protect(self, address, size, permissions):
        reference=getattr(self,'kernel_code_reference',None)
        if (reference is not None and getattr(self,'guest_api_depth',0) and
                reference.describe(address,size) is not None):
            reference.require_api_access(address,size,'protection_change')
        if (self.loading_images and size > 0 and not address % self.page_size
                and not size % self.page_size):
            return self.image_protections.add(address, size, permissions)
        self.image_protections.flush()
        return super().mem_protect(address, size, permissions)

    def _hook_code_tracing(self, emu, addr, size):
        scheduler = getattr(self, "kernel_threads", None)
        if scheduler is not None and scheduler.active and scheduler.yield_at_hook():
            return False
        count = self.curr_run.instr_cnt if len(self.runs) == 1 else sum(run.instr_cnt for run in self.runs)
        if count >= self.budget:
            self.limit_reached = True
            self.on_emu_complete()
            return False
        if self.progress_path is not None and count >= self.next_progress:
            self.next_progress = count + 1_000_000
            if self._checkpoint_progress(count, addr):
                return False
        if self.deadline is not None and time.monotonic() >= self.deadline:
            self.timeout_reached = True
            self.on_emu_complete()
            return False
        if not 1 <= size <= 15:
            # Unicorn uses a sentinel length on some invalid instructions.
            # Let its invalid-instruction path report/handle them; never use
            # that sentinel as a memory-read size in a ctypes callback.
            return False
        start, end = self.evidence_range
        width = self.driver_pointer_size or self.get_ptr_size()
        if start <= addr and addr + size <= end:
            code, flags = self.instruction_cache.instruction_info(addr, size, width)
        else:
            code = bytes(self.mem_read(addr, size))
            flags = InstructionCache.instruction_flags(code, width)
        if flags & 1:
            engine = self.emu_eng.emu
            names = ("RAX", "RBX", "RCX", "RDX", "RSP", "EFLAGS", "CS", "GS_BASE") if self.get_ptr_size() == 8 else ("EAX", "EBX", "ECX", "EDX", "ESP", "EFLAGS", "CS")
            self.context_observations.append({"pc": hex(addr), "bytes": code.hex(),
                "registers_before": {name.lower(): hex(engine.reg_read(getattr(ux, "UC_X86_REG_" + name)))
                                     for name in names}})
        if (flags & 2 and
                self.kernel_cpu.instruction(addr, code)):
            return False
        if flags & 4:
            # This Unicorn build accepts MOV CR8 but its instruction path does
            # not agree with its CR8 register API. Keep direct guest accesses
            # on the same IRQL state as kernel APIs; do not skip other CR ops.
            names = ("RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
                     "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
            register = getattr(ux, "UC_X86_REG_" + names[(code[3] & 7) | (8 if code[0] & 1 else 0)])
            engine = self.emu_eng.emu
            if code[2] == 0x20:
                engine.reg_write(register, self.get_current_irql())
            else:
                value = int(engine.reg_read(register))
                if value > 15:
                    self.curr_run.error = self.get_error_info("invalid_cr8_write", addr)
                    self.on_emu_complete()
                    return False
                self.set_current_irql(value)
            self.set_pc(addr + size)
        if self.cpu_model is not None:
            cpu = self.cpu_model
            if flags & 8:
                cpu.observe_instruction(self, addr, size, code=code)
            else:
                cpu._instructions += 1
                cpu._pending_cycles += 100
                if cpu._instructions % 1000 == 0:
                    cpu.flush_cycles()
        previous = self.previous_instruction
        # Unicorn invokes the hook for each byte of REP MOVSB, including the
        # final zero-count step. Keep native execution and per-hook accounting,
        # but do not fill the branch tail with internal string iterations.
        repeating_copy = previous is not None and addr == previous[0] and code == b"\xf3\xa4"
        if repeating_copy:
            self.repeat_movsb_iterations += 1
        elif previous is not None and addr != previous[0] + previous[1]:
            self.control_flow_transfers += 1
            edge = (previous[0], addr)
            sampled = edge not in self.control_flow_edges or self.control_flow_transfers % 4096 == 0
            registers = None
            if sampled:
                engine = self.emu_eng.emu
                names = ("RAX", "RBX", "RCX", "RDX", "EFLAGS") if self.get_ptr_size() == 8 else ("EAX", "EBX", "ECX", "EDX", "EFLAGS")
                registers = {name.lower(): hex(engine.reg_read(getattr(ux, "UC_X86_REG_" + name))) for name in names}
                if len(self.control_flow_edges) >= 8192:
                    self.control_flow_edges.clear()
                self.control_flow_edges.add(edge)
            self.control_flow_tail.append((previous[0], addr, sampled, registers))
        self.previous_instruction = (addr, size)
        self.instruction_tail.append((addr, size))
        page = addr & ~0xFFF
        if page in self.written_pages:
            self.executed_written_pages.add(page)
        # Experiment: identical common upstream accounting without a second
        # Python function call and repeated cold-path dispatch.
        run = self.curr_run
        cache = run.exec_cache
        if (self.config.max_instructions == -1 or run.instr_cnt < self.config.max_instructions) and not tracing.logger.isEnabledFor(tracing.logging.DEBUG):
            if cache and not self.get_symbol_from_address(addr):
                access = cache[0]
                if access.base <= addr <= access.base + access.size - 1:
                    self.curr_instr_size = size
                    self.prev_pc = addr
                    run.instr_cnt += 1
                    access.execs += 1
                    return True
        return super()._hook_code_tracing(emu, addr, size)

    def on_run_complete(self):
        scheduler = getattr(self, "kernel_threads", None)
        if scheduler is not None:
            return scheduler.complete()
        return self._complete_lifecycle_run()

    def _complete_lifecycle_run(self):
        run = self.curr_run
        returned = (self.get_pc() in (self.return_hook, self.exit_hook)
                    and not run.error and not self.limit_reached and not self.timeout_reached)
        run.ret_val = self.get_return_val() if returned else None
        if returned:
            self.returned_runs.add(id(run))
        # Call no dispatch handlers or exports with invented input. Unload is an
        # explicit analysis stimulus, allowed only after successful initialization.
        if self.run_queue:
            self.lifecycle_errors.append("Queued kernel callbacks or threads are outside driver lifecycle scope")
        self.run_queue.clear()
        if any(item["inserted"] and item["dpc"] for item in self.dispatcher.objects.values()
               if item["kind"] in (8, 9)):
            self.lifecycle_errors.append("Pending kernel timer DPCs require kernel callback scheduling")
        if run.type == EP_DRIVER_ENTRY and returned and not (run.ret_val & 0x80000000):
            driver = next(drv for drv in self.drivers if drv.pe == self.curr_mod)
            driver.read_back()
            if self.request_unload and driver.on_unload:
                mapping = self.get_address_map(int(driver.on_unload))
                if mapping is None:
                    self.lifecycle_errors.append("DriverUnload points outside mapped guest memory")
                else:
                    unload = Run()
                    unload.type = EP_DRIVER_UNLOAD
                    unload.start_addr = int(driver.on_unload)
                    unload.args = [driver.address]
                    self.add_run(unload)
                    driver.unload_called = True
        return self._exec_next_run()


class DriverEmulator(speakeasy.Speakeasy):
    def __init__(self, config, *, unload=False, persona=None, kernel_code_reference=None):
        super().__init__(config=config)
        self.unload = unload
        self.persona_config = persona
        self.kernel_code_reference_data = kernel_code_reference

    def load_module(self, *args, **kwargs):
        with batched_import_patching():
            module = super().load_module(*args, **kwargs)
            self.emu.bind_data_imports(module)
            return module

    def _init_emulator(self, **kwargs):
        # Classification was checked by Emumee. A native PE with no imports
        # must still receive DriverEntry arguments, regardless of PE heuristics.
        self.emu = DriverKernel(self.config, unload=self.unload, persona=self.persona_config,
            kernel_code_reference=self.kernel_code_reference_data)


def run_driver(data: bytes, info: SampleInfo, persona: dict, run_dir: Path,
               timeout: int, max_instructions: int, *, unload: bool = False,
               bundle_files=(), bundle_guest_root: str | None = None,
               kernel_code_reference: bytes | None = None,
               memory_strings: dict | None = None) -> dict:
    from .memory_strings import MemoryStringCapture
    string_capture = MemoryStringCapture(memory_strings)
    if info.kind != "driver" or info.managed:
        raise InvalidSample("Driver emulation requires a native kernel PE")
    if kernel_code_reference is not None and (info.architecture != 'x64' or persona['windows_build'] != 22631):
        raise InvalidSample('Kernel code references require an x64 build22631 driver profile')
    cfg = make_speakeasy_config(persona, info.name, timeout, max_instructions)
    kernel_providers.configure(cfg)
    if info.architecture == "x64":
        for index, definition in enumerate(cfg["modules"]["system_modules"]):
            definition["base_addr"] = hex(0xFFFFF80200000000 + index *
                (REFERENCE_PROVIDER_SPACING if kernel_code_reference is not None else 0x1000000))
    (run_dir / "kernel-modules").mkdir(exist_ok=True)
    for guest_path, host_path in materialize_virtual_files(persona, run_dir / "persona-files"):
        cfg["filesystem"]["files"].append({
            "mode": "full_path", "emu_path": guest_path, "path": str(host_path)})
    for relative, source, _payload in bundle_files:
        cfg["filesystem"]["files"].insert(0, {
            "mode": "full_path", "emu_path": ntpath.join(
                bundle_guest_root or persona["current_dir"], relative.replace("/", "\\")),
            "path": str(source)})
    # Never discover companion code from a host directory. Kernel dependencies
    # are the engine's modeled modules; supplied companion loading is rejected.
    cfg["modules"]["module_directory_x86"] = str(run_dir / "kernel-modules")
    cfg["modules"]["module_directory_x64"] = str(run_dir / "kernel-modules")
    catalog = ArtifactCatalog(run_dir / "artifacts", checkpoint=True)
    (run_dir / "worker-stage.txt").write_text("driver: scanning embedded input", encoding="utf-8")
    catalog.carve_pe(data, "embedded_input", skip_offset_zero=True)
    with DriverEmulator(cfg, unload=unload, persona=persona, kernel_code_reference=kernel_code_reference) as se:
        (run_dir / "worker-stage.txt").write_text("driver: loading kernel image", encoding="utf-8")
        module = se.load_module(data=data, filename=info.name)
        module.emu_path = ntpath.join(r"C:\Windows\System32\drivers", info.name)
        kernel = se.emu
        kernel.kernel_files.configure(persona)
        kernel_context = initialize_kernel_context(kernel)
        clock = VirtualClock(persona)
        kernel.virtual_clock = clock
        kernel.kernel_crt.persona_locale = persona["locale"]
        kernel.kernel_crt.oem_code_page = oem_code_page(persona["locale"])
        clock.attach_shared_data(kernel)
        cpu = VirtualCPU(persona, clock)
        cpu.avx_write_guard = lambda address, size: kernel.observe_image_write(se, 0, address, size, 0)
        cpu.attach(kernel)
        kernel.cpu_model = cpu
        kernel.evidence_range = (module.base, module.base + module.image_size)
        se.add_mem_write_hook(kernel.observe_image_write, begin=module.base,
                              end=module.base + module.image_size - 1)
        se.add_mem_read_hook(kernel.observe_header_read, begin=module.base,
                             end=module.base + min(4096, module.image_size) - 1)
        unresolved = set(kernel.import_table) - getattr(kernel, "modeled_function_addresses", set())
        if unresolved:
            se.add_mem_read_hook(kernel.observe_import_storage_read, begin=min(unresolved),
                                 end=max(unresolved) + kernel.get_ptr_size() - 1)
        reference=kernel.kernel_code_reference
        provider_reads = KernelProviderReads(kernel, sample_interval=64 if reference is not None else 1,
            sample_ranges=[(reference.base+s['rva'], reference.base+s['rva']+s['size']) for s in reference.code] if reference is not None else ())
        provider_reads.install(se)
        kernel.deadline = time.monotonic() + timeout
        kernel.progress_path = run_dir / "driver-progress.json"
        (run_dir / "worker-stage.txt").write_text("driver: running DriverEntry", encoding="utf-8")
        se.run_module(module, all_entrypoints=False)
        (run_dir / "worker-stage.txt").write_text("driver: collecting execution report", encoding="utf-8")
        # Remove return values fabricated by the engine at instruction/time
        # stops. Only a visit to the emulator's return sentinel counts.
        for run in kernel.runs:
            if id(run) not in kernel.returned_runs:
                run.ret_val = None
        from .kernel_memory_report import capture as capture_memory_report
        memory_capture = capture_memory_report(kernel)
        report = se.get_report().model_dump(mode="json")
        report["kernel_memory_capture"] = memory_capture
        report["kernel_provider_reads"] = provider_reads.report()
        report["kernel_code_reference"] = kernel.kernel_code_reference.report() if kernel.kernel_code_reference else None
        report["kernel_formatting"] = {**kernel.kernel_formatting,
            'observations': list(kernel.kernel_formatting['observations'])}
        report["kernel_provider_metadata"] = kernel_providers.report(kernel)
        if kernel.get_ptr_size() == 8 and any(run.error for run in kernel.runs):
            report["exception_unwind"] = walk_exception_frames(kernel)
        # CPU write hooks run before the store. Compare final bytes so a denied
        # or rolled-back write cannot be presented as a recovered code change.
        changed_pages = [page for page, original in kernel.written_pages.items()
                         if hashlib.sha256(kernel.mem_read(page, 0x1000)).hexdigest() != original]
        changed_pages.sort()
        image_changes = {"written_pages_observed": len(kernel.written_pages),
                         "tracking_limit_reached": kernel.image_write_tracking_limited,
                         "changed_pages": len(changed_pages),
                         "executed_after_write_pages": len(set(changed_pages) & kernel.executed_written_pages),
                         "module_base": hex(module.base), "module_size": module.image_size}
        report["driver_image_changes"] = image_changes
        report["kernel_context"] = kernel_context
        report["kernel_cpu"] = kernel.kernel_cpu.report()
        report["kernel_system_information"] = kernel.kernel_system_information.report()
        report["kernel_object_references"] = kernel.object_references.report()
        report["kernel_debugger_state"] = kernel.debugger_state.report()
        report["kernel_initial_system_process"] = kernel.initial_system_process.report()
        report["kernel_address_boundaries"] = kernel.kernel_environment.report_address_boundaries()
        report["kernel_opaque_data"] = kernel.opaque_data.report()
        report["driver_tracing"] = trace_report(kernel)
        report["kernel_data_imports"] = [{"api": f"{name}.{symbol}", "address": hex(address)}
            for (name, symbol), address in kernel.data_import_addresses.items()]
        report["kernel_bugcheck_callbacks"] = kernel.bugcheck_callbacks.report()
        report["kernel_named_callbacks"] = kernel.named_callbacks.report()
        report["kernel_export_catalog"] = kernel.export_catalog.report()
        report["kernel_synchronization"] = kernel.synchronization.report()
        report["kernel_cache_aware_rundown"] = kernel.cache_aware_rundown.report()
        report["kernel_dispatcher"] = kernel.dispatcher.report()
        report["kernel_mdls"] = kernel.mdls.report()
        report["kernel_scheduling"] = kernel.kernel_threads.report()
        report["kernel_ipi"] = kernel.ipi.report()
        report["image_base"] = module.base
        report["image_placement"] = kernel.image_placement
        report["stopped_registers"] = kernel.get_register_state()
        report["driver_header_reads"] = {"observations": kernel.header_reads,
                                         "omitted": kernel.header_reads_omitted}
        report["virtual_uptime_ms"] = clock.uptime_ms
        report["virtual_tsc"] = cpu.tsc()
        report["instruction_cache"] = {"hits": kernel.instruction_cache.hits,
                                       "misses": kernel.instruction_cache.misses,
                                       "page_limit": kernel.instruction_cache.limit}
        report["instruction_repetitions"] = {
            "consecutive_rep_movsb_iterations": kernel.repeat_movsb_iterations,
            "charged_to_instruction_budget": True,
            "coalesced_in_control_flow_tail": True}
        tail = []
        for address, size in kernel.instruction_tail:
            item = {"pc": hex(address), "size": size}
            try:
                item["final_bytes"] = kernel.mem_read(address, size).hex()
                item["instruction"] = kernel.get_disasm(address, max(16, size))[2][:256]
            except Exception:
                item["instruction"] = "unavailable"
            tail.append(item)
        report["instruction_tail"] = tail
        report["control_flow_tail"] = [dict({"from":hex(source),"to":hex(target),"registers_sampled":sampled},
                                           **({"registers":registers} if registers is not None else {}))
                                       for source,target,sampled,registers in kernel.control_flow_tail]
        report["control_flow_register_sampling"] = {"new_edges": True,
            "periodic_transfer_interval": 4096, "edge_set_limit": 8192}
        report["context_observations"] = list(kernel.context_observations)
        entries = report.get("entry_points") or []
        errors = [_engine_error_text(error) for error in report.get("errors") or [] if error]
        errors.extend(_engine_error_text(entry["error"]) for entry in entries if entry.get("error"))
        errors.extend(kernel.lifecycle_errors)
        errors.extend(kernel.kernel_crt.unsupported)
        if kernel.cancel_requested:
            errors.append("Driver execution stopped by analyst control; initialization was not completed")
        coverage = _api_coverage(report)
        if coverage["signature_only_calls"]:
            errors.append("Signature-only kernel APIs: " + ", ".join(
                item["api"] for item in coverage["signature_only_calls"][:20]))
        count = sum(int(entry.get("instr_count") or 0) for entry in entries)
        limited = kernel.limit_reached or (count >= max_instructions and any(
            entry.get("ret_val") is None for entry in entries))
        timed_out = kernel.timeout_reached or (time.monotonic() >= kernel.deadline and any(
            entry.get("ret_val") is None for entry in entries))
        if limited:
            errors.append(f"Driver instruction budget exhausted at {max_instructions} instructions")
        if timed_out:
            errors.append(f"Driver emulation exceeded the {timeout}-second wall-clock limit")
        entry = next((item for item in entries if item.get("ep_type") == "entry_point"), {})
        raw_status = entry.get("ret_val") if not entry.get("error") else None
        status = (int(raw_status, 0) if isinstance(raw_status, str) else raw_status)
        status = status & 0xFFFFFFFF if status is not None else None
        driver = next(drv for drv in kernel.drivers if drv.pe == module)
        driver.read_back()
        lifecycle = {
            "entry_status": status,
            "initialization_succeeded": status is not None and not bool(status & 0x80000000),
            "registry_path": driver.reg_path,
            "driver_object": hex(driver.address),
            "unload_requested": unload,
            "unload_registered": bool(driver.on_unload),
            "unload_completed": any(item.get("ep_type") == "driver_unload" and
                                    item.get("ret_val") is not None and not item.get("error")
                                    for item in entries),
            "devices_created": [{"name": str(dev.name)[:1024], "address": hex(dev.address)}
                        for dev in driver.devices[:64]],
            "dispatch_routines": {str(index): hex(int(address))
                                  for index, address in enumerate(driver.mj_funcs) if address},
            "scope": "DriverEntry and optionally DriverUnload; no synthetic IRPs or hardware",
        }
        (run_dir / "worker-stage.txt").write_text("driver: capturing modified image pages", encoding="utf-8")
        # Retain changed pages as bounded chunks with their image RVAs. These
        # are evidence of mutation, not a claim of a complete unpacked image.
        index = 0
        while index < len(changed_pages):
            first = changed_pages[index]
            stop = index + 1
            while (stop < len(changed_pages) and changed_pages[stop] == changed_pages[stop - 1] + 0x1000
                   and stop - index < 1024):
                stop += 1
            size = (stop - index) * 0x1000
            payload = kernel.mem_read(first, size)
            source = f"modified_driver_image:0x{first - module.base:x}"
            catalog.add(payload, source, kind="memory", context={
                "module_base": hex(module.base), "module_rva": first - module.base,
                "executed_after_write": any(page in kernel.executed_written_pages
                                            for page in changed_pages[index:stop]),
                "original_page_hashes_sha256": hashlib.sha256(b"".join(
                    bytes.fromhex(kernel.written_pages[page]) for page in changed_pages[index:stop])).hexdigest()})
            catalog.carve_pe(payload, source)
            index = stop
        # A failure NTSTATUS is a completed observation, not an emulator error.
        # Registered callbacks and devices describe guest state, not coverage.
        for item in kernel.get_file_manager().files:
            if item.config or not item.bytes_written:
                continue
            payload = item.data.getvalue() if isinstance(item.data, io.BytesIO) else item.data
            if isinstance(payload, bytes) and payload:
                catalog.add(payload, "virtual_file_final", guest_path=item.path)
        for point in entries:
            for event in point.get("events") or []:
                if event.get("event") == "file_write" and event.get("data_ref"):
                    payload = _report_blob(report.get("data") or {}, event["data_ref"])
                    if payload:
                        catalog.add(payload, "file_write", guest_path=event.get("path") or "")
        scanned = 0
        for tag, base, _size, freed, _process, blob in se.get_memory_dumps():
            if freed:
                continue
            mapped_module = kernel.get_mod_from_addr(base)
            if (not str(tag).startswith("emu.module.") or
                    mapped_module is not None and not mapped_module.is_decoy()):
                string_capture.scan_memory(blob, f"memory:{tag}", base)
            remaining = max(0, MAX_MEMORY_SCAN - scanned)
            if len(blob) > remaining:
                catalog.note_omission(f"memory:{tag}:0x{base:x}", len(blob) - remaining,
                                      "memory_scan_run_limit")
            blob = blob[:remaining]
            scanned += len(blob)
            if blob:
                catalog.carve_pe(blob, f"memory:{tag}:0x{base:x}",
                                 skip_offset_zero=str(tag).startswith("emu.module."))
                if len(blob) <= 4 * 1024 * 1024 and str(tag).startswith("api.pool."):
                    catalog.add(blob, f"memory:{tag}:0x{base:x}", kind="memory")
        reason = ("cancelled" if kernel.cancel_requested else "instruction_limit" if limited else "timeout" if timed_out else
                  "error" if errors else "entry_return" if status is not None else "unknown")
        report.update({"execution_mode": "kernel", "driver": lifecycle,
                       "memory_strings": string_capture.report(),
                       "image_protections": {"requests": kernel.image_protections.requests,
                                             "applied": kernel.image_protections.applied},
                       "artifact_capture": catalog.capture_summary()})
        kernel.progress_path.write_text(json.dumps({"status": "stopped", "instruction_count": count,
            "completion_reason": reason, "driver_image_changes": image_changes}), encoding="utf-8")
        (run_dir / "engine-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        catalog.save_manifest()
        return {"engine": "speakeasy-unicorn", "execution_mode": "kernel",
                "memory_strings": string_capture.report(),
                "engine_report": "engine-report.json", "driver": lifecycle,
                "driver_image_changes": image_changes,
                "artifacts": catalog.items, "artifact_groups": catalog.groups(),
                "artifact_capture": catalog.capture_summary(), "api_coverage": coverage,
                "entry_points": len(entries), "instruction_count": count,
                "instruction_limit_reached": limited, "timeout_reached": timed_out,
                "guest_exit_code": None, "guest_entry_return": status,
                "completion_reason": reason, "denied_operations": 0, "errors": errors}
