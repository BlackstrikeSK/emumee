"""Bounded, passive evidence of native reads from modeled kernel providers."""

from collections import Counter, deque
from functools import partial
from speakeasy.windows.loaders import ApiModuleLoader
from .kernel_providers import PROVIDER_EXPORTS


class KernelProviderReads:
    def __init__(self, kernel, *, first_limit=256, tail_limit=256,
                 stack_limit=128, all_register_pointers=False, scope=None,
                 sample_interval=1, sample_ranges=()):
        self.kernel = kernel
        self.first_limit = max(0, min(first_limit, 256))
        self.tail = deque(maxlen=max(0, min(tail_limit, 256)))
        self.first = {}
        self.latest = {}
        self.last_observed = {}
        self.sample_interval = max(1, min(int(sample_interval), 4096))
        self.sample_ranges = tuple(sample_ranges)
        if len(self.sample_ranges) > 32 or any(not 0 <= start < end <= 1 << 64 for start, end in self.sample_ranges):
            raise ValueError('Invalid provider snapshot sampling ranges')
        self.sampled_out_reads = 0
        self.reads = Counter()
        self.sequence = 0
        self.capture_errors = 0
        self.stack_limit = max(0, min(stack_limit, 1024))
        self.all_register_pointers = all_register_pointers
        self.watched_regions = []
        self.watch_errors = 0
        self.omitted_watched_regions = 0
        self.scope = scope or 'Native reads of modeled provider images; bounded first/latest read per provider/PC and global tail; pointer/stack prefixes are passive snapshots, not resolved APIs'
        if self.sample_interval > 1:
            self.scope += '; selected ranges use periodic full snapshots; latest captured contexts may precede exact last-read metadata'

    def install(self, facade):
        for module in self.kernel.modules:
            if isinstance(module.loader, ApiModuleLoader) or module.name in PROVIDER_EXPORTS:
                self.watch_region(module.name, module.base, module.image_size, facade=facade)

    def watch_region(self, name, address, size, *, facade=None):
        from types import SimpleNamespace
        for watched in self.watched_regions:
            previous = int(watched['address'], 0)
            if previous == address and watched['size'] == size:
                return True  # One physical read must not acquire duplicate callbacks.
            if address < previous + watched['size'] and previous < address + size:
                self.omitted_watched_regions += 1
                return False  # Explicitly bound partially overlapping observations.
        if len(self.watched_regions) >= 128:
            self.omitted_watched_regions += 1
            return False
        region = SimpleNamespace(name=name, base=address)
        try:
            (facade or self.kernel).add_mem_read_hook(partial(self.observe, region),
                begin=address, end=address + size - 1)
        except Exception:
            self.watch_errors += 1
            return False
        self.watched_regions.append({'name': name, 'address': hex(address), 'size': size})
        return True

    def observe(self, module, _facade, _access, address, size, _value):
        self.sequence += 1
        self.reads[module.name] += 1
        try:
            kernel = self.kernel
            pc = kernel.get_pc()
            key = module.name, pc
            save_first = key not in self.first and len(self.first) < self.first_limit
            save_latest = save_first or key in self.first
            if save_latest:
                self.last_observed[key] = (self.sequence, address, size, kernel.curr_run.instr_cnt)
            if not save_latest and not self.tail.maxlen:
                return True
            sampled = (not self.sample_ranges or any(start <= address < end for start, end in self.sample_ranges))
            if sampled and self.sample_interval > 1 and not save_first and self.sequence % self.sample_interval:
                self.sampled_out_reads += 1
                return True
            # Snapshot only readable native VM ranges, without allocating,
            # touching guest counters, observing virtual time or invoking APIs.
            regions = list(kernel.emu_eng.emu.mem_regions())

            def prefix(pointer, maximum):
                for start, end, permissions in regions:
                    if start <= pointer <= end and permissions & 1:
                        return kernel.mem_read(pointer, min(maximum, end + 1 - pointer)).hex()
                return None

            registers = kernel.get_register_state()
            wide = kernel.get_ptr_size() == 8
            names = ('rcx', 'rdx', 'r8', 'r9', 'rsi', 'rdi') if wide else ('eax', 'ecx', 'edx', 'esi', 'edi')
            if self.all_register_pointers:
                names = tuple(name for name in registers if name not in ('rip', 'eip'))
            pointers = {}
            for name in names:
                pointer = int(registers[name], 0)
                data = prefix(pointer, 64)
                if data is not None:
                    pointers[name] = {'address': hex(pointer), 'prefix': data}
            sp = int(registers['rsp' if wide else 'esp'], 0)
            item = {'sequence': self.sequence, 'provider': module.name,
                'pc': hex(pc), 'address': hex(address), 'rva': hex(address - module.base),
                'size': size, 'prefix_at_read': prefix(address, min(max(size, 1), 64)),
                'registers_before': registers, 'register_pointer_prefixes': pointers,
                'stack_address': hex(sp), 'stack_prefix': prefix(sp, self.stack_limit),
                'run_instructions': kernel.curr_run.instr_cnt,
                'thread_id': kernel.curr_run.thread.tid if kernel.curr_run.thread else None}
            if save_first:
                self.first[key] = item
            if save_latest:
                self.latest[key] = item
            self.tail.append(item)
        except Exception:
            # Diagnostics cannot change native results, even if a snapshot is
            # unavailable. Explicitly report missing evidence instead.
            self.capture_errors += 1
        return True

    def report(self):
        captured = ({item['sequence'] for item in self.first.values()} |
                    {item['sequence'] for item in self.latest.values()} |
                    {item['sequence'] for item in self.tail})
        return {'scope': self.scope,
            'total_reads': self.sequence, 'reads_by_provider': dict(self.reads),
            'first_pc_limit': self.first_limit, 'tail_limit': self.tail.maxlen,
            'first_pc_observations': list(self.first.values()),
            'latest_pc_observations': list(self.latest.values()), 'tail': list(self.tail),
            'sample_interval': self.sample_interval, 'sampled_out_reads': self.sampled_out_reads,
            'sampling_ranges': [{'address':hex(start),'size':end-start} for start,end in self.sample_ranges],
            'snapshot_scope': 'First and latest captured snapshots plus captured tail; periodic sampling applies only inside declared ranges (or all reads when no ranges); exact last-read metadata has no register/pointer snapshot',
            'last_observed_per_pc': [{'provider':key[0],'pc':hex(key[1]),'sequence':v[0],
                'address':hex(v[1]),'size':v[2],'run_instructions':v[3]} for key,v in self.last_observed.items()],
            'omitted_reads': self.sequence - len(captured), 'capture_errors': self.capture_errors,
            'watched_regions': self.watched_regions, 'watch_errors': self.watch_errors,
            'omitted_watched_regions': self.omitted_watched_regions,
            'stack_prefix_limit': self.stack_limit}
