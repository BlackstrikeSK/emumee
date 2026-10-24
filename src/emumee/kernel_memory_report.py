"""Bounded final-layout metadata from already collected guest access counters.

This records guest CPU accesses, not API implementation reads or writes. Final
layout and execution counters do not establish that an unpacked PE was saved.
"""
from bisect import bisect_right
import ntpath


def capture(kernel, max_records=8192, max_modules=128, max_segments=2048, max_dynamic=8192):
    native = sorted(kernel.emu_eng.emu.mem_regions())
    starts = [region[0] for region in native]
    modules = list(kernel.modules)
    by_base = {module.base: module for module in modules}
    module_ranges = [(module.base, module.base + module.image_size) for module in modules]

    def protection(address, size):
        cursor, end, values = address, address + size, set()
        while cursor < end:
            index = bisect_right(starts, cursor) - 1
            if index < 0 or not native[index][0] <= cursor <= native[index][1]:
                return 'unmapped'
            values.add(native[index][2])
            if len(values) > 1:
                return 'mixed'
            cursor = min(end, native[index][1] + 1)
        flags = next(iter(values), 0)
        return ''.join(letter if flags & bit else '-' for letter, bit in (('r',1),('w',2),('x',4)))

    emitted = omitted = dynamic_count = omitted_dynamic = 0
    for run in kernel.runs:
        existing = run.dyn_code.get('mmap') or []
        retained = existing[:max(0, max_dynamic - dynamic_count)]
        omitted_dynamic += len(existing) - len(retained)
        run.dyn_code = {'mmap': retained, 'base_addrs': {
            int(entry['base'], 0) if isinstance(entry['base'], str) else entry['base']
            for entry in retained}}
        dynamic_count += len(retained)
        run.memory_regions.clear()
        run.loaded_modules.clear()
        for mapping, access in run.mem_access.items():
            # Dynamic-code evidence has its own global bound; a full layout
            # must not silently discard it when its separate budget remains.
            if access.execs and not any(begin <= mapping.base < end for begin, end in module_ranges):
                if mapping.base not in run.dyn_code['base_addrs']:
                    if dynamic_count < max_dynamic:
                        kernel.profiler.record_dyn_code_event(run, mapping.tag, mapping.base, mapping.size)
                        dynamic_count += 1
                    else:
                        omitted_dynamic += 1
            if emitted >= max_records:
                omitted += 1
                continue
            run.memory_regions.append({'tag': str(mapping.tag or '')[:512], 'address': mapping.base,
                'size': mapping.size, 'prot': protection(mapping.base, mapping.size), 'is_free': mapping.free,
                'accesses': {'reads': access.reads, 'writes': access.writes, 'execs': access.execs}})
            emitted += 1
        for (base, rva), access in run.section_access.items():
            if emitted >= max_records:
                omitted += 1
                continue
            module = by_base.get(base)
            if module is None:
                omitted += 1
                continue
            section = next((section for section in module.sections if section.virtual_address == rva), None)
            size = section.virtual_size if section else min((section.virtual_address for section in module.sections), default=4096)
            tag = f'emu.module.{module.name}.{section.name if section else "headers"}'
            run.memory_regions.append({'tag':tag[:512], 'address':base+rva, 'size':size,
                'prot':protection(base+rva,size), 'is_free':False,
                'accesses':{'reads':access.reads, 'writes':access.writes, 'execs':access.execs}})
            emitted += 1

    inventory = []
    segment_count = omitted_segments = 0
    for module in modules[:max_modules]:
        segments = []
        for section in module.sections:
            if segment_count >= max_segments:
                omitted_segments += 1
                continue
            segments.append({'name':section.name,'address':module.base+section.virtual_address,
                'size':section.virtual_size,'prot':protection(module.base+section.virtual_address,section.virtual_size)})
            segment_count += 1
        inventory.append({'name':ntpath.basename(module.emu_path) or module.name, 'path':module.emu_path,
                          'base':module.base,'size':module.image_size,'segments':segments})
    if kernel.runs:
        kernel.runs[0].loaded_modules = inventory
    return {'scope':'Final layout and native guest counters; API host memory operations are not included in counters; '
                    'module inventory appears once; no memory-byte dumps',
            'region_records':emitted,'omitted_region_records':omitted,'module_count':len(inventory),
            'omitted_modules':max(0,len(modules)-max_modules),'omitted_segments':omitted_segments,
            'dynamic_regions':dynamic_count,'omitted_dynamic_regions':omitted_dynamic,
            'limited':bool(omitted or len(modules)>max_modules or omitted_segments or omitted_dynamic)}
