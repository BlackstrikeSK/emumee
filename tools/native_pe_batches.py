"""Freeze and validate an exact, dependency-ordered native API work partition."""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import re

from native_pe_worklist import (
    CLOSED_STATES, atomic_write, contract_key, fingerprint, indexed,
    validate_batch_graph, validate_evidence,
)


MODULE_FAMILIES = {
    'crt': 'msvcrt ucrtbase api-ms-win-crt-private-l1-1-0 api-ms-win-crt-string-l1-1-0',
    'crypto': 'bcrypt bcryptprimitives crypt32 ncrypt',
    'network': 'dnsapi icmp iphlpapi mpr netapi32 netutils winhttp wininet ws2_32 wkscli',
    'ui': 'comctl32 gdi32 msimg32 user32 winmm ext-ms-win-ntuser-chartranslation-l1-1-0',
    'com': 'com_api ole32 oleaut32 rpcrt4 shell32 shlwapi urlmon',
    'security': 'advapi32 secur32 sspicli',
    'misc': 'advpack lz32 msvfw32 sfc version wtsapi32 ext-ms-win-fsutilext-ulib-l1-1-0',
    'native-bridges': 'mscoree msi32',
    'system': 'kernel32 kernelbase ntdll psapi api-ms-win-core-apiquery-l1-1-0 '
              'api-ms-win-core-console-l1-1-0 api-ms-win-core-console-l2-1-0 '
              'api-ms-win-core-delayload-l1-1-1 api-ms-win-core-file-l1-1-0 '
              'api-ms-win-core-file-l1-2-0 api-ms-win-core-handle-l1-1-0 '
              'api-ms-win-core-heap-l1-1-0 api-ms-win-core-libraryloader-l1-2-0 '
              'api-ms-win-core-localization-l1-2-0 api-ms-win-core-memory-l1-1-0 '
              'api-ms-win-core-registry-l1-1-0 api-ms-win-core-string-l1-1-0 '
              'api-ms-win-core-string-l2-1-0 api-ms-win-core-sysinfo-l1-1-0 '
              'api-ms-win-core-timezone-l1-1-0',
}
MODULES = {module: family for family, modules in MODULE_FAMILIES.items() for module in modules.split()}
EXPORT_RULES = (
    ('exceptions', r'^(?:AddVectored|RemoveVectored|RaiseException|SetUnhandledExceptionFilter|UnhandledExceptionFilter|Rtl(?:AddVectored|RemoveVectored|CaptureContext|LookupFunctionEntry|Unwind))'),
    ('resources', r'^(?:FindResource|LoadResource|LockResource|FreeResource|SizeofResource|LoadString)'),
    ('environment', r'^(?:GetCommandLine|GetEnvironment|FreeEnvironment|ExpandEnvironment|SetEnvironment|GetStartupInfo|RtlGetCurrentPeb)'),
    ('time', r'^(?:GetSystemTime|GetLocalTime|GetTickCount|GetTimeZone|GetDynamicTimeZone|QueryPerformance|CompareFileTime|FileTimeTo|SystemTimeTo)'),
    ('persona', r'^(?:GetComputerName|GetSystem(?:Info|Directory|FirmwareTable|Default)|GetNativeSystemInfo|GetPhysicallyInstalledSystemMemory|GetWindowsDirectory|GetVersion|VerifyVersionInfo|VerSetConditionMask|Get(?:UserDefault|LocaleInfo|DateFormat|TimeFormat|CurrentPackageId)|GlobalMemoryStatus|Is(?:ProcessorFeaturePresent|Wow64Process|ValidLocale)|WTSGetActiveConsoleSessionId|Rtl(?:GetVersion|GetNtVersionNumbers|VerifyVersionInfo|QueryFeatureConfiguration))'),
    ('registry', r'^(?:Reg|Nt(?:Open|Create|Query|Set|Enumerate|Delete)Key|Zw(?:Open|Create|Query|Set|Enumerate|Delete)Key)'),
    ('crypto', r'^(?:Crypt|SystemFunction0)'),
    ('allocation', r'^(?:Heap|Local(?:Alloc|ReAlloc|Free|Lock|Unlock|Size)|Global(?:Alloc|ReAlloc|Free|Lock|Unlock|Size|Flags|Handle)|Virtual(?:Alloc|Free|Protect|Query)|IsBad(?:Read|Write|String)Ptr|(?:Rtl|Nt|Zw)(?:Allocate|Free|ReAllocate|Size|CreateHeap|DestroyHeap|ProtectVirtual|QueryVirtual))'),
    ('loader', r'^(?:LoadLibrary|FreeLibrary|GetModule|GetProcAddress|Ldr|EnumProcessModules|GetMappedFileName|DisableThreadLibraryCalls|SetDllDirectory|SetDefaultDllDirectories|ResolveDelayLoadedAPI|ApiSetQueryApiSetPresence|K32(?:EnumProcessModules|GetModule|GetMappedFileName))'),
    ('synchronization', r'^(?:WaitFor|SignalObject|Sleep|SwitchToThread|Nt(?:Wait|Yield)|Initialize(?:ConditionVariable|SListHead)|(?:Create|Open|Set|Reset|Pulse)(?:Event|Mutex|Semaphore|WaitableTimer)|(?:Release|Cancel)(?:Mutex|Semaphore|WaitableTimer)|(?:Initialize|Enter|Leave|Delete|TryEnter)CriticalSection|(?:Acquire|Release|Initialize|TryAcquire)SRW|Interlocked|Wake|InitOnce)'),
    ('process', r'^(?:CreateProcess|CreateRemoteThread|CreateThread|OpenProcess|OpenThread|ExitProcess|ExitThread|Terminate|GetCurrentProcess|GetCurrentThread|GetProcess|GetThread|SetThread|SetProcess|SuspendThread|ResumeThread|QueueUserAPC|Tls|Fls|ReadProcessMemory|WriteProcessMemory|DuplicateHandle|CloseHandle|CreateToolhelp32Snapshot|Process32|Thread32|Module32|EnumProcesses|GetExitCode|GetHandleInformation|SetHandle|GetLastError|SetLastError|GetErrorMode|SetErrorMode|SetPriorityClass|ProcessIdToSessionId|WinExec|IsDebuggerPresent|CheckRemoteDebuggerPresent|Nt(?:QueryInformationProcess|SetInformationProcess)|Rtl(?:GetLastWin32Error|NtStatusToDosError))'),
    ('filesystem', r'^(?:CreateFile|ReadFile|WriteFile|CloseFile|FlushFile|GetFile|SetFile|FindFirst|FindNext|FindClose|DeleteFile|CopyFile|MoveFile|ReplaceFile|CreateDirectory|RemoveDirectory|GetCurrentDirectory|SetCurrentDirectory|GetFullPath|GetLongPath|GetShortPath|GetTemp|GetDrive|GetDisk|GetLogicalDrive|CreateFileMapping|OpenFileMapping|MapView|UnmapView|FlushView|LockFile|UnlockFile|GetVolume|SetEndOfFile|GetStdHandle|SetStdHandle|ReadConsole|WriteConsole|AllocConsole|FreeConsole|GetConsole|SetConsole|AreFileApisANSI|GetBinaryType|FindVolume|QueryDosDevice|Wow64.*FsRedirection|(?:Create|Connect|Disconnect|Peek)NamedPipe|CreatePipe|CreateIoCompletionPort|DeviceIoControl|GetComm|GetMailslotInfo|_l(?:close|lseek|open)|(?:Nt|Zw)(?:CreateFile|OpenFile|ReadFile|WriteFile|QueryInformationFile|SetInformationFile|UnmapViewOfSection))'),
    ('strings', r'^(?:lstr|(?:Rtl)?(?:InitAnsiString|InitUnicodeString|AnsiString|UnicodeString|CompareMemory|CopyMemory|MoveMemory|FillMemory|ZeroMemory|Ipv4AddressToString|IsTextUnicode|OemToUnicodeN)|MultiByteToWideChar|WideCharToMultiByte|CompareString|LCMapString|GetStringType|CharUpper|CharLower|IsChar|FindStringOrdinal|FormatMessage|GetACP|GetOEMCP|GetCPInfo|IsDBCSLeadByte|IsValidCodePage)'),
)
CRT_RULES = (
    ('allocation', r'^(?:malloc|calloc|realloc|free|_aligned_|_malloca|_freea|\?\?[23])'),
    ('strings', r'^(?:_?(?:str|wcs|mem)|toupper|tolower|atoi|atol|wcsto)'),
    ('crt-stdio', r'^(?:_?(?:fopen|fclose|fread|fwrite|fseek|ftell|fget|fput|fileno|fdopen|open|close|read|write|lseek|eof|setmode|commit)|puts|gets|perror|fflush|rewind|feof|ferror|clearerr|setbuf|setvbuf)'),
    ('crt-format', r'^(?:_?(?:s?n?w?printf|v.*printf|.*scanf)|__stdio_common_)'),
    ('crt-math', r'^(?:abs|labs|llabs|div|ldiv|sqrt|pow|sin|cos|tan|atan|log|exp|ceil|floor|fmod|frexp|ldexp|modf|_?(?:isnan|finite|controlfp|copysign|ftol))'),
)
FAMILY_REQUIREMENTS = {
    'allocation': ('heap and virtual-memory ownership', [], 'zero/resize/free/protect and allocation lifetime', 'overflow, interior pointers, double free and protected backing'),
    'strings': ('guest buffers and codepage state', ['allocation'], 'narrow/wide conversion, widths, lengths and canaries', 'overlap, malformed encoding, unterminated input and short output'),
    'crt': ('CRT process/thread globals and stream ownership', ['allocation', 'strings', 'filesystem'], 'startup, argv, formatting, varargs, streams and teardown', 'bad formats, pointer bounds, EOF/error state and ownership'),
    'crt-stdio': ('CRT streams sharing the owned VFS and descriptors', ['allocation', 'filesystem'], 'byte/character IO, positions, modes, descriptors and stream lifetime', 'EOF/error preservation, short IO, invalid descriptors and failed close'),
    'crt-format': ('CRT locale, varargs ABI and bounded output buffers', ['allocation', 'strings'], 'narrow/wide integer, floating-point and string formatting/scanning', 'bad formats, missing arguments, truncation and output canaries'),
    'crt-math': ('guest floating-point environment and width/sign rules', ['allocation'], 'independent numeric vectors, rounding, conversions and exceptional values', 'NaN/inf, overflow, divide-by-zero and preserved error state'),
    'filesystem': ('owned VFS, mappings, handles and mutation journal', ['allocation', 'persona'], 'open/read/write/map/enumerate and artifact bytes', 'sharing denial, path escapes, stale handles and failed mutation rollback'),
    'registry': ('owned registry roots, views and handles', ['allocation', 'persona'], 'types, enumeration, buffers, views and persistent mutations', 'bad root/view/access, short buffers and cross-owner handles'),
    'loader': ('one module catalog and loader lifecycle', ['allocation', 'strings'], 'name/ordinal/alias resolution, refcounts and module visibility', 'missing/cyclic dependency, failed attach and use after unload'),
    'process': ('owned process/thread identities, contexts and TLS', ['allocation', 'loader', 'persona'], 'creation/context/exit and independent process/thread state', 'invalid target, wrong owner, partial copy and shared-budget exhaustion'),
    'synchronization': ('guest scheduler, wait queues and virtual clock', ['process'], 'Any/All waits, signaling, deadlines, callbacks and continuations', 'deadlock, timeout, alertability, reentrancy and exhausted run budget'),
    'persona': ('one validated persona and virtual time authority', ['allocation'], 'contrasting personas, enumeration and direct-memory consistency', 'short buffers, invalid selectors and contradictory persona views'),
    'time': ('one virtual clock and persona time-zone authority', ['allocation', 'persona'], 'file/system/local time conversions, counters, units and wraparound', 'invalid dates, short outputs, overflow and inconsistent clock views'),
    'environment': ('owned process parameters, argv and environment blocks', ['allocation', 'strings'], 'direct PEB/environment reads, quoting, expansion and mutation', 'missing variables, short outputs, encoding and cross-process leakage'),
    'exceptions': ('owned user exception/unwind state and continuations', ['process'], 'SEH/VEH/unwind ordering, context preservation and callback return', 'nested fault, invalid handler/unwind metadata and shared-budget exhaustion'),
    'resources': ('module-owned resource catalog and guest buffers', ['loader'], 'resource name/ID/language selection, bytes and lifetime', 'missing/malformed resource, short buffers and unloaded owner'),
    'security': ('owned tokens, SIDs, privileges and service state', ['allocation', 'persona'], 'serialized identity/access/privilege/service contracts', 'denied access, malformed structures, wrong ownership and stale handles'),
    'crypto': ('owned provider/key/hash/RNG state', ['allocation'], 'independent known-answer vectors, streaming and lifecycle', 'bad key/algorithm/length, short output and destroyed handles'),
    'network': ('offline fixture, socket/session and adapter authorities', ['allocation', 'persona'], 'exact DNS/socket/HTTP fixtures, partial IO and event bytes', 'fixture miss, denied request, cancellation and zero host networking'),
    'ui': ('bounded guest window/message/resource state', ['allocation', 'persona', 'synchronization'], 'messages, resources, callbacks, timers and serialized buffers', 'bad handles/resources, callback faults and queue quotas'),
    'com': ('guest interfaces, refcounts, variants and callback ABI', ['allocation', 'strings', 'security'], 'vtables, identity, activation, variants and release lifetime', 'bad IID/vtable, failed activation, use after release and no host COM'),
    'misc': ('explicit per-export owned model state', ['allocation', 'persona'], 'review each exact export including resource/version/compression effects', 'bad pointer/size, unsupported variant and observable failure state'),
    'native-bridges': ('frozen native-facing CLR/MSI registration disposition', [], 'characterize exact native baseline effects or proven placeholders', 'unsupported managed/MSI expansion must not become invented success'),
}
DEFAULT_CONTROLS = {
    'oracle': 'Frozen handler source with synthetic guest services; use independently authored properties when safe observation is unavailable. Retain exact inputs, outputs and source/dependency hashes; unproved equivalence stays open.',
    'guest_controls': 'Execute named and ordinal imports on x86 and x64, check ABI/return/error state and memory canaries, and prove the public contained submitted route. Exercise every distinct ABI/state/callback path; alias dispatch alone is not a semantic oracle.',
    'negative_controls': 'Check invalid pointers/handles, bounded work/output, preserved failed state, teardown and explicit unsupported outcomes. Never invoke host guest effects.',
}


def variants(row):
    name = row['export']
    if not isinstance(name, str) or not name:
        raise ValueError('Invalid legacy export')
    names = [name[:-1] + suffix for suffix in ('A', 'W')] if name.endswith('*') else [name]
    if not name.endswith('*') and row.get('character_width_dispatch'):
        names = [name + suffix for suffix in ('A', 'W')]
    if row.get('ordinal'):
        names.append('#' + str(row['ordinal']))
    return sorted(set(names))


def inventory_contracts(inventory):
    declarations = defaultdict(list)
    for row in inventory['entries']:
        for name in variants(row):
            for architecture in ('x86', 'x64'):
                key = contract_key(dict(module=row['module'], export=name, kind=row['kind'], architecture=architecture))
                declarations[key].append(row)
    return dict(sorted(declarations.items()))


def family_for(module, names):
    if module not in MODULES:
        raise ValueError(f'Unreviewed module requires an explicit family policy: {module}')
    family = MODULES[module]
    if family == 'crt':
        for candidate, pattern in CRT_RULES:
            if any(re.search(pattern, name) for name in names):
                return candidate
    if family in ('system', 'security'):
        for candidate, pattern in EXPORT_RULES:
            if any(re.search(pattern, name) for name in names):
                return candidate
    return 'misc' if family == 'system' else family


def partition(inventory, max_contracts=32):
    if type(max_contracts) is not int or not 2 <= max_contracts <= 128:
        raise ValueError('Batch size must be an integer in 2..128')
    declarations = inventory_contracts(inventory)
    parent = {key: key for key in declarations}

    def find(key):
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    for row in inventory['entries']:
        aliases = [(row['module'], name, row['kind'], architecture)
                   for name in variants(row) for architecture in ('x86', 'x64')]
        anchor = find(aliases[0])
        for key in aliases[1:]:
            parent[find(key)] = anchor
    units = defaultdict(list)
    for key in declarations:
        units[find(key)].append(key)
    buckets = defaultdict(list)
    for keys in units.values():
        keys.sort()
        module, _, kind, _ = keys[0]
        names = [key[1] for key in keys if not key[1].startswith('#')]
        family = family_for(module, names)
        if len(keys) > max_contracts:
            raise ValueError(f'Alias/architecture group exceeds batch size; explicitly increase policy: {keys}')
        buckets[(family, module, kind)].append(keys)
    batches = []
    for (family, module, kind), groups in sorted(buckets.items()):
        chunks = [[]]
        for group in sorted(groups):
            if len(chunks[-1]) + len(group) > max_contracts:
                chunks.append([])
            chunks[-1].extend(group)
        state, dependencies, positive, negative = FAMILY_REQUIREMENTS[family]
        for keys in chunks:
            members = sorted(keys)
            batch_id = f'api:{family}:{module}:{kind}:{fingerprint(members)[:16]}'
            source_paths = sorted({row['source'] for key in members for row in declarations[key] if row.get('source')})
            batches.append({
                'id': batch_id, 'family': family, 'module': module, 'kind': kind,
                'contracts': [list(key) for key in members], 'legacy_sources': source_paths,
                'depends_on': ['M4-user-scheduling'], 'family_dependencies': dependencies,
                'shared_state': state,
                'oracle': DEFAULT_CONTROLS['oracle'],
                'guest_controls': [positive, DEFAULT_CONTROLS['guest_controls']],
                'negative_controls': [negative, DEFAULT_CONTROLS['negative_controls']],
                'next_action': f'Qualify {module} {family} {kind} contracts: {", ".join(sorted({key[1] for key in members}))}',
                'exit_tests': ['source-bound independent semantic evidence for every contract',
                               'architecture-specific submitted route and negative controls',
                               'no missing, stale, blocked or unreviewed member'],
            })
            if family == 'native-bridges':
                batches[-1]['depends_on'].append('M0-effective-baseline')
            if kind == 'data':
                batches[-1]['guest_controls'] = [
                    'Direct guest loads/stores prove address, size, alignment, mutability, accessor aliases and process/thread/module lifetime.',
                    'Read and mutate the same imported storage through each alias on both architectures; attach source-bound ownership and teardown evidence.',
                ]
                batches[-1]['negative_controls'] = [
                    'Reject out-of-bounds access, invalid writes, stale storage and cross-owner aliasing without corrupting canaries.',
                    DEFAULT_CONTROLS['negative_controls'],
                ]
    by_family = defaultdict(list)
    for batch in batches:
        by_family[batch['family']].append(batch)
    for batch in batches:
        for dependency in batch.pop('family_dependencies'):
            batch['depends_on'].extend(item['id'] for item in by_family[dependency])
        if batch['kind'] == 'function':
            batch['depends_on'].extend(item['id'] for item in by_family[batch['family']] if item['kind'] == 'data')
        batch['depends_on'] = sorted(set(batch['depends_on']))
    return {
        'schema': 1, 'inventory_fingerprint': fingerprint(inventory),
        'contract_count': len(declarations), 'max_contracts': max_contracts,
        'control_semantics': 'Required future qualification controls, not observations or equivalence claims.',
        'batches': batches,
    }


def validate_partition(document, rows, inventory_fingerprint=None, inventory=None):
    if document.get('schema') != 1:
        raise ValueError('Unknown API partition schema')
    if inventory_fingerprint is not None and document.get('inventory_fingerprint') != inventory_fingerprint:
        raise ValueError('API partition inventory fingerprint differs')
    expected = set(indexed(rows))
    assigned = {}
    batch_ids = set()
    for batch in document['batches']:
        if batch['id'] in batch_ids:
            raise ValueError('Duplicate API batch ID')
        batch_ids.add(batch['id'])
        for field in ('contracts', 'depends_on', 'shared_state', 'oracle', 'guest_controls', 'negative_controls', 'next_action', 'exit_tests'):
            if not batch.get(field):
                raise ValueError(f'API batch requires {field}')
        keys = []
        for member in batch['contracts']:
            if not isinstance(member, (list, tuple)) or len(member) != 4:
                raise ValueError('Malformed API batch contract identity')
            key = contract_key(dict(zip(('module', 'export', 'kind', 'architecture'), member)))
            if key in assigned:
                raise ValueError(f'Duplicate API batch assignment: {key}')
            assigned[key] = batch['id']
            keys.append(key)
        if len(keys) > document['max_contracts']:
            raise ValueError('API batch exceeds declared size policy')
        prefix = f'api:{batch["family"]}:{batch["module"]}:{batch["kind"]}:'
        if batch['id'] != prefix + fingerprint(sorted(keys))[:16]:
            raise ValueError('API batch ID does not bind its exact contracts')
        if any(key[0] != batch['module'] or key[2] != batch['kind'] for key in keys):
            raise ValueError('API batch mixes module or data/function ownership')
    if set(assigned) != expected or document['contract_count'] != len(expected):
        raise ValueError(f'API partition coverage differs: {len(expected - set(assigned))} missing, {len(set(assigned) - expected)} orphan')
    if inventory is not None and document != partition(inventory, document['max_contracts']):
        raise ValueError('API partition differs from reviewed alias, family, dependency or control policy')
    return assigned


def expand_worklist(worklist, document, rows):
    row_index = indexed(rows)
    validate_partition(document, rows)
    expanded = []
    for batch in worklist['batches']:
        if batch['id'] == 'M5-M7-model-families':
            continue
        item = dict(batch)
        item['depends_on'] = [dependency for dependency in batch['depends_on'] if dependency != 'M5-M7-model-families']
        if 'M5-M7-model-families' in batch['depends_on']:
            item['depends_on'].extend(batch['id'] for batch in document['batches'])
        expanded.append(item)
    for batch in document['batches']:
        members = [row_index[tuple(key)] for key in batch['contracts']]
        for row in members:
            validate_evidence(row)
        closed = all(row.get('semantic_status') in CLOSED_STATES
                     and row.get('submitted_route') in ('verified', 'not_applicable_with_proof')
                     and (row.get('status') != 'missing_binding' or row['semantic_status'] == 'not_applicable_with_proof')
                     for row in members)
        blocked = [row for row in members if row.get('semantic_status') == 'blocked']
        expanded.append({**batch, 'status': 'closed' if closed else 'blocked' if blocked else 'pending',
                         'blocker': [row.get('blocker') or list(contract_key(row)) for row in blocked] or None})
    return {**worklist, 'batches': expanded}


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, default=root / 'rust/api-parity/legacy-inventory.json')
    parser.add_argument('--output', type=Path, default=root / 'docs/native-pe/api-batches.json')
    parser.add_argument('--worklist', type=Path, default=root / 'docs/native-pe/worklist.json')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--refresh', action='store_true', help='Explicitly accept a reviewed partition/policy change.')
    args = parser.parse_args()
    try:
        inventory = json.loads(args.inventory.read_text(encoding='utf-8-sig'))
        document = partition(inventory)
        rows = [dict(zip(('module', 'export', 'kind', 'architecture'), key)) for key in inventory_contracts(inventory)]
        validate_partition(document, rows, fingerprint(inventory), inventory)
        worklist = json.loads(args.worklist.read_text(encoding='utf-8-sig'))
        validate_batch_graph(expand_worklist(worklist, document, rows))
    except (ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    if args.output.exists():
        previous = json.loads(args.output.read_text(encoding='utf-8-sig'))
        if previous != document and (args.check or not args.refresh):
            parser.error('Frozen API partition differs; review before --refresh')
    elif args.check:
        parser.error('Frozen API partition is missing')
    if not args.check:
        atomic_write(args.output, json.dumps(document, indent=2) + '\n')
    print(json.dumps({'contracts': document['contract_count'], 'batches': len(document['batches']),
                      'inventory_fingerprint': document['inventory_fingerprint'], 'checked': args.check}))


if __name__ == '__main__':
    main()
