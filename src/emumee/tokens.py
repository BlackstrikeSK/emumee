"""Guest token user SID data tied to the configured Windows persona."""

from __future__ import annotations

import struct

import speakeasy.common as common


ERROR_INVALID_HANDLE = 6
ERROR_INVALID_PARAMETER = 87
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NONE_MAPPED = 1332
ERROR_NO_SUCH_PRIVILEGE = 1313
TOKEN_USER = 1
TOKEN_GROUPS = 2
TOKEN_PRIVILEGES = 3
TOKEN_USER_CLAIMS = 33
TOKEN_DEVICE_CLAIMS = 34
SE_GROUP_MANDATORY = 1
SE_GROUP_ENABLED_BY_DEFAULT = 2
SE_GROUP_ENABLED = 4

PRIVILEGE_NAMES = {
    2: 'SeCreateTokenPrivilege', 3: 'SeAssignPrimaryTokenPrivilege',
    4: 'SeLockMemoryPrivilege', 5: 'SeIncreaseQuotaPrivilege',
    6: 'SeMachineAccountPrivilege', 7: 'SeTcbPrivilege',
    8: 'SeSecurityPrivilege', 9: 'SeTakeOwnershipPrivilege',
    10: 'SeLoadDriverPrivilege', 11: 'SeSystemProfilePrivilege',
    12: 'SeSystemtimePrivilege', 13: 'SeProfileSingleProcessPrivilege',
    14: 'SeIncreaseBasePriorityPrivilege', 15: 'SeCreatePagefilePrivilege',
    16: 'SeCreatePermanentPrivilege', 17: 'SeBackupPrivilege',
    18: 'SeRestorePrivilege', 19: 'SeShutdownPrivilege',
    20: 'SeDebugPrivilege', 21: 'SeAuditPrivilege',
    22: 'SeSystemEnvironmentPrivilege', 23: 'SeChangeNotifyPrivilege',
    24: 'SeRemoteShutdownPrivilege', 25: 'SeUndockPrivilege',
    26: 'SeSyncAgentPrivilege', 27: 'SeEnableDelegationPrivilege',
    28: 'SeManageVolumePrivilege', 29: 'SeImpersonatePrivilege',
    30: 'SeCreateGlobalPrivilege', 31: 'SeTrustedCredManAccessPrivilege',
    32: 'SeRelabelPrivilege', 33: 'SeIncreaseWorkingSetPrivilege',
    34: 'SeTimeZonePrivilege', 35: 'SeCreateSymbolicLinkPrivilege',
}

PRIVILEGE_DESCRIPTIONS = {
    5: 'Adjust memory quotas for a process',
    8: 'Manage auditing and security log',
    9: 'Take ownership of files or other objects',
    10: 'Load and unload device drivers',
    11: 'Profile system performance',
    12: 'Change the system time',
    13: 'Profile single process',
    14: 'Increase scheduling priority',
    15: 'Create a pagefile',
    17: 'Back up files and directories',
    18: 'Restore files and directories',
    19: 'Shut down the system',
    20: 'Debug programs',
    22: 'Modify firmware environment values',
    23: 'Bypass traverse checking',
    24: 'Force shutdown from a remote system',
    25: 'Remove computer from docking station',
    28: 'Perform volume maintenance tasks',
    29: 'Impersonate a client after authentication',
    30: 'Create global objects',
    33: 'Increase a process working set',
    34: 'Change the time zone',
    35: 'Create symbolic links',
}


def encode_sid(value: str) -> bytes:
    parts = value.split('-')
    if (len(parts) < 4 or parts[0] != 'S' or parts[1] != '1' or
            len(parts) > 18):
        raise ValueError('Invalid persona SID')
    authority = int(parts[2])
    subs = [int(part) for part in parts[3:]]
    if not 0 <= authority < 1 << 48 or any(not 0 <= sub < 1 << 32 for sub in subs):
        raise ValueError('Invalid persona SID')
    return (bytes((1, len(subs))) + authority.to_bytes(6, 'big') +
            b''.join(struct.pack('<I', sub) for sub in subs))


class GuestTokens:
    def __init__(self, persona: dict):
        self.persona = persona
        self.sid = encode_sid(persona['user_sid'])
        groups = ['S-1-1-0', 'S-1-5-11', 'S-1-5-4', 'S-1-5-32-545']
        if persona['user_is_admin']:
            groups.append('S-1-5-32-544')
        self.groups = [encode_sid(value) for value in groups]
        self.sid_names = {
            self.sid: (persona['user_name'], persona['hostname'], 1),
            encode_sid('S-1-1-0'): ('Everyone', '', 5),
            encode_sid('S-1-5-11'): ('Authenticated Users', 'NT AUTHORITY', 5),
            encode_sid('S-1-5-4'): ('INTERACTIVE', 'NT AUTHORITY', 5),
            encode_sid('S-1-5-32-545'): ('Users', 'BUILTIN', 4),
            encode_sid('S-1-5-32-544'): ('Administrators', 'BUILTIN', 4),
        }
        default_privileges = {19: 0, 23: 3, 25: 0, 33: 0, 34: 0}
        if persona['user_is_admin']:
            default_privileges.update({
                5: 0, 8: 0, 9: 0, 10: 0, 11: 0, 12: 0, 13: 0,
                14: 0, 15: 0, 17: 0, 18: 0, 20: 0, 22: 0,
                24: 0, 28: 0, 29: 3, 30: 3, 35: 0,
            })
        self.privileges = sorted(default_privileges.items())
        self.read_guard = None
        self.write_guard = None

    def install(self, emulator) -> None:
        emulator.add_api_hook(self._token_info, 'advapi32',
                              'GetTokenInformation', argc=5)
        emulator.add_api_hook(self._length_sid, 'advapi32',
                              'GetLengthSid', argc=1)
        emulator.add_api_hook(self._valid_sid, 'advapi32',
                              'IsValidSid', argc=1)
        emulator.add_api_hook(self._copy_sid, 'advapi32',
                              'CopySid', argc=3)
        emulator.add_api_hook(self._initialize_sid, 'advapi32',
                              'InitializeSid', argc=3)
        for suffix in ('A', 'W'):
            emulator.add_api_hook(self._lookup_sid, 'advapi32',
                                  'LookupAccountSid' + suffix, argc=7)
            emulator.add_api_hook(self._lookup_privilege_name, 'advapi32',
                                  'LookupPrivilegeName' + suffix, argc=4)
            emulator.add_api_hook(self._lookup_privilege_display_name, 'advapi32',
                                  'LookupPrivilegeDisplayName' + suffix, argc=5)
            emulator.add_api_hook(self._lookup_privilege_value, 'advapi32',
                                  'LookupPrivilegeValue' + suffix, argc=3)

    def _read_guest_string(self, emu, address: int, wide: bool) -> str | None:
        width = 2 if wide else 1
        if not address:
            return None
        data = bytearray()
        for offset in range(256):
            if not self._access(emu, address + offset * width, width, 'read'):
                return None
            try:
                char = emu.mem_read(address + offset * width, width)
            except Exception:
                return None
            if char == b'\0' * width:
                try:
                    return data.decode('utf-16le' if wide else 'cp1252')
                except UnicodeError:
                    return None
            data.extend(char)
        return None

    def _write_privilege_text(self, emu, api_name: str, value: str,
                              output: int, size_ptr: int) -> int:
        wide = api_name.endswith('W')
        encoding = 'utf-16le' if wide else 'cp1252'
        data = (value + '\0').encode(encoding, errors='replace')
        unit = 2 if wide else 1
        required = len(data) // unit
        if (not self._access(emu, size_ptr, 4, 'read') or
                not self._access(emu, size_ptr, 4, 'write')):
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        try:
            capacity = struct.unpack('<I', emu.mem_read(size_ptr, 4))[0]
            if capacity < required:
                emu.mem_write(size_ptr, struct.pack('<I', required))
                emu.set_last_error(ERROR_INSUFFICIENT_BUFFER)
                return 0
            if not self._access(emu, output, len(data), 'write'):
                emu.set_last_error(ERROR_INVALID_PARAMETER)
                return 0
            emu.mem_write(output, data)
            emu.mem_write(size_ptr, struct.pack('<I', required - 1))
        except Exception:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        emu.set_last_error(0)
        return 1

    def _lookup_privilege_name(self, emu, api_name, _original, params) -> int:
        system, luid_ptr, output, size_ptr = map(int, params)
        if system or not self._access(emu, luid_ptr, 8, 'read'):
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        try:
            low, high = struct.unpack('<II', emu.mem_read(luid_ptr, 8))
        except Exception:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        name = PRIVILEGE_NAMES.get(low) if high == 0 else None
        if name is None:
            emu.set_last_error(ERROR_NO_SUCH_PRIVILEGE)
            return 0
        return self._write_privilege_text(emu, api_name, name, output, size_ptr)

    def _lookup_privilege_display_name(self, emu, api_name, _original, params) -> int:
        system, name_ptr, output, size_ptr, language_ptr = map(int, params)
        if system or not self._access(emu, language_ptr, 4, 'write'):
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        name = self._read_guest_string(emu, name_ptr, api_name.endswith('W'))
        luid = next((key for key, value in PRIVILEGE_NAMES.items()
                     if value.casefold() == name.casefold()), None) if name else None
        if luid is None:
            emu.set_last_error(ERROR_NO_SUCH_PRIVILEGE)
            return 0
        description = PRIVILEGE_DESCRIPTIONS.get(luid, name)
        result = self._write_privilege_text(emu, api_name, description,
                                            output, size_ptr)
        if result:
            try:
                emu.mem_write(language_ptr, struct.pack('<I', 0x0409))
            except Exception:
                emu.set_last_error(ERROR_INVALID_PARAMETER)
                return 0
        return result

    def _lookup_privilege_value(self, emu, api_name, _original, params) -> int:
        system, name_ptr, luid_ptr = map(int, params)
        if system or not self._access(emu, luid_ptr, 8, 'write'):
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        name = self._read_guest_string(emu, name_ptr, api_name.endswith('W'))
        luid = next((key for key, value in PRIVILEGE_NAMES.items()
                     if value.casefold() == name.casefold()), None) if name else None
        if luid is None:
            emu.set_last_error(ERROR_NO_SUCH_PRIVILEGE)
            return 0
        try:
            emu.mem_write(luid_ptr, struct.pack('<II', luid, 0))
        except Exception:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        emu.set_last_error(0)
        return 1

    def _access(self, emu, address: int, size: int, mode: str) -> bool:
        if not address or size <= 0:
            return False
        mapping = emu.get_address_map(address)
        permission = (common.PERM_MEM_READ if mode == 'read' else
                      common.PERM_MEM_WRITE)
        if (mapping is None or mapping.free or
                address + size > int(mapping.base) + int(mapping.size) or
                not (int(mapping.prot) & permission)):
            return False
        guard = self.read_guard if mode == 'read' else self.write_guard
        return guard is None or bool(guard(emu, address, size))

    def _token_info(self, emu, api_name, original, params) -> int:
        handle, info_class, output, capacity, required_ptr = map(int, params)
        if info_class not in (TOKEN_USER, TOKEN_GROUPS, TOKEN_PRIVILEGES,
                              TOKEN_USER_CLAIMS, TOKEN_DEVICE_CLAIMS):
            return original(params)
        process = emu.get_current_process()
        token = getattr(process, 'token', None)
        if token is None or handle not in getattr(token, 'handles', ()):
            emu.set_last_error(ERROR_INVALID_HANDLE)
            return 0
        width = emu.get_ptr_size()
        if info_class == TOKEN_USER:
            header_size = width + (8 if width == 8 else 4)
            required = header_size + len(self.sid)
        elif info_class == TOKEN_GROUPS:
            header_size = 8 if width == 8 else 4
            entry_size = 16 if width == 8 else 8
            required = (header_size + len(self.groups) * entry_size +
                        sum(len(group) for group in self.groups))
        elif info_class == TOKEN_PRIVILEGES:
            required = 4 + len(self.privileges) * 12
        else:
            required = 8 + width
        if not self._access(emu, required_ptr, 4, 'write'):
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        try:
            emu.mem_write(required_ptr, struct.pack('<I', required))
        except Exception:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        if capacity < required:
            emu.set_last_error(ERROR_INSUFFICIENT_BUFFER)
            return 0
        if not self._access(emu, output, required, 'write'):
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        payload = bytearray(required)
        attributes = (SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT |
                      SE_GROUP_ENABLED)
        if info_class == TOKEN_USER:
            payload[:width] = (output + header_size).to_bytes(width, 'little')
            struct.pack_into('<I', payload, width, attributes)
            payload[header_size:] = self.sid
        elif info_class == TOKEN_GROUPS:
            struct.pack_into('<I', payload, 0, len(self.groups))
            cursor = header_size + len(self.groups) * entry_size
            for index, group in enumerate(self.groups):
                row = header_size + index * entry_size
                payload[row:row + width] = (output + cursor).to_bytes(width, 'little')
                struct.pack_into('<I', payload, row + width, attributes)
                payload[cursor:cursor + len(group)] = group
                cursor += len(group)
        elif info_class == TOKEN_PRIVILEGES:
            struct.pack_into('<I', payload, 0, len(self.privileges))
            for index, (luid, flags) in enumerate(self.privileges):
                struct.pack_into('<III', payload, 4 + index * 12,
                                 luid, 0, flags)
        else:
            struct.pack_into('<H', payload, 0, 1)  # claim structure version V1
        try:
            emu.mem_write(output, bytes(payload))
        except Exception:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        emu.set_last_error(0)
        return 1

    def _sid_size(self, emu, address: int) -> int:
        if not self._access(emu, address, 8, 'read'):
            return 0
        try:
            header = emu.mem_read(address, 8)
        except Exception:
            return 0
        if header[0] != 1 or header[1] > 15:
            return 0
        size = 8 + 4 * header[1]
        return size if self._access(emu, address, size, 'read') else 0

    def _valid_sid(self, emu, api_name, _original, params) -> int:
        return int(self._sid_size(emu, int(params[0])) > 0)

    def _length_sid(self, emu, api_name, _original, params) -> int:
        return self._sid_size(emu, int(params[0]))

    def _copy_sid(self, emu, api_name, _original, params) -> int:
        capacity, output, source = map(int, params)
        length = self._sid_size(emu, source)
        if not length:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        if capacity < length:
            emu.set_last_error(ERROR_INSUFFICIENT_BUFFER)
            return 0
        if not self._access(emu, output, length, 'write'):
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        try:
            emu.mem_write(output, emu.mem_read(source, length))
        except Exception:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        emu.set_last_error(0)
        return 1

    def _initialize_sid(self, emu, api_name, _original, params) -> int:
        destination, authority_ptr, count = map(int, params)
        if count < 0 or count > 15:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        try:
            authority = (emu.mem_read(authority_ptr, 6)
                         if self._access(emu, authority_ptr, 6, 'read') else None)
        except Exception:
            authority = None
        size = 8 + count * 4
        if authority is None or not self._access(emu, destination, size, 'write'):
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        try:
            emu.mem_write(destination, bytes((1, count)) + authority +
                          b'\0' * (4 * count))
        except Exception:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        emu.set_last_error(0)
        return 1

    def _lookup_sid(self, emu, api_name, _original, params) -> int:
        system, sid_ptr, name_ptr, name_size_ptr, domain_ptr, domain_size_ptr, use_ptr = map(int, params)
        if system:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        sid_length = self._sid_size(emu, sid_ptr)
        if not sid_length:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        try:
            identity = self.sid_names.get(emu.mem_read(sid_ptr, sid_length))
        except Exception:
            identity = None
        if identity is None:
            emu.set_last_error(ERROR_NONE_MAPPED)
            return 0
        if (not self._access(emu, name_size_ptr, 4, 'read') or
                not self._access(emu, name_size_ptr, 4, 'write') or
                not self._access(emu, domain_size_ptr, 4, 'read') or
                not self._access(emu, domain_size_ptr, 4, 'write')):
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        name, domain, sid_use = identity
        encoding = 'utf-16le' if api_name.endswith('W') else 'cp1252'
        width = 2 if api_name.endswith('W') else 1
        name_bytes = (name + '\0').encode(encoding, errors='replace')
        domain_bytes = (domain + '\0').encode(encoding, errors='replace')
        name_required = len(name_bytes) // width
        domain_required = len(domain_bytes) // width
        try:
            name_capacity = struct.unpack('<I', emu.mem_read(name_size_ptr, 4))[0]
            domain_capacity = struct.unpack('<I', emu.mem_read(domain_size_ptr, 4))[0]
            if name_capacity < name_required or domain_capacity < domain_required:
                emu.mem_write(name_size_ptr, struct.pack('<I', name_required))
                emu.mem_write(domain_size_ptr, struct.pack('<I', domain_required))
                emu.set_last_error(ERROR_INSUFFICIENT_BUFFER)
                return 0
            if (not self._access(emu, name_ptr, len(name_bytes), 'write') or
                    not self._access(emu, domain_ptr, len(domain_bytes), 'write') or
                    not self._access(emu, use_ptr, 4, 'write')):
                emu.set_last_error(ERROR_INVALID_PARAMETER)
                return 0
            emu.mem_write(name_ptr, name_bytes)
            emu.mem_write(domain_ptr, domain_bytes)
            emu.mem_write(name_size_ptr, struct.pack('<I', name_required - 1))
            emu.mem_write(domain_size_ptr, struct.pack('<I', domain_required - 1))
            emu.mem_write(use_ptr, struct.pack('<I', sid_use))
        except Exception:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        emu.set_last_error(0)
        return 1
