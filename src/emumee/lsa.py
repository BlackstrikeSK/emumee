"""Bounded guest LSA connections and persona Kerberos cache metadata."""

from __future__ import annotations

import struct

import speakeasy.common as common
from .kerberos import ticket_cache_response


STATUS_SUCCESS = 0
STATUS_INVALID_HANDLE = 0xC0000008
STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_NO_SUCH_PACKAGE = 0xC00000FE
STATUS_NOT_SUPPORTED = 0xC00000BB
STATUS_PRIVILEGE_NOT_HELD = 0xC0000061
KERBEROS_PACKAGE = 0x1001


class GuestLSA:
    def __init__(self, persona: dict | None = None):
        self.tickets = persona["kerberos"]["tickets"] if persona is not None else []
        self.handles: set[tuple[int, int]] = set()
        self.buffers: dict[tuple[int, int], int] = {}
        self.next_handle = 0xE5100000
        self.unsupported: list[str] = []
        self.read_guard = None
        self.write_guard = None

    def install(self, emulator) -> None:
        for module in ('sspicli', 'secur32'):
            emulator.add_api_hook(self._connect, module, 'LsaConnectUntrusted', argc=1)
            emulator.add_api_hook(self._lookup, module, 'LsaLookupAuthenticationPackage', argc=3)
            emulator.add_api_hook(self._call, module, 'LsaCallAuthenticationPackage', argc=7)
            emulator.add_api_hook(self._free, module, 'LsaFreeReturnBuffer', argc=1)
            emulator.add_api_hook(self._close, module, 'LsaDeregisterLogonProcess', argc=1)

    def _owner(self, emu) -> int:
        process = emu.get_current_process()
        return id(process) if process is not None else 0

    def _access(self, emu, address: int, size: int, write: bool) -> bool:
        if not address or size <= 0:
            return False
        mapping = emu.get_address_map(address)
        permission = common.PERM_MEM_WRITE if write else common.PERM_MEM_READ
        if (mapping is None or mapping.free or
                address + size > int(mapping.base) + int(mapping.size) or
                not (int(mapping.prot) & permission)):
            return False
        guard = self.write_guard if write else self.read_guard
        return guard is None or bool(guard(emu, address, size))

    def _read(self, emu, address: int, size: int) -> bytes | None:
        if not self._access(emu, address, size, False):
            return None
        try:
            return emu.mem_read(address, size)
        except Exception:
            return None

    def _write(self, emu, address: int, data: bytes) -> bool:
        if not self._access(emu, address, len(data), True):
            return False
        try:
            emu.mem_write(address, data)
            return True
        except Exception:
            return False

    def _connect(self, emu, _api_name, _original, params) -> int:
        pointer = int(params[0])
        width = emu.get_ptr_size()
        owner = self._owner(emu)
        if (not owner or len(self.handles) >= 256 or
                not self._access(emu, pointer, width, True)):
            return STATUS_INVALID_PARAMETER
        handle = self.next_handle
        self.next_handle += 1
        if not self._write(emu, pointer, handle.to_bytes(width, 'little')):
            return STATUS_INVALID_PARAMETER
        self.handles.add((owner, handle))
        return STATUS_SUCCESS

    def _lookup(self, emu, _api_name, _original, params) -> int:
        handle, string_ptr, package_ptr = map(int, params)
        if (self._owner(emu), handle) not in self.handles:
            return STATUS_INVALID_HANDLE
        width = emu.get_ptr_size()
        header = self._read(emu, string_ptr, 8 if width == 4 else 16)
        if header is None or not self._access(emu, package_ptr, 4, True):
            return STATUS_INVALID_PARAMETER
        length, maximum = struct.unpack_from('<HH', header)
        buffer_ptr = int.from_bytes(header[4:8] if width == 4 else header[8:16], 'little')
        if length == 0 or length > 127 or maximum < length:
            return STATUS_INVALID_PARAMETER
        name = self._read(emu, buffer_ptr, length)
        if name is None:
            return STATUS_INVALID_PARAMETER
        if name.lower() != b'kerberos':
            return STATUS_NO_SUCH_PACKAGE
        return (STATUS_SUCCESS if self._write(emu, package_ptr,
                                             struct.pack('<I', KERBEROS_PACKAGE))
                else STATUS_INVALID_PARAMETER)

    def _call(self, emu, _api_name, _original, params) -> int:
        (handle, package, request_ptr, request_size, response_ptr,
         length_ptr, status_ptr) = map(int, params)
        if (self._owner(emu), handle) not in self.handles:
            return STATUS_INVALID_HANDLE
        width = emu.get_ptr_size()
        if (package != KERBEROS_PACKAGE or request_size < 12 or
                request_size > 65536 or
                not self._access(emu, response_ptr, width, True) or
                not self._access(emu, length_ptr, 4, True) or
                not self._access(emu, status_ptr, 4, True)):
            return STATUS_INVALID_PARAMETER
        request = self._read(emu, request_ptr, request_size)
        if request is None:
            return STATUS_INVALID_PARAMETER
        message = struct.unpack_from('<I', request)[0]
        logon_id = struct.unpack_from('<Q', request, 4)[0]
        protocol_status = STATUS_SUCCESS
        buffer = 0
        length = 0
        response = None
        if message == 1 and logon_id == 0:  # KerbQueryTicketCacheMessage
            response = ticket_cache_response(self.tickets, width, 0)
        elif message == 32:  # KerbQueryDomainExtendedPoliciesMessage
            domain_offset = 8
            domain_header = 16 if width == 8 else 8
            if (request_size >= domain_offset + domain_header and
                    struct.unpack_from('<I', request, 4)[0] == 0 and
                    request[domain_offset:domain_offset + domain_header] ==
                    b'\0' * domain_header):
                # Local, non-domain persona: DAC and claims are unavailable.
                response = struct.pack('<IIII', 32, 1, 0, 0)
            else:
                protocol_status = STATUS_NOT_SUPPORTED
                self.unsupported.append('Kerberos domain policy request is not modeled')
        elif message == 1:
            protocol_status = STATUS_PRIVILEGE_NOT_HELD
        else:
            protocol_status = STATUS_NOT_SUPPORTED
            self.unsupported.append(f'Kerberos protocol message {message} is not modeled')
        if response is not None:
            if len(self.buffers) >= 256:
                return STATUS_NOT_SUPPORTED
            process = emu.get_current_process()
            allocation_size = (len(response) + 0xfff) & ~0xfff
            try:
                buffer = emu.mem_map(allocation_size, perms=common.PERM_MEM_RW,
                                     tag='api.lsa.response', process=process)
                if message == 1:
                    response = ticket_cache_response(self.tickets, width, buffer)
                emu.mem_write(buffer, response)
            except Exception:
                if buffer:
                    emu.mem_free(buffer)
                return STATUS_INVALID_PARAMETER
            length = len(response)
            self.buffers[(self._owner(emu), buffer)] = allocation_size
        fields = ((response_ptr, buffer.to_bytes(width, 'little')),
                  (length_ptr, struct.pack('<I', length)),
                  (status_ptr, struct.pack('<I', protocol_status)))
        if not all(self._write(emu, ptr, data) for ptr, data in fields):
            if buffer:
                self.buffers.pop((self._owner(emu), buffer), None)
                emu.mem_free(buffer)
            return STATUS_INVALID_PARAMETER
        return STATUS_SUCCESS

    def _free(self, emu, _api_name, _original, params) -> int:
        pointer = int(params[0])
        if self.buffers.pop((self._owner(emu), pointer), None) is None:
            return STATUS_INVALID_PARAMETER
        try:
            emu.mem_free(pointer)
        except Exception:
            return STATUS_INVALID_PARAMETER
        return STATUS_SUCCESS

    def _close(self, emu, _api_name, _original, params) -> int:
        entry = (self._owner(emu), int(params[0]))
        if entry not in self.handles:
            return STATUS_INVALID_HANDLE
        self.handles.remove(entry)
        return STATUS_SUCCESS

    def cleanup_process(self, emu, process) -> None:
        owner = id(process)
        self.handles = {entry for entry in self.handles if entry[0] != owner}
        for entry in tuple(self.buffers):
            if entry[0] == owner:
                emu.mem_free(entry[1])
                self.buffers.pop(entry, None)
