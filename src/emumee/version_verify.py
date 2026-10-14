"""Bounded guest-only Windows version comparison helpers."""

from __future__ import annotations

import struct


STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_REVISION_MISMATCH = 0xC0000059
ERROR_OLD_WIN_VERSION = 1150

_FIELDS = {
    0x01: (8, "I"),    # minor version
    0x02: (4, "I"),    # major version
    0x04: (12, "I"),   # build number
    0x08: (16, "I"),   # platform ID
    0x10: ("sp_minor", "H"),
    0x20: ("sp_major", "H"),
    0x40: ("suite", "H"),
    0x80: ("product", "B"),
}


def set_condition(mask: int, type_mask: int, condition: int) -> int:
    """Match VerSetConditionMask's bit placement and high-bit marker."""
    type_mask &= 0xFFFFFFFF
    if not type_mask:
        return mask & 0xFFFFFFFFFFFFFFFF
    bit_index = type_mask.bit_length() - 1
    shift = bit_index * 3
    if shift > 60:
        return mask & 0xFFFFFFFFFFFFFFFF
    return (mask | (1 << 63) | ((condition & 7) << shift)) & 0xFFFFFFFFFFFFFFFF


def read_request(emu, pointer: int, *, wide: bool) -> dict[int, int] | None:
    """Read only the fixed OSVERSIONINFOEXA/W structure from guest memory."""
    size = 284 if wide else 156
    if not pointer or struct.unpack("<I", emu.mem_read(pointer, 4))[0] != size:
        return None
    data = emu.mem_read(pointer, size)
    offsets = ({"sp_minor": 278, "sp_major": 276, "suite": 280,
                "product": 282} if wide else
               {"sp_minor": 150, "sp_major": 148, "suite": 152,
                "product": 154})
    return {bit: struct.unpack_from("<" + fmt, data,
                                    offsets[offset] if isinstance(offset, str)
                                    else offset)[0]
            for bit, (offset, fmt) in _FIELDS.items()}


def matches_version(request: dict[int, int], actual: dict[int, int],
                    type_mask: int, condition_mask: int) -> bool | None:
    """Compare selected fields; None means an invalid condition request."""
    if not type_mask or type_mask & ~0xFF:
        return None
    operators = {bit: (condition_mask >> ((bit.bit_length() - 1) * 3)) & 7
                 for bit in _FIELDS if type_mask & bit}
    for bit, operation in operators.items():
        if operation not in ((6, 7) if bit == 0x40 else (1, 2, 3, 4, 5)):
            return None

    # Windows compares the version tuple hierarchically. A strictly greater
    # major/minor/SP component settles the selected comparison; equal values
    # continue to the next selected component.
    ordered = [bit for bit in (0x02, 0x01, 0x20, 0x10) if type_mask & bit]
    for index, bit in enumerate(ordered):
        left, right, operation = actual[bit], request[bit], operators[bit]
        if left != right:
            if not _compare(left, right, operation):
                return False
            break
        if index == len(ordered) - 1 and operation in (2, 4):
            return False

    for bit, operation in operators.items():
        if bit in ordered:
            continue
        left, right = actual[bit], request[bit]
        if bit == 0x40:
            valid = ((left & right) == right if operation == 6 else
                     bool(left & right))
        else:
            valid = _compare(left, right, operation)
        if not valid:
            return False
    return True


def _compare(left: int, right: int, operation: int) -> bool:
    return {1: left == right, 2: left > right, 3: left >= right,
            4: left < right, 5: left <= right}[operation]


def actual_version(major: int, minor: int, build: int) -> dict[int, int]:
    return {0x01: minor, 0x02: major, 0x04: build, 0x08: 2,
            0x10: 0, 0x20: 0, 0x40: 0, 0x80: 1}
