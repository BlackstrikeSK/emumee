"""Guest Kerberos cache metadata shared by LSA and enumeration utilities."""

import datetime as dt
import struct


ENCRYPTION_TYPES = {17: "AES-128-CTS-HMAC-SHA1-96",
                    18: "AES-256-CTS-HMAC-SHA1-96",
                    23: "RC4-HMAC"}


def ticket_datetime(value: str) -> dt.datetime:
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def ticket_filetime(value: str) -> int:
    delta = ticket_datetime(value) - dt.datetime(1601, 1, 1)
    return (delta.days * 86400 + delta.seconds) * 10_000_000


def ticket_cache_response(tickets: list[dict], width: int, base: int) -> bytes:
    """Pack KERB_QUERY_TKT_CACHE_RESPONSE with in-buffer UNICODE_STRING data."""
    record_size, string_size = (64, 16) if width == 8 else (48, 8)
    data = bytearray(8 + record_size * len(tickets))
    struct.pack_into("<II", data, 0, 1, len(tickets))
    for index, ticket in enumerate(tickets):
        record = 8 + index * record_size
        for offset, field in ((0, "server"), (string_size, "realm")):
            encoded = ticket[field].encode("utf-16le")
            pointer = base + len(data)
            struct.pack_into("<HH", data, record + offset, len(encoded), len(encoded) + 2)
            struct.pack_into("<Q" if width == 8 else "<I", data,
                             record + offset + (8 if width == 8 else 4), pointer)
            data.extend(encoded + b"\0\0")
        struct.pack_into("<qqqiI", data, record + 2 * string_size,
                         ticket_filetime(ticket["start_utc"]),
                         ticket_filetime(ticket["end_utc"]),
                         ticket_filetime(ticket["renew_utc"]),
                         ticket["encryption_type"], ticket["flags"])
    return bytes(data)
