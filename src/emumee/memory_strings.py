"""Bounded indicator capture from guest memory and interpreted managed strings."""

from __future__ import annotations

import ipaddress
import json
import re
import time
from urllib.parse import urlsplit

from .artifacts import MAX_MEMORY_SCAN

MAX_MATCHES = 1000
MAX_VALUE_CHARS = 1024
MAX_CAPTURE_BYTES = 1024 * 1024
MAX_PATTERNS = 16
MAX_PATTERN_CHARS = 1024
WINDOW_CHARS = 8192
REGEX_TIMEOUT = 0.025
REGEX_BUDGET = 2.0
ASCII = re.compile(rb"[\x20-\x7e]{2,}")
WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){2,}")
IPV4 = re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])")
IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]*(?:%[\w.-]+)?(?![\w:])")
URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`]+", re.IGNORECASE)


def validate_options(value=None) -> dict:
    if value is None:
        return {"enabled": True, "regex": []}
    if (not isinstance(value, dict) or set(value) - {"enabled", "regex"} or
            type(value.get("enabled", True)) is not bool):
        raise ValueError("Invalid memory string capture options")
    patterns = value.get("regex", [])
    if (not isinstance(patterns, list) or len(patterns) > MAX_PATTERNS or
            any(not isinstance(p, str) or not 0 < len(p) <= MAX_PATTERN_CHARS
                for p in patterns)):
        raise ValueError("Memory string capture accepts up to 16 nonempty regexes of 1024 characters")
    if patterns:
        import regex
        for index, pattern in enumerate(patterns):
            try:
                regex.compile(pattern)
            except (regex.error, RecursionError, OverflowError) as exc:
                raise ValueError(f"Invalid memory string regex {index + 1}: {exc}") from exc
    return {"enabled": value.get("enabled", True), "regex": list(patterns)}


class MemoryStringCapture:
    def __init__(self, options=None):
        self.options = validate_options(options)
        if self.options["regex"]:
            import regex
            self.patterns = [regex.compile(p) for p in self.options["regex"]]
        else:
            self.patterns = []
        self.matches: list[dict] = []
        self.match_bytes = 0
        self.seen: set[tuple] = set()
        self.scanned_bytes = 0
        self.limits: set[str] = set()
        self.regex_seconds = 0.0
        self.disabled_patterns: set[int] = set()

    @property
    def active(self):
        return (self.options["enabled"] and len(self.matches) < MAX_MATCHES
                and "match_byte_limit" not in self.limits)

    def _retain(self, kind, value, source, encoding, offset, base):
        if not value:
            return
        if len(value) > MAX_VALUE_CHARS:
            self.limits.add("match_length_limit")
            return
        address = hex(base + offset) if base is not None else None
        key = (kind, value, source, encoding, offset, address)
        if key in self.seen:
            return
        if len(self.matches) >= MAX_MATCHES:
            self.limits.add("match_limit")
            return
        item = {"format": kind, "value": value, "source": source[:256],
                "encoding": encoding, "offset": offset, "address": address}
        size = len(json.dumps(item, ensure_ascii=True))
        if self.match_bytes + size > MAX_CAPTURE_BYTES:
            self.limits.add("match_byte_limit")
            return
        self.match_bytes += size
        self.seen.add(key)
        self.matches.append(item)
        if len(self.matches) == MAX_MATCHES:
            self.limits.add("match_limit")

    def _text(self, text, source, encoding, offset=0, base=None, width=1,
              continued=False, final_text=True):
        # Overlap preserves matches of up to MAX_VALUE_CHARS at window edges.
        step = WINDOW_CHARS - MAX_VALUE_CHARS
        for start in range(0, len(text), step):
            if not self.active:
                break
            window = text[start:start + WINDOW_CHARS]
            last_window = start + WINDOW_CHARS >= len(text)
            final = final_text and last_window

            def retain(kind, match, value=None):
                # A match touching a nonfinal edge may be a partial token.
                if not final and match.end() == len(window):
                    if len(match.group()) > MAX_VALUE_CHARS:
                        self.limits.add("match_length_limit")
                    return
                if (start or continued) and match.start() == 0:
                    return
                self._retain(kind, match.group() if value is None else value,
                             source, encoding, offset + (start + match.start()) * width, base)

            for pattern in (IPV4, IPV6):
                for match in pattern.finditer(window):
                    try:
                        address = ipaddress.ip_address(match.group())
                    except ValueError:
                        continue
                    retain(f"ipv{address.version}", match)
            for match in URL.finditer(window):
                value = match.group().rstrip(".,;!?")
                for opening, closing in (("(", ")"), ("[", "]"), ("{", "}")):
                    while value.endswith(closing) and value.count(closing) > value.count(opening):
                        value = value[:-1]
                try:
                    if not urlsplit(value).hostname:
                        continue
                except ValueError:
                    continue
                retain("url", match, value)
            for index, pattern in enumerate(self.patterns):
                if index in self.disabled_patterns:
                    continue
                remaining = REGEX_BUDGET - self.regex_seconds
                if remaining <= 0:
                    self.limits.add("regex_time_budget")
                    break
                started = time.monotonic()
                try:
                    for match in pattern.finditer(window, timeout=min(REGEX_TIMEOUT, remaining)):
                        retain(f"custom_{index + 1}", match)
                        if not self.active:
                            break
                except TimeoutError:
                    self.disabled_patterns.add(index)
                    self.limits.add(f"regex_{index + 1}_timeout")
                finally:
                    self.regex_seconds += time.monotonic() - started
            if last_window:
                break

    def scan_memory(self, blob: bytes, source: str, base: int):
        if not self.active:
            return
        remaining = max(0, MAX_MEMORY_SCAN - self.scanned_bytes)
        if len(blob) > remaining:
            self.limits.add("scan_byte_limit")
        blob = blob[:remaining]
        self.scanned_bytes += len(blob)
        for pattern, encoding, width in ((ASCII, "ascii", 1), (WIDE, "utf-16le", 2)):
            for match in pattern.finditer(blob):
                if not self.active:
                    return
                # Decode windows, rather than a potentially enormous string.
                stride = (WINDOW_CHARS - MAX_VALUE_CHARS) * width
                for at in range(match.start(), match.end(), stride):
                    end = min(match.end(), at + WINDOW_CHARS * width)
                    text = blob[at:end].decode(encoding)
                    self._text(text, source, encoding, at, base, width,
                               continued=at > match.start(), final_text=end == match.end())
                    if end == match.end() or not self.active:
                        break

    def scan_string(self, value: str, source: str):
        if not self.active:
            return
        remaining = max(0, MAX_MEMORY_SCAN - self.scanned_bytes) // 2
        if len(value) > remaining:
            self.limits.add("scan_byte_limit")
        value = value[:remaining]
        self.scanned_bytes += len(value) * 2
        self._text(value, source, "managed")

    def report(self):
        return {"enabled": self.options["enabled"], "regex": self.options["regex"],
                "matches": self.matches, "scanned_bytes": self.scanned_bytes,
                "truncated": bool(self.limits), "limits": sorted(self.limits)}


def valid_capture(value) -> bool:
    """Validate bounded worker output before rendering it in the dashboard."""
    if (not isinstance(value, dict) or type(value.get("enabled")) is not bool or
            type(value.get("truncated")) is not bool or
            type(value.get("scanned_bytes")) is not int or
            not 0 <= value["scanned_bytes"] <= MAX_MEMORY_SCAN):
        return False
    patterns, matches, limits = (value.get(key) for key in ("regex", "matches", "limits"))
    if (not isinstance(patterns, list) or len(patterns) > MAX_PATTERNS or
            any(not isinstance(p, str) or not 0 < len(p) <= MAX_PATTERN_CHARS for p in patterns) or
            not isinstance(matches, list) or len(matches) > MAX_MATCHES or
            not isinstance(limits, list) or len(limits) > MAX_PATTERNS + 5 or
            any(not isinstance(item, str) or len(item) > 64 for item in limits)):
        return False
    formats = {"ipv4", "ipv6", "url"} | {f"custom_{i + 1}" for i in range(len(patterns))}
    match_bytes = 0
    for item in matches:
        if (not isinstance(item, dict) or set(item) != {"format", "encoding", "value", "source", "offset", "address"} or
                not isinstance(item.get("format"), str) or item["format"] not in formats or
                not isinstance(item.get("encoding"), str) or item["encoding"] not in {"ascii", "utf-16le", "managed"} or
                not isinstance(item.get("value"), str) or not 0 < len(item["value"]) <= MAX_VALUE_CHARS or
                not isinstance(item.get("source"), str) or len(item["source"]) > 256 or
                type(item.get("offset")) is not int or not 0 <= item["offset"] <= (1 << 64) - 1):
            return False
        address = item.get("address")
        if address is not None and (not isinstance(address, str) or
                                    not re.fullmatch(r"0x[0-9a-f]{1,16}", address)):
            return False
        match_bytes += len(json.dumps(item, ensure_ascii=True))
        if match_bytes > MAX_CAPTURE_BYTES:
            return False
    return True
