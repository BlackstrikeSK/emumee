"""Small instruction-page cache; every guest/host image write invalidates it."""

from collections import OrderedDict


class InstructionCache:
    def __init__(self, read, pages=256):
        self.read = read
        self.limit = pages
        self.pages = OrderedDict()
        self.hits = 0
        self.misses = 0
        self.decoded = {}
        self.last_decoded_page = None
        self.last_decoded = None

    def invalidate(self, address, size):
        if size <= 0:
            return
        stop = address + size
        first, last = address & ~4095, (stop - 1) & ~4095
        if self.last_decoded_page is not None and first <= self.last_decoded_page <= last:
            self.last_decoded_page = self.last_decoded = None
        if (last - first) // 4096 + 1 <= len(self.pages):
            for page in range(first, last + 4096, 4096):
                self.pages.pop(page, None)
                self.decoded.pop(page, None)
        else:
            for page in tuple(self.pages):
                if page < stop and page + 4096 > address:
                    del self.pages[page]
                    self.decoded.pop(page, None)

    def instruction_info(self, address, size, width):
        """Cache immutable instruction bytes and the driver's hook predicates.

        Cross-page instructions always use the original read path, so a write
        to either page cannot leave behind a stale decoded instruction.
        """
        page, offset = address & ~4095, address & 4095
        key = (offset << 5) | size | (16 if width == 8 else 0)
        if 1 <= size <= 15 and offset + size <= 4096:
            entries = self.last_decoded if page == self.last_decoded_page else self.decoded.get(page)
            if entries is not None:
                info = entries.get(key)
                if info is not None:
                    self.hits += 1
                    if page != self.last_decoded_page:
                        self.pages.move_to_end(page)
                        self.last_decoded_page, self.last_decoded = page, entries
                    return info
        code = self.instruction(address, size)
        info = code, self.instruction_flags(code, width)
        if offset + size <= 4096:
            entries = self.decoded.setdefault(page, {})
            entries[key] = info
            self.last_decoded_page, self.last_decoded = page, entries
        return info

    @staticmethod
    def instruction_flags(code, width):
        size = len(code)
        prefix = code[:3]
        opcode = prefix[1:] if prefix and 0x40 <= prefix[0] <= 0x4F and width == 8 else prefix
        flags = int(prefix[:1] in (b'\x64', b'\x65') or opcode[:1] == b'\x8c' or opcode[:2] in
                    (b'\x0f\x01', b'\x0f\x20', b'\x0f\x21', b'\x0f\x22', b'\x0f\x23', b'\x0f\x30', b'\x0f\x32', b'\x0f\xa2'))
        flags |= 2 if code[-2:] in (b'\x0f\x05', b'\x0f\x07', b'\x0f\x34', b'\x0f\x35') else 0
        flags |= 4 if size == 4 and width == 8 and code[0] & 0xF4 == 0x44 and code[1:3] in (b'\x0f\x20', b'\x0f\x22') and code[3] & 0xF8 == 0xC0 else 0
        flags |= 8 if code in (b'\x0f\x31', b'\x0f\x01\xf9', b'\x0f\x01\xd0', b'\xc5\xf8\x77', b'\xc4\xe1\x78\x77') else 0
        return flags

    def instruction(self, address, size):
        if not 1 <= size <= 15:
            raise ValueError("Invalid x86 instruction length")
        output = []
        while size:
            page, offset = address & ~4095, address & 4095
            data = self.pages.get(page)
            if data is None:
                data = bytes(self.read(page, 4096))
                self.pages[page] = data
                self.misses += 1
                if len(self.pages) > self.limit:
                    evicted, _ = self.pages.popitem(last=False)
                    self.decoded.pop(evicted, None)
                    if evicted == self.last_decoded_page:
                        self.last_decoded_page = self.last_decoded = None
            else:
                self.pages.move_to_end(page)
                self.hits += 1
            count = min(size, 4096 - offset)
            output.append(data[offset:offset + count])
            address += count
            size -= count
        return b"".join(output)
