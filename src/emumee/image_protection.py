"""Coalesce adjacent loader protection requests without changing permissions."""


class ImageProtectionBatch:
    def __init__(self, protect):
        self.protect = protect
        self.pending = None
        self.requests = 0
        self.applied = 0
        self.error = None

    def add(self, address, size, permissions):
        self.requests += 1
        if self.pending is not None:
            start, length, previous = self.pending
            if start + length == address and previous == permissions:
                self.pending = start, length + size, permissions
                return
            self.flush()
        self.pending = address, size, permissions

    def flush(self):
        if self.error is not None:
            raise self.error
        if self.pending is not None:
            request = self.pending
            self.pending = None
            try:
                self.protect(*request)
            except Exception as exc:
                self.error = exc
                raise
            self.applied += 1
