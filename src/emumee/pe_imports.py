"""Equivalent import sentinel patching with one image copy instead of one per IAT slot."""

from contextlib import contextmanager
from threading import RLock

_parser_lock = RLock()


def patch_imports_once(parser):
    if not parser.imports:
        return
    if not parser.mapped_image:
        raise ValueError("PE image has not been mapped yet")
    image = bytearray(parser.mapped_image)
    for address, imported in parser.imports.items():
        offset = address - parser.base
        if offset < 0 or offset + parser.ptr_size > len(image):
            raise ValueError("Import slot lies outside mapped PE image")
        image[offset:offset + parser.ptr_size] = parser.imp_id.to_bytes(parser.ptr_size, "little")
        parser.import_table[parser.imp_id] = imported
        parser.imp_id += parser.imp_step
    parser.mapped_image = bytes(image)


@contextmanager
def batched_import_patching():
    # Each production worker analyzes one sample. Scope the pinned engine
    # compatibility patch to loading, and restore it for source-library users.
    from speakeasy.windows.common import _PeParser
    with _parser_lock:
        original = _PeParser._patch_imports
        _PeParser._patch_imports = patch_imports_once
        try:
            yield
        finally:
            _PeParser._patch_imports = original
