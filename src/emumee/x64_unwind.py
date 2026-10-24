"""Bounded x64 runtime-function stack walks over guest bytes only.

Based on Microsoft's x64 exception-handling/unwind-code specification. The
walker does not change CPU state or pretend an unhandled exception was caught.
"""

import struct
from unicorn import x86_const as ux

REGISTERS = ("RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
             "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")


def runtime_function(kernel, pc):
    module = kernel.get_mod_from_addr(pc)
    if module is None:
        return None
    parser = getattr(getattr(module._image, "loader", None), "_pe_obj", None)
    if parser is None or len(parser.OPTIONAL_HEADER.DATA_DIRECTORY) < 4:
        return None
    directory = parser.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    rva, size = int(directory.VirtualAddress), int(directory.Size)
    if not rva or not size:
        return None
    if size % 12 or size > 12 * 65536 or rva + size > module.image_size:
        raise ValueError("Invalid or oversized x64 runtime-function directory")
    relative = pc - module.base
    low, high = 0, size // 12
    while low < high:
        middle = (low + high) // 2
        begin, end, unwind = struct.unpack("<III", kernel.mem_read(module.base + rva + middle * 12, 12))
        if not begin < end <= module.image_size or unwind >= module.image_size:
            raise ValueError("Invalid x64 runtime-function bounds")
        if relative < begin:
            high = middle
        elif relative >= end:
            low = middle + 1
        else:
            return module, (begin, end, unwind)
    return None


def walk_exception_frames(kernel):
    engine = kernel.emu_eng.emu
    registers = [int(engine.reg_read(getattr(ux, "UC_X86_REG_" + name))) for name in REGISTERS]
    pc = int(engine.reg_read(ux.UC_X86_REG_RIP))
    mapping = kernel.get_address_map(registers[4])
    frames = []
    stack_tag = str(mapping.tag) if mapping is not None else ""
    if mapping is None or not (stack_tag.startswith("emu.stack") or
            stack_tag == "emu.kernel.thread_stack" or stack_tag.startswith("emu.kernel.ipi_stack.cpu")):
        return {"frames": [], "stop": "Guest RSP is outside the modeled stack"}
    lower, upper = mapping.base, mapping.base + mapping.size

    def stack_value(address, width=8):
        if not lower <= address or address + width > upper:
            raise ValueError("Unwind read lies outside the guest stack")
        return int.from_bytes(kernel.mem_read(address, width), "little")

    visited = set()
    try:
        for _ in range(64):
            sp = registers[4]
            if (pc, sp) in visited:
                raise ValueError("Repeated x64 unwind frame")
            visited.add((pc, sp))
            found = runtime_function(kernel, pc)
            frame = {"pc": hex(pc), "rsp": hex(sp)}
            frames.append(frame)
            if found is not None:
                module, entry = found
                frame["module"] = module.name
                seen_chains = set()
                for _ in range(16):
                    begin, end, unwind = entry
                    if unwind in seen_chains or unwind + 4 > module.image_size:
                        raise ValueError("Invalid or repeated chained unwind info")
                    seen_chains.add(unwind)
                    header = kernel.mem_read(module.base + unwind, 4)
                    version, flags = header[0] & 7, header[0] >> 3
                    prolog, count, frame_description = header[1:]
                    if version != 1 or flags & ~7 or (flags & 4 and flags & 3):
                        raise ValueError(f"Unsupported x64 unwind version/flags {version}/{flags}")
                    size = 4 + ((count + 1) & ~1) * 2
                    if unwind + size + (12 if flags & 4 else 4 if flags & 3 else 0) > module.image_size:
                        raise ValueError("Truncated x64 unwind info")
                    body = kernel.mem_read(module.base + unwind, size)
                    frame.update({"function_begin": hex(module.base + begin),
                                  "unwind_rva": hex(unwind), "flags": flags})
                    offset = pc - module.base - begin
                    frame_register = frame_description & 15
                    establisher = registers[frame_register] - (frame_description >> 4) * 16 if frame_register else sp
                    frame["establisher"] = hex(establisher)
                    if flags & 1 and offset >= prolog:
                        handler = struct.unpack("<I", kernel.mem_read(module.base + unwind + size, 4))[0]
                        if handler >= module.image_size:
                            raise ValueError("Exception handler lies outside the guest image")
                        frame.update({"handler": hex(module.base + handler),
                                      "handler_data": hex(module.base + unwind + size + 4)})
                        return {"frames": frames, "stop": "language_handler_found"}
                    index = 0
                    while index < count:
                        code_offset, operation = body[4 + index * 2:6 + index * 2]
                        opcode, info = operation & 15, operation >> 4
                        slots = {0: 1, 1: 2 if info == 0 else 3, 2: 1, 3: 1,
                                 4: 2, 5: 3, 8: 2, 9: 3}.get(opcode)
                        if slots is None or index + slots > count or opcode == 1 and info > 1:
                            raise ValueError(f"Unsupported or truncated unwind operation {opcode}/{info}")
                        operand = int.from_bytes(body[6 + index * 2:4 + (index + slots) * 2], "little")
                        if offset >= prolog or code_offset <= offset:
                            if opcode == 0:
                                registers[info] = stack_value(registers[4])
                                registers[4] += 8
                            elif opcode == 1:
                                registers[4] += operand * 8 if info == 0 else operand
                            elif opcode == 2:
                                registers[4] += info * 8 + 8
                            elif opcode == 3:
                                if not frame_register:
                                    raise ValueError("Missing unwind frame register")
                                registers[4] = establisher
                            elif opcode in (4, 5):
                                address = registers[4] + (operand * 8 if opcode == 4 else operand)
                                registers[info] = stack_value(address)
                            elif opcode in (8, 9):
                                # The diagnostic walk needs only integer state.
                                # Do not reuse it as a full CONTEXT restoration.
                                stack_value(registers[4] + operand * (16 if opcode == 8 else 1), 16)
                        index += slots
                    if flags & 4:
                        entry = struct.unpack("<III", kernel.mem_read(module.base + unwind + size, 12))
                        if not entry[0] < entry[1] <= module.image_size or entry[2] >= module.image_size:
                            raise ValueError("Invalid chained runtime-function bounds")
                        continue
                    break
                else:
                    raise ValueError("Chained unwind limit reached")
            pc = stack_value(registers[4])
            registers[4] += 8
            if pc in (kernel.return_hook, kernel.exit_hook) or not pc:
                return {"frames": frames, "stop": "end_of_guest_stack"}
        return {"frames": frames, "stop": "frame_limit"}
    except Exception as error:
        return {"frames": frames, "stop": f"{type(error).__name__}: {error}"[:512]}
