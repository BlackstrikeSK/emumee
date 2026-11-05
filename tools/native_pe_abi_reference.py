"""Extract only frozen pure math handlers; never load a PE or legacy runtime."""
import argparse
import ast
import hashlib
import json
import math
from pathlib import Path
import struct
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def transport():
    source = ROOT / ".venv/Lib/site-packages/speakeasy/binemu.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    names = {"get_func_argv", "do_call_return", "clean_stack_args"}
    methods = [method for owner in tree.body if isinstance(owner, ast.ClassDef)
               for method in owner.body if isinstance(method, ast.FunctionDef) and method.name in names]
    assert {method.name for method in methods} == names
    constants = {name: name for name in (
        "ARCH_X86", "ARCH_AMD64", "CALL_CONV_FLOAT", "CALL_CONV_FASTCALL", "CALL_CONV_STDCALL", "CALL_CONV_CDECL",
        "X86_REG_XMM0", "X86_REG_XMM1", "X86_REG_XMM2", "X86_REG_XMM3", "X86_REG_ESP", "X86_REG_EIP",
        "X86_REG_EAX", "X86_REG_ECX", "X86_REG_EDX", "AMD64_REG_RSP", "AMD64_REG_RIP", "AMD64_REG_RAX",
        "AMD64_REG_RCX", "AMD64_REG_RDX", "AMD64_REG_R8", "AMD64_REG_R9")}
    namespace = {"e_arch": SimpleNamespace(**constants), "EmuException": RuntimeError}
    exec(compile(ast.fix_missing_locations(ast.Module(body=methods, type_ignores=[])), str(source), "exec"), namespace)

    class Frame:
        def get_arch(self):
            return constants["ARCH_AMD64" if self.ptr_size == 8 else "ARCH_X86"]

        def get_ptr_size(self):
            return self.ptr_size

        def reg_read(self, register):
            return self.registers[register]

        def reg_write(self, register, value):
            self.registers[register] = value

        def mem_read(self, address, size):
            self.reads.add(address)
            return self.stack[address].to_bytes(size, "little")

    for name in names:
        setattr(Frame, name, namespace[name])
    rows = []
    for width in (4, 8):
        for convention in ("stdcall", "cdecl", "fastcall", "float"):
            for count in ((0, 1, 2, 4) if convention == "float" else (0, 1, 2, 3, 4, 5, 6, 32)):
                frame = Frame()
                frame.ptr_size = width
                frame.reads = set()
                frame.stack = {0x2000 + offset: 0xabcd0000 + offset for offset in range(0, 400, width)}
                frame.registers = {key: 0x2000 if key.endswith(("RSP", "ESP")) else
                                   0x8000000000000000 + index if "XMM" in key else 0xdead0000 + index
                                   for index, key in enumerate(constants) if "_REG_" in key}
                before = dict(frame.registers)
                conv = constants["CALL_CONV_" + convention.upper()]
                arguments = frame.get_func_argv(conv, count)
                frame.do_call_return(count, ret_addr=0x7654321, ret_value=0x80000001, conv=conv)
                register_names = {"Sp": "AMD64_REG_RSP" if width == 8 else "X86_REG_ESP",
                    "Cx": "AMD64_REG_RCX" if width == 8 else "X86_REG_ECX",
                    "Dx": "AMD64_REG_RDX" if width == 8 else "X86_REG_EDX",
                    "R8": "AMD64_REG_R8", "R9": "AMD64_REG_R9",
                    **{f"Xmm{index}": f"X86_REG_XMM{index}" for index in range(4)}}
                rows.append({"architecture": "x64" if width == 8 else "x86", "convention": convention,
                    "count": count, "registers": {name: before[key] for name, key in register_names.items()},
                    "stack": {str(address): frame.stack[address] for address in sorted(frame.reads)},
                    "arguments": arguments, "returned_sp": frame.registers[register_names["Sp"]]})
    return {"source": source.relative_to(ROOT).as_posix(), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "vectors": rows}


def capture(source):
    text = source.read_text(encoding="utf-8")
    tree = ast.parse(text)
    names = {"hex_to_double", "double_to_hex", "pow", "floor", "sin"}
    methods = []
    declarations = {}
    for owner in tree.body:
        if not isinstance(owner, ast.ClassDef):
            continue
        for method in owner.body:
            if not isinstance(method, ast.FunctionDef) or method.name not in names:
                continue
            if method.name in {"pow", "floor", "sin"}:
                hook = method.decorator_list[0]
                options = {item.arg: item.value for item in hook.keywords}
                assert isinstance(options["conv"], ast.Attribute)
                assert options["conv"].attr == "CALL_CONV_FLOAT"
                declarations[method.name] = ast.literal_eval(options["argc"])
            method.decorator_list = []
            method.returns = None
            for argument in method.args.args:
                argument.annotation = None
            methods.append(method)
    assert {method.name for method in methods} == names
    namespace = {"math": math, "struct": struct}
    compiled = ast.fix_missing_locations(ast.Module(body=methods, type_ignores=[]))
    exec(compile(compiled, str(source), "exec"), namespace)
    owner = type("FrozenPureHandlers", (), {name: namespace[name] for name in names})()
    for name in names:
        del namespace[name]
    values = [-math.inf, -1e308, -2.5, -2.0, -1.0, -0.0, 0.0, 0.5, 1.0, 2.0, 1e308, math.inf, math.nan]
    vectors = []
    for name in ("floor", "sin", "pow"):
        inputs = [(value,) for value in values] if name != "pow" else [
            (value, exponent) for value in values for exponent in (-math.inf, -3.0, -1.0, 0.0, 0.5, 2.0, 3.0, math.inf, math.nan)]
        for arguments in inputs:
            bits = [struct.unpack("<Q", struct.pack("<d", value))[0] for value in arguments]
            row = {"api": name, "arguments": [f"{value:016x}" for value in bits]}
            try:
                result = getattr(owner, name)(None, bits)
                row["result"] = f"{result:016x}"
                row["nan"] = math.isnan(struct.unpack("<d", struct.pack("<Q", result))[0])
            except (ValueError, OverflowError, ZeroDivisionError, TypeError, struct.error) as error:
                row["error"] = type(error).__name__
            vectors.append(row)
    return {"schema": 1, "scope": "Frozen pure math handler outcomes; separate CPU tests qualify transport and callbacks",
            "source": source.relative_to(ROOT).as_posix(),
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "declarations": declarations, "vectors": vectors, "transport": transport()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    source = ROOT / ".venv/Lib/site-packages/speakeasy/winenv/api/usermode/msvcrt.py"
    destination = ROOT / "rust/api-parity/abi-float-reference.json"
    actual = capture(source)
    if args.check:
        assert json.loads(destination.read_bytes()) == actual
    else:
        destination.write_text(json.dumps(actual, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"vectors": len(actual["vectors"]), "source_sha256": actual["source_sha256"], "checked": args.check}))


if __name__ == "__main__":
    main()
