"""Export a bounded, observed instruction graph from a saved Rust worker trace.

Edges describe consecutive observations, not complete control flow, retired
stores, recovered VM instructions or semantic equivalence. Different bytes or
observation phases at the same PC remain distinct nodes.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM


def blocks(nodes: list[dict], edges: list[dict]) -> dict:
    """Collapse only single-predecessor/successor observed fallthrough chains."""
    incoming, outgoing = {}, {}
    for edge in edges:
        incoming.setdefault(edge["target"], []).append(edge)
        outgoing.setdefault(edge["source"], []).append(edge)
    links = {}
    for node in nodes:
        after = outgoing.get(node["id"], [])
        if len(after) != 1 or node["transfer"] is not None:
            continue
        edge = after[0]
        target = nodes[edge["target"]]
        if (edge["kind"] == "fallthrough" and len(incoming.get(target["id"], [])) == 1
                and node["phase"] == target["phase"]):
            links[node["id"]] = target["id"]
    continuations = set(links.values())
    rows, owner = [], {}
    for node in nodes:
        if node["id"] in continuations:
            continue
        members = []
        current = node["id"]
        while True:
            members.append(current)
            owner[current] = len(rows)
            if current not in links:
                break
            current = links[current]
        rows.append(dict(id=len(rows), context_id=node["context_id"], pc=node["pc"],
                         instruction_nodes=members))
    if len(owner) != len(nodes):
        raise ValueError("Fallthrough chains did not partition observed instructions")
    counts = Counter()
    for edge in edges:
        a, b = owner[edge["source"]], owner[edge["target"]]
        # A jump back to the start of its own block must survive collapsing.
        if a != b or edge["kind"] != "fallthrough":
            counts[(a, b, edge["kind"])] += edge["observations"]
    return dict(blocks=rows, block_edges=[dict(source=a, target=b, kind=k, observations=n)
                                         for (a,b,k),n in sorted(counts.items())])


def graph(window: dict) -> dict:
    architecture = window["architecture"]
    if architecture not in {"x86", "x64"}:
        raise ValueError("Unsupported trace architecture")
    rows = window["instructions"]
    contexts = window["contexts"]
    if len(rows) > 65536 or len(contexts) > 256:
        raise ValueError("Trace exceeds bounded instruction/context limits")
    decoder = Cs(CS_ARCH_X86, CS_MODE_64 if architecture == "x64" else CS_MODE_32)
    decoder.detail = True
    nodes, identities = [], {}
    edges, boundaries = Counter(), Counter()
    previous = None
    last_sequence = -1
    for row in rows:
        pc, size, context = row["pc"], row["size"], row["context_id"]
        ordinal, sequence = row["instruction_ordinal"], row["sequence"]
        phase = row["phase"]
        if (not 0 <= context < len(contexts) or not 1 <= size <= 15
                or not 0 <= pc < 1 << (64 if architecture == "x64" else 32)
                or ordinal < 0 or sequence <= last_sequence):
            raise ValueError("Invalid instruction identity, ordering or context")
        last_sequence = sequence
        raw = bytes(row["instruction_bytes"])
        if len(raw) != size:
            raise ValueError("Instruction size differs from captured bytes")
        identity = (context, pc, raw, phase)
        node_id = identities.get(identity)
        if node_id is None:
            instructions = list(decoder.disasm(raw, pc))
            if len(instructions) != 1 or instructions[0].size != size:
                raise ValueError(f"Captured bytes do not decode exactly at {pc:#x}")
            instruction = instructions[0]
            groups = [decoder.group_name(group) for group in instruction.groups]
            direct = (instruction.operands and instruction.operands[0].type == X86_OP_IMM)
            transfer = next((g for g in ["call", "ret", "iret", "int", "jump"] if g in groups), None)
            node_id = len(nodes)
            identities[identity] = node_id
            nodes.append(dict(id=node_id, context_id=context, pc=pc, size=size,
                              phase=phase, bytes=raw.hex(), mnemonic=instruction.mnemonic,
                              operands=instruction.op_str, transfer=transfer,
                              indirect=bool(transfer in {"call", "jump"} and not direct),
                              visits=0, first_ordinal=ordinal, last_ordinal=ordinal))
        node = nodes[node_id]
        node["visits"] += 1
        node["last_ordinal"] = ordinal
        if previous is not None:
            prev_id, prev_ordinal, prev_sequence = previous
            before = nodes[prev_id]
            # Sequence is shared with model-write receipts. A sequence gap is
            # not a missing instruction when admission ordinals are adjacent.
            if ordinal != prev_ordinal + 1:
                boundaries["observation_gap"] += 1
            elif before["context_id"] != context:
                boundaries["context_transition"] += 1
            else:
                # An API row is after modeled dispatch. Do not label its edge
                # as proof that the encoded gate instruction executed natively.
                kind = ("modeled_api_successor" if before["phase"] != "native_pre_instruction"
                        else before["transfer"] or
                        ("fallthrough" if before["pc"] + before["size"] == pc else "discontinuous"))
                edges[(prev_id, node_id, kind)] += 1
        previous = (node_id, ordinal, sequence)
    result = dict(schema="emumee.observed_instruction_graph.v1", architecture=architecture,
                rows=len(rows), contexts=contexts, nodes=nodes,
                edges=[dict(source=a, target=b, kind=kind, observations=count)
                       for (a, b, kind), count in sorted(edges.items())],
                boundaries=dict(boundaries), unproven_terminal_nodes=[] if previous is None else [previous[0]],
                window_status=window.get("status"), window_truncated=window.get("truncated"),
                scope="Observed consecutive instructions within one context and ordinal interval only. "
                      "Pre-instruction observations do not prove retirement. Gaps and context transitions "
                      "do not create edges. Byte/phase variants stay distinct. Final node has no proven "
                      "successor from this window. No complete CFG, VM recovery or devirtualization claim.")
    result.update(blocks(nodes, result["edges"]))
    return result


def bound_json(path: Path, maximum: int = 128 * 1024 * 1024) -> tuple[dict, str]:
    if not path.is_file() or path.stat().st_size > maximum:
        raise ValueError(f"Missing or oversized report: {path}")
    raw = path.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--assembly", type=Path, help="Fresh disassembly listing of observed blocks")
    args = parser.parse_args()
    if args.output.exists() or (args.assembly and args.assembly.exists()):
        raise ValueError("Choose fresh output paths")
    summary, summary_sha = bound_json(args.run / "summary.json")
    report, report_sha = bound_json(args.run / "worker" / "engine-report.json")
    manifest, manifest_sha = bound_json(args.run / "controller-manifest.json")
    _, checkpoint_sha = bound_json(args.run / "worker" / "artifact-checkpoint.json")
    report_bytes = (args.run / "worker" / "engine-report.json").stat().st_size
    if (summary["engine_sha256"] != report_sha or summary["engine_bytes"] != report_bytes
            or summary["manifest_sha256"] != checkpoint_sha
            or summary["checkpoint_sha256"] != checkpoint_sha
            or manifest["driver_summary_sha256"] != summary_sha):
        raise ValueError("Saved report/manifest digest or size mismatch")
    execution = report["execution"]
    result = graph(execution["instruction_window"])
    result["provenance"] = dict(run=str(args.run.resolve()), summary_sha256=summary_sha,
                                engine_sha256=report_sha, manifest_sha256=manifest_sha,
                                checkpoint_sha256=checkpoint_sha,
                                input_sha256=summary["binding"]["input_sha256"])
    # Exclusive output creation preserves previous research artifacts.
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    if args.assembly:
        with args.assembly.open("x", encoding="utf-8") as stream:
            stream.write("; Observed blocks only. No complete CFG or devirtualization claim.\n")
            for block in result["blocks"]:
                stream.write(f"\nblock_{block['id']}: ; context {block['context_id']}\n")
                for index in block["instruction_nodes"]:
                    node = result["nodes"][index]
                    stream.write(f"  {node['pc']:016x}  {node['bytes']:<30}  {node['mnemonic']} {node['operands']} ; visits={node['visits']}, {node['phase']}\n")
    print(json.dumps(dict(output=str(args.output), rows=result["rows"], nodes=len(result["nodes"]),
                          edges=len(result["edges"]), blocks=len(result["blocks"]),
                          boundaries=result["boundaries"])))


if __name__ == "__main__":
    main()
