"""Independent small native traces for the observed graph exporter."""
import importlib.util
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "export_instruction_cfg", Path(__file__).resolve().parents[1] / "tools" / "export_instruction_cfg.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def row(sequence, ordinal, pc, raw, context=0, phase="native_pre_instruction"):
    return dict(sequence=sequence, instruction_ordinal=ordinal, pc=pc,
                instruction_bytes=list(bytes.fromhex(raw)), size=len(bytes.fromhex(raw)),
                context_id=context, phase=phase)


def window(rows):
    return dict(architecture="x64", contexts=[{"thread_id": 1}, {"thread_id": 2}], instructions=rows)


class InstructionGraphTests(unittest.TestCase):
    def test_saved_report_and_checkpoint_bindings_are_checked_before_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "worker").mkdir()
            report = root / "worker" / "engine-report.json"
            report.write_text(json.dumps({"execution": {"instruction_window": window([row(1, 0, 0x1000, "90")])}}), encoding="utf-8")
            checkpoint = root / "worker" / "artifact-checkpoint.json"
            checkpoint.write_text('{"payloads":[]}', encoding="utf-8")
            digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
            summary = root / "summary.json"
            summary.write_text(json.dumps(dict(engine_sha256=digest(report), engine_bytes=report.stat().st_size,
                                               manifest_sha256=digest(checkpoint), checkpoint_sha256=digest(checkpoint),
                                               binding={"input_sha256": "a" * 64})), encoding="utf-8")
            (root / "controller-manifest.json").write_text(json.dumps({"driver_summary_sha256": digest(summary)}), encoding="utf-8")
            output = root / "graph.json"
            with patch("sys.argv", ["export", str(root), str(output)]), contextlib.redirect_stdout(io.StringIO()):
                module.main()
            self.assertEqual(json.loads(output.read_text())["rows"], 1)
            for target in [report, checkpoint]:
                original = target.read_bytes()
                target.write_bytes(original + b" ")
                other = root / "refused.json"
                with patch("sys.argv", ["export", str(root), str(other)]), self.assertRaises(ValueError):
                    module.main()
                self.assertFalse(other.exists())
                target.write_bytes(original)

    def test_loop_has_observed_indirect_target_counts_and_unproven_final_successor(self):
        g = module.graph(window([row(1, 10, 0x1000, "90"), row(2, 11, 0x1001, "ff e0"),
                                 row(3, 12, 0x1000, "90"), row(4, 13, 0x1001, "ff e0")]))
        self.assertEqual([n["visits"] for n in g["nodes"]], [2, 2])
        self.assertTrue(g["nodes"][1]["indirect"])
        self.assertEqual([(e["kind"], e["observations"]) for e in g["edges"]], [("fallthrough", 2), ("jump", 1)])
        self.assertEqual(g["unproven_terminal_nodes"], [1])
        self.assertEqual(len(g["blocks"]), 1)
        self.assertEqual(g["blocks"][0]["instruction_nodes"], [0, 1])
        self.assertEqual(g["block_edges"], [dict(source=0, target=0, kind="jump", observations=1)])

    def test_code_versions_and_api_phases_are_never_merged(self):
        g = module.graph(window([row(1, 0, 0x1000, "90"), row(2, 1, 0x1000, "c3"),
                                 row(3, 2, 0x1000, "c3", phase="api_post_dispatch"),
                                 row(4, 3, 0x2000, "90")]))
        self.assertEqual(len(g["nodes"]), 4)
        self.assertEqual(g["edges"][-1]["kind"], "modeled_api_successor")
        self.assertEqual(len(g["blocks"]), 4)

    def test_gaps_and_thread_changes_do_not_invent_control_flow(self):
        g = module.graph(window([row(1, 0, 0x1000, "90"), row(2, 2, 0x2000, "90"),
                                 row(3, 3, 0x3000, "90", context=1)]))
        self.assertEqual(g["edges"], [])
        self.assertEqual(g["boundaries"], {"observation_gap": 1, "context_transition": 1})

    def test_interleaved_non_instruction_event_sequences_preserve_adjacent_ordinals(self):
        g = module.graph(window([row(1, 10, 0x1000, "90"), row(8, 11, 0x1001, "90")]))
        self.assertEqual(g["boundaries"], {})
        self.assertEqual(len(g["edges"]), 1)
        self.assertEqual(g["blocks"][0]["instruction_nodes"], [0, 1])

    def test_invalid_sizes_bytes_contexts_and_duplicate_sequences_fail(self):
        for rows in [[row(1, 0, 0, "0f")], [row(1, 0, 0, "90", context=2)],
                     [row(1, 0, 0, "90"), row(1, 1, 1, "90")]]:
            with self.assertRaises(ValueError):
                module.graph(window(rows))
        bad = row(1, 0, 0, "90")
        bad["size"] = 2
        with self.assertRaises(ValueError):
            module.graph(window([bad]))


if __name__ == "__main__":
    unittest.main()
