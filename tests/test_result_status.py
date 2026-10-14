"""A run is complete only when the guest completion path is observed."""

import unittest

from emumee.reports import valid_summary
from emumee.worker import _result_status


class ResultStatusTests(unittest.TestCase):
    def test_error_free_unknown_stop_is_partial(self):
        status, error = _result_status({
            "errors": [], "completion_reason": "unknown", "instruction_count": 25})
        self.assertEqual(status, "partial")
        self.assertEqual(error, "Guest completion path was not observed")

    def test_observed_return_and_exit_are_complete(self):
        for reason in ("entry_return", "exit_process"):
            with self.subTest(reason=reason):
                self.assertEqual(_result_status({
                    "errors": [], "completion_reason": reason}), ("completed", None))

    def test_limits_and_errors_do_not_look_complete(self):
        self.assertEqual(_result_status({"errors": [], "timeout_reached": True,
                                         "completion_reason": "timeout"}),
                         ("timeout", None))
        self.assertEqual(_result_status({"errors": ["unsupported API"],
                                         "completion_reason": "entry_return"}),
                         ("partial", None))

    def test_validator_rejects_contradictory_completed_reason(self):
        value = {"id": "20261013T120000Z-12345678", "sample": {},
                 "status": "completed", "artifacts": [], "errors": [],
                 "completion_reason": "unknown"}
        self.assertFalse(valid_summary(value))
        value["status"] = "partial"
        self.assertTrue(valid_summary(value))
        value["status"] = "completed"
        value["completion_reason"] = "entry_return"
        self.assertTrue(valid_summary(value))
