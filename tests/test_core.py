import unittest

from analyzer.core import MAX_CONTEXT_CHARS, analyze, redact


class AnalyzerTests(unittest.TestCase):
    def test_linker_error_over_generic_build_failure(self):
        result = analyze(
            "[Pipeline] build\nsrc/driver.c: warning: unused variable\nld: undefined reference to `init_driver'\ncollect2: error: ld returned 1 exit status\nFinished: FAILURE"
        )
        self.assertEqual(result["failure_type"], "Compilation Error")
        self.assertEqual(result["likely_component"], "driver")
        self.assertEqual(result["failure_line"], 3)
        self.assertIn("library", result["suggested_investigation"])

    def test_context_is_bounded_and_excludes_unrelated_output(self):
        result = analyze(
            "unrelated successful output\n" * 10000
            + "ld: undefined reference to init_driver\n"
            + "error: follow-up diagnostic\n" * 2000
        )
        self.assertLessEqual(len(result["context"]), MAX_CONTEXT_CHARS)
        self.assertNotIn("L1:", result["context"])
        self.assertIn("init_driver", result["context"])
        self.assertLessEqual(len(result["findings"]), 80)

    def test_secrets_redacted_before_returning_context(self):
        text = 'error: token=private-value password="two words"\nAuthorization: Bearer abc123\nhttps://alice:private@example.com\n{"api_key": "hidden"}'
        result = analyze(text)
        for secret in (
            "private-value",
            "two words",
            "abc123",
            "alice:private",
            "hidden",
        ):
            self.assertNotIn(secret, str(result))

    def test_private_key_redacted(self):
        self.assertNotIn(
            "sensitive",
            redact(
                "-----BEGIN RSA PRIVATE KEY-----\nsensitive\n-----END RSA PRIVATE KEY-----"
            ),
        )

    def test_redaction_preserves_failure_line_number(self):
        result = analyze(
            "-----BEGIN RSA PRIVATE KEY-----\nsensitive\n-----END RSA PRIVATE KEY-----\nSyntaxError: invalid syntax"
        )
        self.assertEqual(result["failure_line"], 4)

    def test_categories(self):
        for text, expected in (
            ("ModuleNotFoundError: No module named 'requests'", "Dependency Error"),
            (
                "FAILED tests/test_build.py::test_output - AssertionError",
                "Test Failure",
            ),
            ("error: permission denied", "Permission Error"),
            ("error: connection refused", "Infrastructure Error"),
            ("error: unexpected build result", "Unclassified Failure"),
            ("Permission denied (publickey)", "Permission Error"),
            ("Agent: No space left on device", "Infrastructure Error"),
            ("Finished: FAILURE", "Unclassified Failure"),
            ("warning: deprecated API", "Warnings Only"),
            ("Build complete: 0 errors, 0 warnings", "No Failure Detected"),
        ):
            with self.subTest(text=text):
                self.assertEqual(analyze(text)["failure_type"], expected)

    def test_ansi_removed(self):
        self.assertNotIn(
            "\x1b",
            analyze("\x1b[31mSyntaxError: invalid syntax\x1b[0m")["relevant_error"],
        )

    def test_invalid_input(self):
        for text in ("  ", "binary\x00data", "x" * (5 * 1024 * 1024 + 1)):
            with self.assertRaises(ValueError):
                analyze(text)


if __name__ == "__main__":
    unittest.main()
