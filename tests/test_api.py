import os
import unittest
from unittest.mock import MagicMock, patch

import httpx
from fastapi.testclient import TestClient

from analyzer.ai import ExplanationUnavailable, explain
from analyzer.app import app
from analyzer.core import MAX_CONTEXT_CHARS


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_analysis_never_calls_ai(self):
        with patch("analyzer.app.explain") as provider:
            response = self.client.post(
                "/api/analyze", json={"log": "ld: undefined reference to init_driver"}
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["likely_component"], "driver")
        provider.assert_not_called()

    def test_empty_binary_and_invalid_requests(self):
        for payload in ({"log": " "}, {"log": "binary\x00"}, {"log": 42}, {}):
            self.assertIn(
                self.client.post("/api/analyze", json=payload).status_code, (400, 422)
            )

    def test_transport_limit(self):
        self.assertEqual(
            self.client.post(
                "/api/analyze", content=b"x" * (6 * 1024 * 1024 + 1)
            ).status_code,
            413,
        )

    def test_cross_origin_rejected(self):
        response = self.client.post(
            "/api/analyze",
            json={"log": "failure"},
            headers={"origin": "https://untrusted.example"},
        )
        self.assertEqual(response.status_code, 403)

    def test_explanation_context_limit(self):
        with patch("analyzer.app.explain") as provider:
            response = self.client.post(
                "/api/explain", json={"context": "x" * (MAX_CONTEXT_CHARS + 1)}
            )
        self.assertEqual(response.status_code, 422)
        provider.assert_not_called()

    def test_missing_ai_key(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}):
            self.assertFalse(self.client.get("/api/health").json()["ai_enabled"])
            self.assertEqual(
                self.client.post(
                    "/api/explain", json={"context": "L1: error"}
                ).status_code,
                503,
            )

    def test_ui_served(self):
        self.assertIn("Build investigation", self.client.get("/").text)
        self.assertEqual(self.client.get("/static/app.js").status_code, 200)
        self.assertEqual(
            self.client.get("/").headers["x-content-type-options"], "nosniff"
        )

    def test_docs_policy_does_not_weaken_app_policy(self):
        self.assertIn(
            "https://cdn.jsdelivr.net",
            self.client.get("/docs").headers["content-security-policy"],
        )
        self.assertNotIn(
            "unsafe-inline", self.client.get("/").headers["content-security-policy"]
        )

    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    @patch("analyzer.ai.httpx.Client")
    def test_provider_only_receives_redacted_context(self, client_class):
        client = client_class.return_value.__enter__.return_value
        client.post.return_value = MagicMock()
        client.post.return_value.json.return_value = {
            "choices": [{"message": {"content": "Check linker dependencies."}}]
        }
        self.assertEqual(
            explain("L4: error token=secret-value"), "Check linker dependencies."
        )
        payload = client.post.call_args.kwargs["json"]
        self.assertNotIn("secret-value", str(payload))
        self.assertIn("[REDACTED]", payload["messages"][1]["content"])
        self.assertEqual(len(payload["messages"]), 2)

    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    @patch("analyzer.ai.httpx.Client")
    def test_provider_errors_are_sanitized(self, client_class):
        client_class.return_value.__enter__.return_value.post.side_effect = (
            httpx.ConnectError("internal-sensitive-detail")
        )
        with self.assertRaises(ExplanationUnavailable) as caught:
            explain("L1: error")
        self.assertNotIn("internal-sensitive-detail", str(caught.exception))
