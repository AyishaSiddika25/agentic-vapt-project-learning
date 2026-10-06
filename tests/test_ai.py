from __future__ import annotations

import os
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from agentic_vapt.ai import (
    HeuristicAnalyzer,
    OpenAIResponsesAnalyzer,
    _parse_structured_analysis,
    _validate_endpoint,
)
from agentic_vapt.config import AIConfig
from agentic_vapt.models import GateDecision, Reachability
from tests.helpers import make_finding


class AIAnalysisTests(unittest.TestCase):
    def test_valid_structured_response(self) -> None:
        parsed = _parse_structured_analysis(
            '{"security_reasoning":"Relevant", "evidence":["scanner"], '
            '"confidence":"High", "recommended_next_step":"Review"}'
        )
        self.assertEqual(parsed["confidence"], "high")

    def test_invalid_structured_response(self) -> None:
        with self.assertRaises(ValueError):
            _parse_structured_analysis('{"security_reasoning":"Relevant"}')

    def test_missing_credentials_is_graceful(self) -> None:
        analyzer = OpenAIResponsesAnalyzer(AIConfig(provider="openai"))
        with patch.dict(os.environ, {}, clear=True):
            result = analyzer.analyze(make_finding())
        self.assertEqual(result.status, "error")
        self.assertIn("AGENTIC_VAPT_LLM_API_KEY", result.error)

    def test_api_failure_is_graceful(self) -> None:
        analyzer = OpenAIResponsesAnalyzer(AIConfig(provider="openai"))
        with (
            patch.dict(os.environ, {"AGENTIC_VAPT_LLM_API_KEY": "test-key"}, clear=True),
            patch("agentic_vapt.ai._open_request", side_effect=URLError("offline")),
        ):
            result = analyzer.analyze(make_finding())
        self.assertEqual(result.status, "error")
        self.assertIn("offline", result.error)

    def test_valid_api_response_is_validated(self) -> None:
        analyzer = OpenAIResponsesAnalyzer(AIConfig(provider="openai"))
        response = MagicMock()
        response.read.return_value = (
            b'{"output_text":"{\\"security_reasoning\\":\\"Relevant\\",'
            b'\\"evidence\\":[\\"scanner\\"],\\"confidence\\":\\"high\\",'
            b'\\"recommended_next_step\\":\\"Review\\"}"}'
        )
        response.__enter__.return_value = response
        with (
            patch.dict(os.environ, {"AGENTIC_VAPT_LLM_API_KEY": "test-key"}, clear=True),
            patch("agentic_vapt.ai._open_request", return_value=response),
        ):
            result = analyzer.analyze(make_finding())
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.confidence, "high")

    def test_heuristic_analysis_cannot_change_gate(self) -> None:
        finding = make_finding()
        finding.decision = GateDecision.BLOCK
        finding.reachability = Reachability.REACHABLE
        result = HeuristicAnalyzer().analyze(finding)
        self.assertEqual(result.status, "completed")
        self.assertEqual(finding.decision, GateDecision.BLOCK)

    def test_generic_scanner_help_uses_actionable_fallback(self) -> None:
        finding = make_finding()
        finding.remediation = finding.title
        result = HeuristicAnalyzer().analyze(finding)
        self.assertIn("parameterized queries", result.recommended_next_step)

    def test_remote_endpoint_requires_allow_list(self) -> None:
        error = _validate_endpoint("https://internal.example/v1/responses", ("api.openai.com",))
        self.assertTrue(error)

    def test_local_http_endpoint_is_allowed(self) -> None:
        self.assertEqual(_validate_endpoint("http://127.0.0.1:11434/v1/responses", ()), "")


if __name__ == "__main__":
    unittest.main()
