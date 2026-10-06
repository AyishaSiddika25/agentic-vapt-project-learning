"""Configuration loading with safe defaults and environment overrides."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class GatePolicy:
    block_severities: tuple[str, ...] = ("critical", "high")
    warn_severities: tuple[str, ...] = ("medium",)
    block_unknown_reachability: bool = False
    analyze_decisions: tuple[str, ...] = ("block", "warn", "unknown")


@dataclass(frozen=True, slots=True)
class AIConfig:
    provider: str = "heuristic"
    model: str = "gpt-5-mini"
    base_url: str = "https://api.openai.com/v1/responses"
    allowed_hosts: tuple[str, ...] = ("api.openai.com",)
    timeout_seconds: float = 30.0
    max_context_characters: int = 12_000


@dataclass(frozen=True, slots=True)
class ScannerConfig:
    timeout_seconds: float = 60.0
    max_output_bytes: int = 25_000_000


@dataclass(frozen=True, slots=True)
class AppConfig:
    gate: GatePolicy = field(default_factory=GatePolicy)
    ai: AIConfig = field(default_factory=AIConfig)
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    suppressions: tuple[dict[str, Any], ...] = ()

    @classmethod
    def load(cls, path: str | Path | None = None) -> AppConfig:
        data: dict[str, Any] = {}
        if path:
            config_path = Path(path)
            try:
                loaded = json.loads(config_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError(f"Unable to load configuration {config_path}: {exc}") from exc
            if not isinstance(loaded, dict):
                raise ValueError("Configuration root must be a JSON object")
            data = loaded

        gate_data = _object(data.get("gate"))
        ai_data = _object(data.get("ai"))
        scanner_data = _object(data.get("scanner"))
        provider = os.getenv("AGENTIC_VAPT_AI_PROVIDER", str(ai_data.get("provider", "heuristic")))
        model = os.getenv("AGENTIC_VAPT_LLM_MODEL", str(ai_data.get("model", "gpt-5-mini")))
        base_url = os.getenv(
            "AGENTIC_VAPT_LLM_BASE_URL",
            str(ai_data.get("base_url", "https://api.openai.com/v1/responses")),
        )
        allowed_hosts_env = os.getenv("AGENTIC_VAPT_LLM_ALLOWED_HOSTS", "").strip()
        allowed_hosts = (
            tuple(host.strip().lower() for host in allowed_hosts_env.split(",") if host.strip())
            if allowed_hosts_env
            else _strings(ai_data.get("allowed_hosts"), ("api.openai.com",))
        )

        suppressions = data.get("suppressions", [])
        if not isinstance(suppressions, list) or not all(isinstance(item, dict) for item in suppressions):
            raise ValueError("suppressions must be a list of JSON objects")

        return cls(
            gate=GatePolicy(
                block_severities=_strings(gate_data.get("block_severities"), ("critical", "high")),
                warn_severities=_strings(gate_data.get("warn_severities"), ("medium",)),
                block_unknown_reachability=bool(gate_data.get("block_unknown_reachability", False)),
                analyze_decisions=_strings(gate_data.get("analyze_decisions"), ("block", "warn", "unknown")),
            ),
            ai=AIConfig(
                provider=provider.lower(),
                model=model,
                base_url=base_url,
                allowed_hosts=allowed_hosts,
                timeout_seconds=_positive_float(ai_data.get("timeout_seconds", 30.0), "ai.timeout_seconds"),
                max_context_characters=_positive_int(
                    ai_data.get("max_context_characters", 12_000),
                    "ai.max_context_characters",
                ),
            ),
            scanner=ScannerConfig(
                timeout_seconds=_positive_float(
                    scanner_data.get("timeout_seconds", 60.0), "scanner.timeout_seconds"
                ),
                max_output_bytes=_positive_int(
                    scanner_data.get("max_output_bytes", 25_000_000),
                    "scanner.max_output_bytes",
                ),
            ),
            suppressions=tuple(suppressions),
        )


def _object(value: object) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise TypeError("Configuration section must be a JSON object")
    return value


def _strings(value: object, default: tuple[str, ...]) -> tuple[str, ...]:
    if value is None:
        return default
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("Configuration value must be a list of strings")
    return tuple(item.strip().lower() for item in value if item.strip())


def _positive_float(value: object, name: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a number") from exc
    if result <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return result


def _positive_int(value: object, name: str) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if result <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return result
