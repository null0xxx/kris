"""Versioned config schema for ``config.toml`` / ``policy.toml`` (SPEC §12.2).

Rules enforced here:

- ``config_version = 1`` is required; any other version →
  :class:`ConfigVersionError` (V1 ships no migration). The version gate in
  :func:`load_config` runs **before** pydantic validation.
- Unknown field → startup warning + ignored: collected into the model's
  ``warnings`` list and **deleted** from the stored model (never fatal, never
  silently honored, §12.2).
- Deprecated field (see :data:`DEPRECATED_FIELDS`) → explicit warning.
- Invalid values → pydantic ``ValidationError`` with exact field paths.

Key fields per §12.2: ``providers.kimi.{base_url, model, timeout_s}``,
``providers.ollama.{endpoint, model, num_ctx}``, ``budgets.*``,
``net.allowlist[]``, ``memory.retention_days``, ``lab.enabled`` (default
``false``, §11.1), ``ui.language = ka|en``.

The Ollama endpoint is pinned to the §5.3 allowlist regex
(:data:`OLLAMA_ENDPOINT_PATTERN`) — a remote Ollama endpoint is a config
validation error.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from lsassist.contracts import BudgetState

__all__ = [
    "DEPRECATED_FIELDS",
    "OLLAMA_ENDPOINT_PATTERN",
    "BudgetsConfig",
    "Config",
    "ConfigVersionError",
    "KimiConfig",
    "LabConfig",
    "MemoryConfig",
    "NetConfig",
    "OllamaConfig",
    "ProvidersConfig",
    "UiConfig",
    "load_config",
]

# §5.3: remote Ollama = config validation error. Exact regex, do not drift.
OLLAMA_ENDPOINT_PATTERN = r"^https?://(127\.0\.0\.1|\[::1\]|localhost)(:\d+)?$"

# Top-level keys that were once valid but are gone in config_version 1.
# Each maps to the reason shown in the explicit deprecation warning (§12.2).
DEPRECATED_FIELDS: dict[str, str] = {
    "telemetry": "removed in config_version 1; observability is local-only (§14.2)",
    "auto_update": "removed in config_version 1; updates are a manual signed path (§13.2)",
}


class ConfigVersionError(Exception):
    """Refuse to start: missing or unsupported ``config_version`` (§12.2)."""


class _Section(BaseModel):
    """Base for every config section: unknown fields → warning + dropped (§12.2)."""

    model_config = ConfigDict(extra="allow")

    warnings: list[str] = Field(default_factory=list, exclude=True)

    @model_validator(mode="after")
    def _collect_unknown_fields(self) -> Self:
        extra = self.model_extra
        if extra:
            for key in list(extra):
                reason = DEPRECATED_FIELDS.get(key)
                if reason is not None:
                    self.warnings.append(f"deprecated config field {key!r}: {reason}")
                else:
                    self.warnings.append(f"unknown config field {key!r} ignored (§12.2)")
                del extra[key]
        return self


class KimiConfig(_Section):
    """``providers.kimi`` — coding endpoint (§5.1)."""

    base_url: str = "https://api.kimi.com/coding/v1"
    model: str = "kimi-for-coding"
    timeout_s: float = Field(default=60.0, gt=0)


class OllamaConfig(_Section):
    """``providers.ollama`` — local adapter (§5.3)."""

    endpoint: Annotated[str, StringConstraints(pattern=OLLAMA_ENDPOINT_PATTERN)] = (
        "http://127.0.0.1:11434"
    )
    model: str = "gemma4:e4b-it-qat"
    num_ctx: int = Field(default=32_768, ge=1)


class ProvidersConfig(_Section):
    kimi: KimiConfig = Field(default_factory=KimiConfig)
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)


_BUDGET_DEFAULTS = BudgetState()


class BudgetsConfig(_Section):
    """``budgets.*`` — §4.3 limits; defaults mirror ``BudgetState`` (T1.05)."""

    max_tool_calls: int = Field(default=_BUDGET_DEFAULTS.max_tool_calls, ge=1)
    max_plan_revisions: int = Field(default=_BUDGET_DEFAULTS.max_plan_revisions, ge=1)
    max_tokens: int = Field(default=_BUDGET_DEFAULTS.max_tokens, ge=1)
    max_wall_clock_s: int = Field(default=_BUDGET_DEFAULTS.max_wall_clock_s, ge=1)
    max_output_per_tool: tuple[int, int] = _BUDGET_DEFAULTS.max_output_per_tool
    max_session_tool_calls: int = Field(
        default=_BUDGET_DEFAULTS.max_session_tool_calls, ge=1
    )


class NetConfig(_Section):
    allowlist: list[str] = Field(default_factory=list)


class MemoryConfig(_Section):
    retention_days: int = Field(default=90, ge=1)


class LabConfig(_Section):
    """§11.1 feature gate — off by default; enabling requires CONFIRM_EXACT."""

    enabled: bool = False


class UiConfig(_Section):
    language: Literal["ka", "en"] = "ka"


class Config(_Section):
    """Root config model; ``config_version`` gates schema evolution (§12.2)."""

    config_version: Literal[1]
    providers: ProvidersConfig = Field(default_factory=ProvidersConfig)
    budgets: BudgetsConfig = Field(default_factory=BudgetsConfig)
    net: NetConfig = Field(default_factory=NetConfig)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    lab: LabConfig = Field(default_factory=LabConfig)
    ui: UiConfig = Field(default_factory=UiConfig)


def load_config(path: Path) -> Config:
    """Parse ``config.toml`` at *path*; version gate first, then validation.

    Raises :class:`ConfigVersionError` for a missing or unsupported
    ``config_version``, and pydantic ``ValidationError`` (exact field paths)
    for any other invalid content (§12.2: refuse to start).
    """
    with path.open("rb") as handle:
        data: dict[str, Any] = tomllib.load(handle)
    version = data.get("config_version")
    if version is None:
        raise ConfigVersionError(
            f"{path}: config_version is required (§12.2); expected config_version = 1"
        )
    if version != 1:
        raise ConfigVersionError(
            f"{path}: config_version = {version!r} is unsupported; "
            "V1 ships no migration — write config_version = 1 (§12.2)"
        )
    return Config.model_validate(data)
