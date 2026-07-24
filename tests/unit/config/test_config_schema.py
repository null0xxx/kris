"""T1.08 RED: versioned config schema (SPEC §12.2, §5.3, §11.1, §4.3).

§12.2: ``config_version = 1``; unknown field → startup warning + ignored
(never fatal, never silently honored); deprecated field → explicit warning;
invalid → refuse to start with exact field errors.
§5.3: Ollama endpoint allowlist regex — remote Ollama = config error.
§11.1: ``lab.enabled`` defaults to ``false``.
§4.3: ``budgets.*`` defaults mirror ``BudgetState``.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from lsassist.config import Config, ConfigVersionError, load_config
from lsassist.config.schema import DEPRECATED_FIELDS, OLLAMA_ENDPOINT_PATTERN
from lsassist.contracts import BudgetState

MINIMAL_TOML = "config_version = 1\n"


def write_config(tmp_path: Path, body: str = MINIMAL_TOML) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(body, encoding="utf-8")
    return path


# --- (1) minimal valid config parses with defaults ---------------------------


def test_minimal_config_parses_with_defaults() -> None:
    cfg = Config.model_validate({"config_version": 1})
    assert cfg.config_version == 1
    assert cfg.warnings == []


def test_load_config_minimal_file(tmp_path: Path) -> None:
    cfg = load_config(write_config(tmp_path))
    assert cfg.config_version == 1
    assert cfg.providers.kimi.model
    assert cfg.providers.ollama.endpoint == "http://127.0.0.1:11434"


# --- (2) config_version = 2 → refuse (no migration in V1) --------------------


def test_version_2_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigVersionError):
        load_config(write_config(tmp_path, "config_version = 2\n"))


def test_version_2_error_says_no_migration(tmp_path: Path) -> None:
    with pytest.raises(ConfigVersionError, match="migration"):
        load_config(write_config(tmp_path, "config_version = 2\n"))


# --- (3) missing config_version → refuse -------------------------------------


def test_missing_config_version_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigVersionError, match="config_version"):
        load_config(write_config(tmp_path, "[lab]\nenabled = false\n"))


# --- (4) unknown top-level field → warning + ignored -------------------------


def test_unknown_top_level_field_warns_and_parses() -> None:
    cfg = Config.model_validate({"config_version": 1, "bogus_field": True})
    assert len(cfg.warnings) == 1
    assert "bogus_field" in cfg.warnings[0]


def test_unknown_field_never_stored_on_model() -> None:
    cfg = Config.model_validate({"config_version": 1, "bogus_field": True})
    assert not hasattr(cfg, "bogus_field")
    assert "bogus_field" not in cfg.model_dump()
    assert cfg.model_extra == {}


def test_unknown_nested_field_warns() -> None:
    cfg = Config.model_validate(
        {"config_version": 1, "providers": {"kimi": {"bogus_nested": 1}}}
    )
    assert len(cfg.providers.kimi.warnings) == 1
    assert "bogus_nested" in cfg.providers.kimi.warnings[0]
    assert not hasattr(cfg.providers.kimi, "bogus_nested")


# --- (5) deprecated field → explicit warning ---------------------------------


def test_deprecated_field_explicit_warning() -> None:
    deprecated_key = next(iter(DEPRECATED_FIELDS))
    cfg = Config.model_validate({"config_version": 1, deprecated_key: True})
    assert any(
        "deprecated" in warning and deprecated_key in warning
        for warning in cfg.warnings
    )
    assert not hasattr(cfg, deprecated_key)


# --- (6) invalid type → refuse with exact field path --------------------------


def test_invalid_budgets_type_refused_with_field_path() -> None:
    with pytest.raises(ValidationError) as excinfo:
        Config.model_validate(
            {"config_version": 1, "budgets": {"max_tool_calls": "abc"}}
        )
    assert "budgets.max_tool_calls" in str(excinfo.value)


def test_load_config_invalid_file_refuses(tmp_path: Path) -> None:
    path = write_config(tmp_path, 'config_version = 1\n[budgets]\nmax_tool_calls = "abc"\n')
    with pytest.raises(ValidationError) as excinfo:
        load_config(path)
    assert "budgets.max_tool_calls" in str(excinfo.value)


def test_invalid_ui_language_refused_with_field_path() -> None:
    with pytest.raises(ValidationError) as excinfo:
        Config.model_validate({"config_version": 1, "ui": {"language": "fr"}})
    assert "ui.language" in str(excinfo.value)


# --- (7) key fields exist (§12.2) --------------------------------------------


def test_kimi_fields_exist() -> None:
    kimi = Config.model_validate({"config_version": 1}).providers.kimi
    assert kimi.base_url == "https://api.kimi.com/coding/v1"
    assert kimi.model
    assert kimi.timeout_s > 0


def test_ollama_fields_exist() -> None:
    ollama = Config.model_validate({"config_version": 1}).providers.ollama
    assert ollama.endpoint == "http://127.0.0.1:11434"
    assert ollama.model
    assert ollama.num_ctx == 32_768


def test_budgets_defaults_mirror_budget_state() -> None:
    """§4.3: budgets.* defaults must equal the T1.05 BudgetState limits."""
    budgets = Config.model_validate({"config_version": 1}).budgets
    state = BudgetState()
    assert budgets.max_tool_calls == state.max_tool_calls
    assert budgets.max_plan_revisions == state.max_plan_revisions
    assert budgets.max_tokens == state.max_tokens
    assert budgets.max_wall_clock_s == state.max_wall_clock_s
    assert tuple(budgets.max_output_per_tool) == tuple(state.max_output_per_tool)
    assert budgets.max_session_tool_calls == state.max_session_tool_calls


def test_net_allowlist_default_and_parse() -> None:
    cfg = Config.model_validate({"config_version": 1})
    assert cfg.net.allowlist == []
    cfg2 = Config.model_validate(
        {"config_version": 1, "net": {"allowlist": ["example.com"]}}
    )
    assert cfg2.net.allowlist == ["example.com"]


def test_memory_retention_days() -> None:
    cfg = Config.model_validate({"config_version": 1})
    assert cfg.memory.retention_days >= 1


def test_lab_enabled_defaults_false() -> None:
    """§11.1: LAB feature gate is off by default."""
    assert Config.model_validate({"config_version": 1}).lab.enabled is False


def test_ui_language_choices() -> None:
    assert Config.model_validate({"config_version": 1}).ui.language == "ka"
    cfg = Config.model_validate({"config_version": 1, "ui": {"language": "en"}})
    assert cfg.ui.language == "en"


# --- (8) Ollama endpoint allowlist (§5.3) -------------------------------------


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://127.0.0.1:11434",
        "http://127.0.0.1",
        "https://localhost:11434",
        "http://localhost",
        "http://[::1]:11434",
        "http://[::1]",
    ],
)
def test_ollama_local_endpoints_accepted(endpoint: str) -> None:
    cfg = Config.model_validate(
        {"config_version": 1, "providers": {"ollama": {"endpoint": endpoint}}}
    )
    assert cfg.providers.ollama.endpoint == endpoint


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://192.168.1.10:11434",
        "http://example.com:11434",
        "https://ollama.internal",
        "http://127.0.0.1:11434/api",
        "http://localhost.evil.com",
    ],
)
def test_ollama_remote_endpoints_refused(endpoint: str) -> None:
    with pytest.raises(ValidationError) as excinfo:
        Config.model_validate(
            {"config_version": 1, "providers": {"ollama": {"endpoint": endpoint}}}
        )
    assert "providers.ollama.endpoint" in str(excinfo.value)


def test_ollama_endpoint_pattern_is_spec_regex() -> None:
    """§5.3 pins the exact allowlist regex; it must not drift."""
    assert OLLAMA_ENDPOINT_PATTERN == r"^https?://(127\.0\.0\.1|\[::1\]|localhost)(:\d+)?$"
