"""Runtime configuration.

Everything environment-specific arrives through environment variables (each
supporting a ``_FILE`` variant) or the mounted site profile. Nothing in this
package hardcodes a hostname, address, credential, or topology fact.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus

from .errors import ConfigError
from .secrets import (
    SecretRegistry,
    SecretStr,
    read_bool,
    read_env,
    read_float,
    read_int,
    read_list,
    read_secret,
)

ENV_PREFIX = "DAWNPATROL_"


# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class DatabaseSettings:
    """SQLite by default; MySQL when credentials are supplied.

    The override is credential-driven rather than mode-driven: if a MySQL host
    *and* user are present, remote wins. That means deploying against a shared
    database is purely additive configuration - no flag to remember to flip.
    """

    url: str
    dialect: str  # "sqlite" | "mysql"
    echo: bool = False
    pool_size: int = 5
    display: str = ""

    @classmethod
    def from_env(cls, data_dir: Path, registry: SecretRegistry) -> DatabaseSettings:
        explicit = read_env(f"{ENV_PREFIX}DB_URL")
        if explicit:
            dialect = "mysql" if explicit.startswith("mysql") else "sqlite"
            return cls(
                url=explicit,
                dialect=dialect,
                echo=read_bool(f"{ENV_PREFIX}DB_ECHO"),
                display=_mask_url(explicit),
            )

        host = read_env(f"{ENV_PREFIX}DB_HOST")
        user = read_env(f"{ENV_PREFIX}DB_USER")
        if host and user:
            password = read_secret(f"{ENV_PREFIX}DB_PASSWORD")
            registry.register(password)
            port = read_int(f"{ENV_PREFIX}DB_PORT", 3306)
            name = read_env(f"{ENV_PREFIX}DB_NAME", "dawnpatrol") or "dawnpatrol"
            url = (
                f"mysql+pymysql://{quote_plus(user)}:{quote_plus(password.get())}"
                f"@{host}:{port}/{name}?charset=utf8mb4"
            )
            return cls(
                url=url,
                dialect="mysql",
                echo=read_bool(f"{ENV_PREFIX}DB_ECHO"),
                pool_size=read_int(f"{ENV_PREFIX}DB_POOL_SIZE", 5),
                display=f"mysql://{user}:***@{host}:{port}/{name}",
            )

        path = data_dir / "dawnpatrol.db"
        return cls(
            url=f"sqlite:///{path}",
            dialect="sqlite",
            echo=read_bool(f"{ENV_PREFIX}DB_ECHO"),
            display=f"sqlite:///{path}",
        )

    @property
    def is_mysql(self) -> bool:
        return self.dialect == "mysql"


def _mask_url(url: str) -> str:
    if "://" not in url or "@" not in url:
        return url
    scheme, rest = url.split("://", 1)
    creds, tail = rest.rsplit("@", 1)
    user = creds.split(":", 1)[0]
    return f"{scheme}://{user}:***@{tail}"


# --------------------------------------------------------------------------- #
# AI
# --------------------------------------------------------------------------- #

#: A named model config is defined by setting its PROVIDER variable -
#: DAWNPATROL_AI_<NAME>_PROVIDER - the same "presence enables it" pattern the
#: plugin folders use. Every one of them can be fully configured and left
#: uncommented at once (each lives in its own namespace, so two configured
#: models never share a variable and can't stomp each other's key/model/base
#: URL); DAWNPATROL_AI_ACTIVE then picks which single one actually runs.
_AI_DESIGNATOR_RE = re.compile(rf"^{ENV_PREFIX}AI_([A-Z0-9_]+)_PROVIDER$")


@dataclass(slots=True)
class AISettings:
    """One fully-resolved model config - provider, model, credentials, and
    every provider-specific knob a run against it needs. ``Settings.ai`` is
    whichever one DAWNPATROL_AI_ACTIVE selects; ``Settings.ai_profiles``
    holds every one that was defined, active or not, so a future feature that
    runs more than one model over the same evidence and compares results has
    them ready without any further config-loading work.
    """

    enabled: bool = True
    provider: str = "anthropic"
    model: str = "claude-opus-5"
    effort: str = "high"
    max_tokens: int = 16000
    #: Run mechanics, not model capability - deliberately identical across
    #: every profile (copied in once by _load_ai_profiles), not read here.
    max_tool_calls: int = 25
    max_turns: int = 30
    max_cost_usd: float = 3.00
    task_budget_tokens: int = 0  # 0 disables
    refusal_fallback: bool = True
    temperature: float | None = None  # openai_compatible only
    base_url: str = ""
    api_key: SecretStr = field(default_factory=lambda: SecretStr(""))
    timeout_seconds: int = 300
    verify_tls: bool = True
    max_tokens_param: str = "max_tokens"  # openai_compatible only
    reasoning_effort: str = ""            # openai_compatible only
    #: Cost accounting only, never sent to the API. anthropic_provider.py
    #: prices from its own built-in per-model table instead of these.
    price_input_per_mtok: float = 0.0
    price_output_per_mtok: float = 0.0
    price_cache_read_per_mtok: float = 0.0
    price_cache_write_per_mtok: float = 0.0

    @classmethod
    def _for_designator(
        cls, name: str, *, enabled: bool, max_tool_calls: int, max_turns: int,
        max_cost_usd: float, registry: SecretRegistry,
    ) -> AISettings:
        """Read one DAWNPATROL_AI_<NAME>_* block."""
        p = f"{ENV_PREFIX}AI_{name}_"
        provider = (read_env(f"{p}PROVIDER", "anthropic") or "anthropic").strip()
        key = read_secret(f"{p}API_KEY")
        if not key:
            # Conventional provider-native variable, so an existing host's
            # environment works unchanged without an explicit per-model key.
            fallback = {"anthropic": "ANTHROPIC_API_KEY",
                       "openai": "OPENAI_API_KEY",
                       "openai_compatible": "OPENAI_API_KEY"}.get(provider, "")
            if fallback:
                key = read_secret(fallback)
        registry.register(key)
        temp_raw = read_env(f"{p}TEMPERATURE")
        return cls(
            enabled=enabled,
            provider=provider,
            model=read_env(f"{p}MODEL", "claude-opus-5") or "claude-opus-5",
            effort=(read_env(f"{p}EFFORT", "high") or "high").strip().lower(),
            max_tokens=read_int(f"{p}MAX_TOKENS", 16000),
            max_tool_calls=max_tool_calls,
            max_turns=max_turns,
            max_cost_usd=max_cost_usd,
            task_budget_tokens=read_int(f"{p}TASK_BUDGET_TOKENS", 0),
            refusal_fallback=read_bool(f"{p}REFUSAL_FALLBACK", True),
            temperature=float(temp_raw) if temp_raw else None,
            base_url=read_env(f"{p}BASE_URL", "") or "",
            api_key=key,
            timeout_seconds=read_int(f"{p}TIMEOUT", 300),
            verify_tls=read_bool(f"{p}VERIFY_TLS", True),
            max_tokens_param=read_env(f"{p}MAX_TOKENS_PARAM", "max_tokens") or "max_tokens",
            reasoning_effort=read_env(f"{p}REASONING_EFFORT", "") or "",
            price_input_per_mtok=read_float(f"{p}PRICE_IN", 0.0),
            price_output_per_mtok=read_float(f"{p}PRICE_OUT", 0.0),
            price_cache_read_per_mtok=read_float(f"{p}PRICE_CACHE_READ", 0.0),
            price_cache_write_per_mtok=read_float(f"{p}PRICE_CACHE_WRITE", 0.0),
        )


def _discover_ai_designators() -> list[str]:
    return sorted({
        m.group(1) for key in os.environ
        if (m := _AI_DESIGNATOR_RE.match(key))
    })


def _load_ai_profiles(registry: SecretRegistry) -> tuple[dict[str, AISettings], str]:
    """Load every configured model, and decide which one actually runs.

    Every DAWNPATROL_AI_<NAME>_PROVIDER defines a config named <name>; all of
    them can be fully configured and uncommented simultaneously without
    conflict. DAWNPATROL_AI_ACTIVE selects the one this run uses - required
    once more than one is defined, since nothing else would disambiguate them.
    """
    enabled = read_bool(f"{ENV_PREFIX}AI_ENABLED", True)
    max_tool_calls = read_int(f"{ENV_PREFIX}AI_MAX_TOOL_CALLS", 25)
    max_turns = read_int(f"{ENV_PREFIX}AI_MAX_TURNS", 30)
    max_cost_usd = read_float(f"{ENV_PREFIX}AI_MAX_COST_USD", 3.00)

    profiles = {
        name.lower(): AISettings._for_designator(
            name, enabled=enabled, max_tool_calls=max_tool_calls,
            max_turns=max_turns, max_cost_usd=max_cost_usd, registry=registry,
        )
        for name in _discover_ai_designators()
    }

    active = (read_env(f"{ENV_PREFIX}AI_ACTIVE", "") or "").strip().lower()
    if not active:
        if not profiles:
            # Nothing configured - an empty, disabled-look-alike profile so
            # startup never crashes over a still-blank .env. Harness checks
            # .enabled/provider.available() before ever spending anything.
            return {"default": AISettings(enabled=enabled, max_tool_calls=max_tool_calls,
                                          max_turns=max_turns, max_cost_usd=max_cost_usd)}, "default"
        if len(profiles) > 1:
            raise ConfigError(
                f"{len(profiles)} AI model configs are defined "
                f"({', '.join(sorted(profiles))}) - set {ENV_PREFIX}AI_ACTIVE to "
                f"one of them."
            )
        active = next(iter(profiles))
    elif active not in profiles:
        raise ConfigError(
            f"{ENV_PREFIX}AI_ACTIVE={active!r} does not match any configured model "
            f"({', '.join(sorted(profiles)) or 'none defined'}). Each config needs "
            f"at least {ENV_PREFIX}AI_{active.upper()}_PROVIDER set."
        )
    return profiles, active


# --------------------------------------------------------------------------- #
# Scheduling and delivery
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class ScheduleSettings:
    cron: str = ""
    timezone: str = "UTC"
    run_on_start: bool = True
    jitter_seconds: int = 0

    @classmethod
    def from_env(cls) -> ScheduleSettings:
        return cls(
            cron=(read_env(f"{ENV_PREFIX}SCHEDULE", "") or "").strip(),
            timezone=read_env(f"{ENV_PREFIX}TZ", "UTC") or "UTC",
            run_on_start=read_bool(f"{ENV_PREFIX}RUN_ON_START", True),
            jitter_seconds=read_int(f"{ENV_PREFIX}SCHEDULE_JITTER_SECONDS", 0),
        )


@dataclass(slots=True)
class MCPSettings:
    """The optional read/trigger surface for an external agent.

    Off by default - this is the one thing in the whole design that listens.
    The bearer token is never logged when the operator supplied it; it is
    logged once, at startup, only when none was configured and one had to be
    generated, since that log line is the only place to learn it.
    """

    enabled: bool = False
    host: str = "0.0.0.0"
    port: int = 8420
    token: SecretStr = field(default_factory=lambda: SecretStr(""))
    path: str = "/mcp"
    #: A second, separate opt-in: writing agent-submitted context into every
    #: future run's prompt is a different trust boundary than read-only tools,
    #: so it does not turn on just because DAWNPATROL_MCP_ENABLED did.
    notebook_enabled: bool = False
    #: Bounds cost/context growth on the read side of that boundary - the
    #: harness injects at most this many of the most recent entries; the full
    #: history remains readable in full via the read_notebook tool.
    notebook_max_injected: int = 50
    notebook_max_entry_chars: int = 4000

    @classmethod
    def from_env(cls, registry: SecretRegistry) -> MCPSettings:
        token = read_secret(f"{ENV_PREFIX}MCP_TOKEN")
        registry.register(token)
        return cls(
            enabled=read_bool(f"{ENV_PREFIX}MCP_ENABLED", False),
            host=read_env(f"{ENV_PREFIX}MCP_HOST", "0.0.0.0") or "0.0.0.0",
            port=read_int(f"{ENV_PREFIX}MCP_PORT", 8420),
            token=token,
            path=read_env(f"{ENV_PREFIX}MCP_PATH", "/mcp") or "/mcp",
            notebook_enabled=read_bool(f"{ENV_PREFIX}MCP_NOTEBOOK_ENABLED", False),
            notebook_max_injected=read_int(f"{ENV_PREFIX}MCP_NOTEBOOK_MAX_INJECTED", 50),
            notebook_max_entry_chars=read_int(
                f"{ENV_PREFIX}MCP_NOTEBOOK_MAX_ENTRY_CHARS", 4000
            ),
        )


@dataclass(slots=True)
class RetentionSettings:
    """Raw events age out quickly; a narrow IOC slice persists for hunting."""

    raw_days: int = 7
    ioc_days: int = 180
    metrics_days: int = 730
    enrichment_cache_days: int = 14

    @classmethod
    def from_env(cls) -> RetentionSettings:
        return cls(
            raw_days=read_int(f"{ENV_PREFIX}RETENTION_RAW_DAYS", 7),
            ioc_days=read_int(f"{ENV_PREFIX}RETENTION_IOC_DAYS", 180),
            metrics_days=read_int(f"{ENV_PREFIX}RETENTION_METRICS_DAYS", 730),
            enrichment_cache_days=read_int(f"{ENV_PREFIX}ENRICHMENT_CACHE_DAYS", 14),
        )


# --------------------------------------------------------------------------- #
# Top-level settings
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class Settings:
    data_dir: Path
    output_dir: Path
    profile_path: Path | None
    window_hours: int
    db: DatabaseSettings
    ai: AISettings
    schedule: ScheduleSettings
    retention: RetentionSettings
    secrets: SecretRegistry
    #: Every configured model, keyed by its lowercased designator - not just
    #: the active one. Reused as-is by any future feature that runs more than
    #: one model over the same evidence and compares results.
    ai_profiles: dict[str, AISettings] = field(default_factory=dict)
    ai_active: str = ""
    enabled_sources: list[str] = field(default_factory=list)
    enabled_analyzers: list[str] = field(default_factory=list)
    enabled_enrichers: list[str] = field(default_factory=list)
    enabled_outputs: list[str] = field(default_factory=list)
    disabled: list[str] = field(default_factory=list)
    canary_every_n_runs: int = 1
    canary_enabled: bool = True
    enrichment_enabled: bool = True
    log_level: str = "INFO"
    dry_run: bool = False
    mcp: MCPSettings = field(default_factory=MCPSettings)

    @classmethod
    def from_env(cls) -> Settings:
        registry = SecretRegistry()
        data_dir = Path(read_env(f"{ENV_PREFIX}DATA_DIR", "./data") or "./data").expanduser()
        output_dir = Path(read_env(f"{ENV_PREFIX}OUTPUT_DIR", "./out") or "./out").expanduser()
        profile_raw = read_env(f"{ENV_PREFIX}PROFILE", "")
        profile_path = Path(profile_raw).expanduser() if profile_raw else None

        window_hours = read_int(f"{ENV_PREFIX}WINDOW_HOURS", 24)
        if window_hours < 1:
            raise ConfigError(f"{ENV_PREFIX}WINDOW_HOURS must be >= 1")

        ai_profiles, ai_active = _load_ai_profiles(registry)

        return cls(
            data_dir=data_dir,
            output_dir=output_dir,
            profile_path=profile_path,
            window_hours=window_hours,
            db=DatabaseSettings.from_env(data_dir, registry),
            ai=ai_profiles[ai_active],
            ai_profiles=ai_profiles,
            ai_active=ai_active,
            schedule=ScheduleSettings.from_env(),
            retention=RetentionSettings.from_env(),
            mcp=MCPSettings.from_env(registry),
            secrets=registry,
            enabled_sources=read_list(f"{ENV_PREFIX}SOURCES"),
            enabled_analyzers=read_list(f"{ENV_PREFIX}ANALYZERS"),
            enabled_enrichers=read_list(f"{ENV_PREFIX}ENRICHERS"),
            enabled_outputs=read_list(f"{ENV_PREFIX}OUTPUTS"),
            disabled=read_list(f"{ENV_PREFIX}DISABLE"),
            canary_every_n_runs=read_int(f"{ENV_PREFIX}CANARY_EVERY_N_RUNS", 1),
            canary_enabled=read_bool(f"{ENV_PREFIX}CANARY_ENABLED", True),
            enrichment_enabled=read_bool(f"{ENV_PREFIX}ENRICHMENT_ENABLED", True),
            log_level=(read_env(f"{ENV_PREFIX}LOG_LEVEL", "INFO") or "INFO").upper(),
        )

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def is_disabled(self, name: str) -> bool:
        return name in self.disabled

    def allowed(self, kind: str, name: str) -> bool:
        """Explicit allowlists win; otherwise a plugin self-enables on its env."""
        if self.is_disabled(name):
            return False
        allowlist = {
            "source": self.enabled_sources,
            "analyzer": self.enabled_analyzers,
            "enricher": self.enabled_enrichers,
            "output": self.enabled_outputs,
        }.get(kind, [])
        if allowlist:
            return name in allowlist
        return True

    def describe(self) -> dict[str, Any]:
        return {
            "data_dir": str(self.data_dir),
            "output_dir": str(self.output_dir),
            "profile": str(self.profile_path) if self.profile_path else "(none)",
            "window_hours": self.window_hours,
            "database": self.db.display,
            "ai_active": self.ai_active,
            "ai_provider": self.ai.provider,
            "ai_model": self.ai.model,
            "ai_enabled": self.ai.enabled,
            "ai_configured": ", ".join(sorted(self.ai_profiles)) or "(none)",
            "schedule": self.schedule.cron or "(run once)",
            "retention_raw_days": self.retention.raw_days,
            "retention_ioc_days": self.retention.ioc_days,
            "mcp": (f"enabled on {self.mcp.host}:{self.mcp.port}{self.mcp.path}"
                    if self.mcp.enabled else "disabled"),
            "mcp_notebook": ("enabled" if self.mcp.notebook_enabled
                             else "disabled"),
        }
