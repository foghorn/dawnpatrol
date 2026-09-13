"""Runtime configuration.

Everything environment-specific arrives through environment variables (each
supporting a ``_FILE`` variant) or the mounted site profile. Nothing in this
package hardcodes a hostname, address, credential, or topology fact.
"""

from __future__ import annotations

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


@dataclass(slots=True)
class AISettings:
    enabled: bool = True
    provider: str = "anthropic"
    model: str = "claude-opus-5"
    effort: str = "high"
    max_tokens: int = 16000
    max_tool_calls: int = 25
    max_turns: int = 30
    max_cost_usd: float = 3.00
    task_budget_tokens: int = 0  # 0 disables
    refusal_fallback: bool = True
    temperature: float | None = None  # OpenAI-compatible providers only
    base_url: str = ""
    api_key: SecretStr = field(default_factory=lambda: SecretStr(""))
    extra: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls, registry: SecretRegistry) -> AISettings:
        provider = (read_env(f"{ENV_PREFIX}AI_PROVIDER", "anthropic") or "anthropic").strip()
        key = read_secret(f"{ENV_PREFIX}AI_API_KEY")
        if not key:
            # Conventional provider-native variables, so an existing host works unchanged.
            for fallback in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
                candidate = read_secret(fallback)
                if candidate:
                    key = candidate
                    break
        registry.register(key)
        temp_raw = read_env(f"{ENV_PREFIX}AI_TEMPERATURE")
        return cls(
            enabled=read_bool(f"{ENV_PREFIX}AI_ENABLED", True),
            provider=provider,
            model=read_env(f"{ENV_PREFIX}AI_MODEL", "claude-opus-5") or "claude-opus-5",
            effort=(read_env(f"{ENV_PREFIX}AI_EFFORT", "high") or "high").strip().lower(),
            max_tokens=read_int(f"{ENV_PREFIX}AI_MAX_TOKENS", 16000),
            max_tool_calls=read_int(f"{ENV_PREFIX}AI_MAX_TOOL_CALLS", 25),
            max_turns=read_int(f"{ENV_PREFIX}AI_MAX_TURNS", 30),
            max_cost_usd=read_float(f"{ENV_PREFIX}AI_MAX_COST_USD", 3.00),
            task_budget_tokens=read_int(f"{ENV_PREFIX}AI_TASK_BUDGET_TOKENS", 0),
            refusal_fallback=read_bool(f"{ENV_PREFIX}AI_REFUSAL_FALLBACK", True),
            temperature=float(temp_raw) if temp_raw else None,
            base_url=read_env(f"{ENV_PREFIX}AI_BASE_URL", "") or "",
            api_key=key,
        )


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

        return cls(
            data_dir=data_dir,
            output_dir=output_dir,
            profile_path=profile_path,
            window_hours=window_hours,
            db=DatabaseSettings.from_env(data_dir, registry),
            ai=AISettings.from_env(registry),
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
            "ai_provider": self.ai.provider,
            "ai_model": self.ai.model,
            "ai_enabled": self.ai.enabled,
            "schedule": self.schedule.cron or "(run once)",
            "retention_raw_days": self.retention.raw_days,
            "retention_ioc_days": self.retention.ioc_days,
            "mcp": (f"enabled on {self.mcp.host}:{self.mcp.port}{self.mcp.path}"
                    if self.mcp.enabled else "disabled"),
        }
