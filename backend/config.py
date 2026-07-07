"""
config.py — PentraAI settings
All API keys and configuration loaded from .env file.
Never hardcode keys in code — always use environment variables.

LLM layer (updated): Groq removed. PentraAI now uses free providers with
automatic multi-key rotation and provider fallback:
  deepseek_zen    → DeepSeek V4 Flash Free via OpenCode Zen   (primary, free)
  gemini          → Gemini Flash via Google AI Studio         (fallback, free)
  deepseek_direct → api.deepseek.com                          (optional, paid)
Give several comma-separated keys per provider to enable rotation on rate limits.
"""

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):

    # ── LLM provider order ────────────────────────────────────────
    # Comma-separated. First = primary; the rest are fallbacks in order.
    # Valid names: deepseek_zen, gemini, deepseek_direct
    llm_provider_order: str = Field(
        default="deepseek_zen,gemini", env="LLM_PROVIDER_ORDER"
    )

    # ── DeepSeek via OpenCode Zen (PRIMARY, free) ─────────────────
    # Multiple keys → comma-separated → automatic rotation on rate limits.
    opencode_zen_api_keys: str = Field(default="", env="OPENCODE_ZEN_API_KEYS")
    deepseek_zen_model: str = Field(
        default="deepseek-v4-flash-free", env="DEEPSEEK_ZEN_MODEL"
    )
    deepseek_zen_base_url: str = Field(
        default="https://opencode.ai/zen/v1", env="DEEPSEEK_ZEN_BASE_URL"
    )

    # ── Gemini (FALLBACK, free — aistudio.google.com) ─────────────
    gemini_api_keys: str = Field(default="", env="GEMINI_API_KEYS")
    gemini_model: str = Field(default="gemini-2.5-flash", env="GEMINI_MODEL")
    gemini_base_url: str = Field(
        default="https://generativelanguage.googleapis.com/v1beta/openai/",
        env="GEMINI_BASE_URL",
    )

    # ── DeepSeek direct (OPTIONAL, paid — leave blank to disable) ─
    deepseek_api_keys: str = Field(default="", env="DEEPSEEK_API_KEYS")
    deepseek_direct_model: str = Field(
        default="deepseek-v4-pro", env="DEEPSEEK_DIRECT_MODEL"
    )
    deepseek_direct_base_url: str = Field(
        default="https://api.deepseek.com", env="DEEPSEEK_DIRECT_BASE_URL"
    )

    # ── LLM request behaviour ─────────────────────────────────────
    llm_temperature: float = Field(default=0.1, env="LLM_TEMPERATURE")
    llm_max_tokens: int = Field(default=4096, env="LLM_MAX_TOKENS")
    llm_request_timeout: float = Field(default=60.0, env="LLM_REQUEST_TIMEOUT")

    # ── Retry / backoff / key rotation ────────────────────────────
    llm_max_retries_per_provider: int = Field(
        default=4, env="LLM_MAX_RETRIES_PER_PROVIDER"
    )
    llm_backoff_base_seconds: float = Field(
        default=1.0, env="LLM_BACKOFF_BASE_SECONDS"
    )
    llm_backoff_max_seconds: float = Field(
        default=30.0, env="LLM_BACKOFF_MAX_SECONDS"
    )
    llm_key_cooldown_seconds: float = Field(
        default=60.0, env="LLM_KEY_COOLDOWN_SECONDS"
    )
    llm_auth_cooldown_seconds: float = Field(
        default=1800.0, env="LLM_AUTH_COOLDOWN_SECONDS"
    )

    # ── Legacy single-key fields (kept for back-compat; optional) ─
    # If GEMINI_API_KEYS is empty but the old GEMINI_API_KEY is set, it is used.
    gemini_api_key: str = Field(default="", env="GEMINI_API_KEY")
    claude_api_key: str = Field(default="", env="CLAUDE_API_KEY")
    claude_model: str = Field(
        default="claude-haiku-4-5-20251001", env="CLAUDE_MODEL"
    )

    # ── App ───────────────────────────────────────────────────────
    app_name: str = "PentraAI"
    app_version: str = "1.1.0"
    debug: bool = Field(default=False, env="DEBUG")

    # ── Scan limits ───────────────────────────────────────────────
    max_endpoints: int = Field(default=50, env="MAX_ENDPOINTS")
    request_timeout: int = Field(default=10, env="REQUEST_TIMEOUT")
    max_concurrent_requests: int = Field(default=5, env="MAX_CONCURRENT")

    # ── Database ──────────────────────────────────────────────────
    database_url: str = Field(
        default="sqlite+aiosqlite:///./pentraai.db", env="DATABASE_URL"
    )

    # ── Derived helpers (parse comma-separated key lists) ─────────
    @property
    def llm_provider_order_list(self) -> list[str]:
        return [p.strip() for p in self.llm_provider_order.split(",") if p.strip()]

    @property
    def opencode_zen_api_keys_list(self) -> list[str]:
        return [k.strip() for k in self.opencode_zen_api_keys.split(",") if k.strip()]

    @property
    def gemini_api_keys_list(self) -> list[str]:
        keys = [k.strip() for k in self.gemini_api_keys.split(",") if k.strip()]
        if not keys and self.gemini_api_key.strip():
            keys = [self.gemini_api_key.strip()]  # fall back to legacy single key
        return keys

    @property
    def deepseek_api_keys_list(self) -> list[str]:
        return [k.strip() for k in self.deepseek_api_keys.split(",") if k.strip()]

    class Config:
        env_file = [".env", "../.env"]
        env_file_encoding = "utf-8"
        extra = "ignore"


# Single instance used across the whole app
settings = Settings()
