"""
config.py — PentraAI settings
All API keys and configuration loaded from .env file.
Never hardcode keys in code — always use environment variables.
"""

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):

    # ── LLM Provider ──────────────────────────────────────────────
    # Change this ONE line to switch between LLMs:
    #   "groq"    → free, fast, Llama 3.1 70B  (console.groq.com)
    #   "gemini"  → free tier, Google Gemini    (aistudio.google.com)
    #   "claude"  → paid, most accurate         (console.anthropic.com)
    llm_provider: str = Field(default="groq", env="LLM_PROVIDER")

    # ── Groq settings (FREE — console.groq.com) ───────────────────
    groq_api_key: str = Field(default="", env="GROQ_API_KEY")
    groq_model: str = Field(
        default="llama-3.1-70b-versatile",
        env="GROQ_MODEL"
    )

    # ── Gemini settings (FREE tier — aistudio.google.com) ─────────
    gemini_api_key: str = Field(default="", env="GEMINI_API_KEY")
    gemini_model: str = Field(
        default="gemini-1.5-flash",
        env="GEMINI_MODEL"
    )

    # ── Claude settings (PAID — console.anthropic.com) ────────────
    claude_api_key: str = Field(default="", env="CLAUDE_API_KEY")
    claude_model: str = Field(
        default="claude-haiku-4-5-20251001",
        env="CLAUDE_MODEL"
    )

    # ── App ───────────────────────────────────────────────────────
    app_name: str = "PentraAI"
    app_version: str = "1.0.0"
    debug: bool = Field(default=False, env="DEBUG")

    # ── Scan limits ───────────────────────────────────────────────
    max_endpoints: int = Field(default=50, env="MAX_ENDPOINTS")
    request_timeout: int = Field(default=10, env="REQUEST_TIMEOUT")
    max_concurrent_requests: int = Field(default=5, env="MAX_CONCURRENT")

    # ── Database ──────────────────────────────────────────────────
    database_url: str = Field(
        default="sqlite+aiosqlite:///./pentraai.db",
        env="DATABASE_URL"
    )

    class Config:
        env_file = [".env", "../.env"]
        env_file_encoding = "utf-8"
        extra = "ignore"

# Single instance used across the whole app
settings = Settings()
