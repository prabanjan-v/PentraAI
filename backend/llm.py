"""
llm.py — Universal LLM wrapper for PentraAI.

Every LLM call in PentraAI goes through call_llm(). This module now uses free
providers with automatic resilience — no other file needs to change because
call_llm()'s signature is unchanged.

Providers (configured in .env via config.py):
  deepseek_zen    → DeepSeek V4 Flash Free via OpenCode Zen   (primary, free)
  gemini          → Gemini Flash via Google AI Studio         (fallback, free)
  deepseek_direct → api.deepseek.com                          (optional, paid)

Resilience:
  * multiple API keys per provider, rotated automatically on rate-limit/quota;
  * exponential backoff on transient errors;
  * automatic fallback to the next provider when one is exhausted.

Usage (unchanged):
    text   = call_llm("Is this IDOR?  Response: {...}")
    parsed = call_llm("Return a JSON test plan", expect_json=True)
"""

import json
import re
import time
import random
import logging

from config import settings
from openai import OpenAI
from openai import (
    AuthenticationError,
    PermissionDeniedError,
    RateLimitError,
    APITimeoutError,
    APIConnectionError,
    InternalServerError,
    BadRequestError,
    NotFoundError,
)

logger = logging.getLogger("pentraai.llm")

# Base URL + model + key list for every known provider name.
_CATALOG = {
    "deepseek_zen": lambda: (
        settings.deepseek_zen_base_url,
        settings.deepseek_zen_model,
        settings.opencode_zen_api_keys_list,
    ),
    "gemini": lambda: (
        settings.gemini_base_url,
        settings.gemini_model,
        settings.gemini_api_keys_list,
    ),
    "deepseek_direct": lambda: (
        settings.deepseek_direct_base_url,
        settings.deepseek_direct_model,
        settings.deepseek_api_keys_list,
    ),
}

# Lazily-built provider list (each: name, base_url, model, key slots, clients).
_PROVIDERS = None


def _build_providers() -> list[dict]:
    providers: list[dict] = []
    for name in settings.llm_provider_order_list:
        factory = _CATALOG.get(name)
        if factory is None:
            logger.warning("unknown LLM provider '%s' in LLM_PROVIDER_ORDER; skipping", name)
            continue
        base_url, model, keys = factory()
        if not keys:
            logger.info("provider '%s' has no API keys; skipping", name)
            continue
        providers.append({
            "name": name,
            "base_url": base_url,
            "model": model,
            "keys": [{"key": k, "cooldown_until": 0.0} for k in keys],
            "idx": 0,
            "clients": {},
        })
    if not providers:
        raise ValueError(
            "No LLM providers configured. Add keys to your .env "
            "(OPENCODE_ZEN_API_KEYS and/or GEMINI_API_KEYS) and list them in "
            "LLM_PROVIDER_ORDER."
        )
    logger.info("LLM ready with providers: %s", ", ".join(p["name"] for p in providers))
    return providers


def _providers() -> list[dict]:
    global _PROVIDERS
    if _PROVIDERS is None:
        _PROVIDERS = _build_providers()
    return _PROVIDERS


def _mask(key: str) -> str:
    return "****" if len(key) <= 8 else f"{key[:4]}…{key[-4:]}"


def _next_key(provider: dict):
    """Return the next available key slot (round-robin), skipping cooling keys."""
    now = time.monotonic()
    slots = provider["keys"]
    n = len(slots)
    for offset in range(n):
        i = (provider["idx"] + offset) % n
        if slots[i]["cooldown_until"] <= now:
            provider["idx"] = (i + 1) % n
            return slots[i]
    return None  # all keys cooling down


def _client(provider: dict, key: str) -> OpenAI:
    client = provider["clients"].get(key)
    if client is None:
        client = OpenAI(
            api_key=key,
            base_url=provider["base_url"],
            timeout=settings.llm_request_timeout,
            max_retries=0,  # retries handled here, not by the SDK
        )
        provider["clients"][key] = client
    return client


def _backoff(attempt: int) -> float:
    raw = settings.llm_backoff_base_seconds * (2 ** attempt)
    jitter = random.uniform(0, settings.llm_backoff_base_seconds)
    return min(settings.llm_backoff_max_seconds, raw + jitter)


def _generate(prompt: str) -> str:
    """Send prompt through providers with rotation, backoff and fallback."""
    failures: dict[str, str] = {}

    for provider in _providers():
        last = None
        for attempt in range(settings.llm_max_retries_per_provider):
            slot = _next_key(provider)
            if slot is None:
                last = "all keys cooling down"
                break
            key = slot["key"]
            try:
                resp = _client(provider, key).chat.completions.create(
                    model=provider["model"],
                    messages=[{"role": "user", "content": prompt}],
                    temperature=settings.llm_temperature,
                    max_tokens=settings.llm_max_tokens,
                )
                text = (resp.choices[0].message.content or "").strip()
                slot["cooldown_until"] = 0.0  # success clears any prior penalty
                if not text:
                    # e.g. a reasoning model that spent its budget before answering
                    last = "empty response"
                    time.sleep(_backoff(attempt))
                    continue
                return text
            except (AuthenticationError, PermissionDeniedError) as e:
                slot["cooldown_until"] = time.monotonic() + settings.llm_auth_cooldown_seconds
                logger.warning("%s auth failure key=%s; rotating", provider["name"], _mask(key))
                last = f"auth: {e}"
                continue
            except RateLimitError as e:
                slot["cooldown_until"] = time.monotonic() + settings.llm_key_cooldown_seconds
                delay = _backoff(attempt)
                logger.warning("%s rate-limited key=%s; rotate + backoff %.1fs",
                               provider["name"], _mask(key), delay)
                last = f"rate_limit: {e}"
                time.sleep(delay)
                continue
            except (APITimeoutError, APIConnectionError, InternalServerError) as e:
                delay = _backoff(attempt)
                logger.warning("%s transient error; backoff %.1fs: %s", provider["name"], delay, e)
                last = f"transient: {e}"
                time.sleep(delay)
                continue
            except (BadRequestError, NotFoundError) as e:
                # caller/config error — no point retrying or falling back
                raise ValueError(f"{provider['name']} bad request: {e}") from e

        failures[provider["name"]] = last or "exhausted retries"
        logger.warning("provider %s exhausted (%s); falling back", provider["name"], failures[provider["name"]])

    raise RuntimeError(
        "All LLM providers failed: "
        + "; ".join(f"{name} -> {err}" for name, err in failures.items())
    )


def call_llm(prompt: str, expect_json: bool = False) -> str:
    """
    Send a prompt to the configured LLM(s) and return the response.

    Args:
        prompt:      The full prompt string to send.
        expect_json: If True, strips code fences and returns valid JSON text.

    Returns:
        The LLM response as a string (valid JSON string if expect_json=True).
    """
    raw = _generate(prompt)
    if expect_json:
        return _clean_json(raw)
    return raw


# ── JSON cleaner ──────────────────────────────────────────────────

def _clean_json(text: str) -> str:
    """
    Strip markdown code fences and return valid JSON.

    LLMs sometimes wrap JSON in ```json ... ``` fences, or add a sentence before
    or after it. We first try a direct parse; if that fails we extract the
    outermost {...} or [...] block and parse that. This makes JSON handling
    robust across different models (Llama, DeepSeek, Gemini all format slightly
    differently).
    """
    cleaned = re.sub(r"```(?:json)?\s*", "", text)
    cleaned = re.sub(r"```\s*$", "", cleaned, flags=re.MULTILINE).strip()

    try:
        json.loads(cleaned)
        return cleaned
    except json.JSONDecodeError:
        pass

    # Fallback: pull the outermost JSON object or array out of surrounding prose.
    candidates = []
    for open_ch, close_ch in (("{", "}"), ("[", "]")):
        start = cleaned.find(open_ch)
        end = cleaned.rfind(close_ch)
        if start != -1 and end != -1 and end > start:
            candidates.append(cleaned[start:end + 1])

    for candidate in candidates:
        try:
            json.loads(candidate)
            return candidate
        except json.JSONDecodeError:
            continue

    raise ValueError(f"LLM returned invalid JSON.\n\nRaw output:\n{text}")