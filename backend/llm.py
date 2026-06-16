"""
llm.py — Universal LLM wrapper (supports Groq, Gemini, Claude)
All LLM calls in PentraAI go through call_llm().
To switch provider, change LLM_PROVIDER in your .env file.
No other file needs to change.

Providers:
  groq    → FREE  — console.groq.com    — Llama 3.1 70B
  gemini  → FREE  — aistudio.google.com — Gemini 1.5 Flash
  claude  → PAID  — console.anthropic.com — Claude Haiku
"""

import json
import re
from config import settings


def call_llm(prompt: str, expect_json: bool = False) -> str:
    """
    Send a prompt to the configured LLM and return the response.

    Args:
        prompt:      The full prompt string to send
        expect_json: If True, strips code fences and validates JSON

    Returns:
        LLM response as a plain string.
        If expect_json=True, returns a valid JSON string.

    Usage (same regardless of which LLM is active):
        text   = call_llm("Is this IDOR?  Response: {...}")
        parsed = call_llm("Return a JSON test plan", expect_json=True)
    """
    provider = settings.llm_provider.lower().strip()

    if provider == "groq":
        raw = _call_groq(prompt)
    elif provider == "gemini":
        raw = _call_gemini(prompt)
    elif provider == "claude":
        raw = _call_claude(prompt)
    else:
        raise ValueError(
            f"Unknown LLM_PROVIDER '{provider}'. "
            f"Choose from: groq, gemini, claude"
        )

    if expect_json:
        return _clean_json(raw)

    return raw


# ── Provider implementations ──────────────────────────────────────

def _call_groq(prompt: str) -> str:
    """
    Call Groq API — FREE tier, fast, powerful.
    Model: llama-3.1-70b-versatile
    Get key: console.groq.com
    """
    if not settings.groq_api_key:
        raise ValueError(
            "GROQ_API_KEY is missing. "
            "Add it to your .env file. Get it free at console.groq.com"
        )

    from groq import Groq
    client = Groq(api_key=settings.groq_api_key)

    response = client.chat.completions.create(
        model=settings.groq_model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=2000,
    )
    return response.choices[0].message.content.strip()


def _call_gemini(prompt: str) -> str:
    """
    Call Google Gemini API — FREE tier available.
    Model: gemini-1.5-flash
    Get key: aistudio.google.com → Get API Key
    """
    if not settings.gemini_api_key:
        raise ValueError(
            "GEMINI_API_KEY is missing. "
            "Add it to your .env file. Get it free at aistudio.google.com"
        )

    import google.generativeai as genai
    genai.configure(api_key=settings.gemini_api_key)

    model = genai.GenerativeModel(
        model_name=settings.gemini_model,
        generation_config={"temperature": 0.1, "max_output_tokens": 2000}
    )
    response = model.generate_content(prompt)
    return response.text.strip()


def _call_claude(prompt: str) -> str:
    """
    Call Anthropic Claude API — PAID, most accurate.
    Model: claude-haiku-4-5-20251001 (cheapest, ~$0.001 per call)
    Get key: console.anthropic.com
    Note: Your Claude Pro subscription is separate from the API.
    """
    if not settings.claude_api_key:
        raise ValueError(
            "CLAUDE_API_KEY is missing. "
            "Add it to your .env file. Get it at console.anthropic.com"
        )

    import anthropic
    client = anthropic.Anthropic(api_key=settings.claude_api_key)

    response = client.messages.create(
        model=settings.claude_model,
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.content[0].text.strip()


# ── JSON cleaner ──────────────────────────────────────────────────

def _clean_json(text: str) -> str:
    """
    Strip markdown code fences and extract valid JSON.
    LLMs sometimes wrap their JSON output in ```json ... ``` blocks.
    This removes those wrappers and validates the result.
    """
    text = re.sub(r"```(?:json)?\s*", "", text)
    text = re.sub(r"```\s*$", "", text, flags=re.MULTILINE)
    text = text.strip()

    try:
        json.loads(text)
        return text
    except json.JSONDecodeError as e:
        raise ValueError(
            f"LLM returned invalid JSON: {e}\n\nRaw output:\n{text}"
        ) from e
