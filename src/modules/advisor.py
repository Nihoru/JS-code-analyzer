from __future__ import annotations

import json
import os
import re
import time
from typing import Protocol

import httpx

# --- КОНСТАНТЫ ---
DEFAULT_LLM_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai"
DEFAULT_LLM_MODEL = "gemini-2.5-flash"
DEFAULT_TIMEOUT_SECONDS = 120.0
DEFAULT_MAX_TOKENS = 8192
DEFAULT_TEMPERATURE = 0.35
DEFAULT_MAX_RETRIES = 2
OUTPUT_MAX_LENGTH = 1000
MAX_INPUT_VULNERABILITY_LINES = 5

# --- ИСКЛЮЧЕНИЯ ---
class RecommenderError(RuntimeError):
    pass

class ConfigurationError(RecommenderError):
    pass

class ProviderResponseError(RecommenderError):
    pass

# --- ИНТЕРФЕЙС ---
class IVulnerabilityRecommender(Protocol):
    def get_recommendations(self, lines: list[str]) -> str:
        ...

# --- ОСНОВНОЙ КЛАСС ---
class LlmVulnerabilityRecommender:
    """
    Модуль для получения рекомендаций по уязвимостям через LLM (OpenAI-совместимый API).
    """
    def __init__(
        self,
        api_key: str | None = None,
        *,
        key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        temperature: float = DEFAULT_TEMPERATURE,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        output_max_length: int = OUTPUT_MAX_LENGTH,
        max_input_lines: int = MAX_INPUT_VULNERABILITY_LINES,
    ) -> None:
        explicit = (api_key or "").strip() or (key or "").strip()
        resolved_key = (
            explicit
            or os.environ.get("GEMINI_API_KEY", "").strip()
            or os.environ.get("LLM_API_KEY", "").strip()
            or os.environ.get("OPENAI_API_KEY", "").strip()
            or os.environ.get("CURSOR_API_KEY", "").strip()
        )
        if not resolved_key:
            raise ConfigurationError(
                "Нужен ключ API. Передайте его в конструктор или установите переменную окружения GEMINI_API_KEY."
            )

        base = (
            (base_url or "").strip()
            or os.environ.get("LLM_BASE_URL", "").strip()
            or os.environ.get("CURSOR_LLM_BASE_URL", "").strip()
        ).rstrip("/")
        
        self._api_key = resolved_key
        self._base_url = base or DEFAULT_LLM_BASE_URL
        self._model = (
            (model or "").strip()
            or os.environ.get("LLM_MODEL", "").strip()
            or os.environ.get("CURSOR_LLM_MODEL", "").strip()
            or DEFAULT_LLM_MODEL
        )
        
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._max_retries = max_retries
        self._output_max_length = output_max_length
        self._max_input_lines = max_input_lines
        
        self._client = httpx.Client(
            timeout=timeout_seconds,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
        )

    def get_recommendations(self, lines: list[str]) -> str:
        normalized = _normalize_lines(lines)[: self._max_input_lines]
        if not normalized:
            return ""

        try:
            content = self._request_recommendations_content(normalized)
            return _truncate_output(content, self._output_max_length)
        except Exception as exc:
            return _truncate_output(f"Ошибка API: {exc}", self._output_max_length)

    def _request_recommendations_content(self, lines: list[str]) -> str:
        path = f"{self._base_url.rstrip('/')}/chat/completions"
        payload = self._build_payload(lines)

        for attempt in range(self._max_retries + 1):
            try:
                response = self._client.post(path, json=payload)
                if response.status_code in {429, 500, 502, 503, 504} and attempt < self._max_retries:
                    time.sleep(2**attempt)
                    continue
                response.raise_for_status()
                data = response.json()
                return _extract_content_from_response(data)
            except (httpx.HTTPStatusError, httpx.RequestError) as exc:
                if attempt < self._max_retries:
                    time.sleep(2**attempt)
                    continue
                raise ProviderResponseError(f"Ошибка запроса: {exc}") from exc

        raise ProviderResponseError("Не удалось получить ответ после повторных попыток.")

    def _build_payload(self, lines: list[str]) -> dict:
        limit = self._output_max_length
        system = (
            "Ты эксперт по безопасной разработке. Отвечай только на русском. "
            f"Итог — нумерованный список (3–7 пунктов), не длиннее {limit} символов. "
            "Без вступлений — сразу «1. …»."
        )
        user = _build_consolidated_prompt(lines, limit)
        return {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self._temperature,
            "max_tokens": self._max_tokens,
        }

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> LlmVulnerabilityRecommender:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
def _build_consolidated_prompt(lines: list[str], max_chars: int) -> str:
    numbered = "\n".join(f"{i + 1}. {line.strip()}" for i, line in enumerate(lines))
    return (
        f"Ниже {len(lines)} строк от сканера. Сформируй ОДИН общий список рекомендаций.\n"
        f"Максимум {max_chars} символов.\n\nСтроки:\n{numbered}"
    )

def _extract_content_from_response(data: dict) -> str:
    choices = data.get("choices") or []
    if not choices:
        raise ProviderResponseError("Пустой ответ от провайдера.")
    content = choices[0].get("message", {}).get("content", "")
    if not content:
        raise ProviderResponseError("Текст ответа пуст.")
    return content.strip()

def _normalize_lines(lines: list[str]) -> list[str]:
    return [line.strip() for line in lines if line and line.strip()]

_SENTENCE_END = re.compile(r"(?<![.!?…\d])[.!?…](?=\s|$)")

def _truncate_output(text: str, max_length: int) -> str:
    text = text.strip()
    if not text or max_length < 1:
        return ""
    if len(text) > max_length:
        text = text[:max_length].rstrip()
    
    # Обрезка по последнему законченному предложению
    if not _ends_with_sentence_punctuation(text):
        matches = list(_SENTENCE_END.finditer(text))
        if matches:
            text = text[: matches[-1].end()].rstrip()
    return text

def _ends_with_sentence_punctuation(s: str) -> bool:
    s = s.rstrip()
    return bool(s and s[-1] in ".!?…")