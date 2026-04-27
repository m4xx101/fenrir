"""OpenAI-compatible LLM client with tool calling, streaming, and retry support."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, AsyncGenerator

import httpx
from loguru import logger
from openai import AsyncOpenAI, OpenAI
from openai.types.chat import (
    ChatCompletion,
    ChatCompletionChunk,
    ChatCompletionMessageToolCall,
)
from pydantic import BaseModel, Field
from tenacity import retry, stop_after_attempt, wait_exponential

from fenrir.config import LLMConfig, LLMTier


class LLMUsage(BaseModel):
    """Token usage tracking."""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0

    def accumulate(self, other: LLMUsage) -> None:
        self.prompt_tokens += other.prompt_tokens
        self.completion_tokens += other.completion_tokens
        self.total_tokens += other.total_tokens
        self.cost_usd += other.cost_usd


class LLMResponse(BaseModel):
    """Response from LLM with optional tool calls."""
    content: str = ""
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    finish_reason: str = "stop"
    usage: LLMUsage = Field(default_factory=LLMUsage)
    model_used: str = ""
    latency_s: float = 0.0


class LLMClient:
    """OpenAI-compatible client supporting all Fenrir tiers."""

    def __init__(self, config: LLMConfig, tier: LLMTier = LLMTier.TIER_0):
        self.config = config
        self.tier = tier
        self.total_usage = LLMUsage()

        self._client = AsyncOpenAI(
            api_key=config.api_key or "empty",
            base_url=config.base_url or "http://localhost:11434/v1",
            timeout=httpx.Timeout(config.timeout, connect=30.0),
            max_retries=3,
        )
        self._sync_client = OpenAI(
            api_key=config.api_key or "empty",
            base_url=config.base_url or "http://localhost:11434/v1",
            timeout=httpx.Timeout(config.timeout, connect=30.0),
            max_retries=3,
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        reraise=True,
    )
    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        stream: bool = False,
        response_format: dict | None = None,
    ) -> LLMResponse:
        """Send chat completion request with retry."""
        start = time.time()
        kwargs: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": temperature if temperature is not None else self.config.temperature,
            "max_tokens": max_tokens or self.config.max_tokens,
        }

        if tools:
            kwargs["tools"] = tools
        if tool_choice:
            kwargs["tool_choice"] = tool_choice
        if response_format:
            kwargs["response_format"] = response_format

        try:
            if stream:
                response = await self._stream_response(kwargs)
            else:
                completion: ChatCompletion = await self._client.chat.completions.create(**kwargs)
                response = self._parse_completion(completion, time.time() - start)

            self.total_usage.accumulate(response.usage)
            logger.debug(
                f"[{self.tier.value}] {response.usage.total_tokens} tokens, "
                f"latency={response.latency_s:.2f}s"
            )
            return response
        except Exception as e:
            logger.error(f"LLM request failed on {self.tier.value}: {e}")
            raise

    async def _stream_response(
        self, kwargs: dict[str, Any]
    ) -> LLMResponse:
        """Handle streaming responses."""
        content_parts = []
        tool_calls_map: dict[int, dict] = {}
        finish_reason = "stop"
        usage = LLMUsage()

        stream = await self._client.chat.completions.create(**kwargs)
        async for chunk in stream:
            delta = chunk.choices[0].delta if chunk.choices else None
            if delta:
                if delta.content:
                    content_parts.append(delta.content)
                if delta.tool_calls:
                    for tc in delta.tool_calls:
                        idx = tc.index
                        if idx not in tool_calls_map:
                            tool_calls_map[idx] = {
                                "id": tc.id or "",
                                "type": tc.type or "function",
                                "function": {
                                    "name": tc.function.name if tc.function else "",
                                    "arguments": "",
                                },
                            }
                        if tc.function and tc.function.arguments:
                            tool_calls_map[idx]["function"]["arguments"] += tc.function.arguments

            if chunk.choices[0].finish_reason:
                finish_reason = chunk.choices[0].finish_reason

            if chunk.usage:
                usage = LLMUsage(
                    prompt_tokens=chunk.usage.prompt_tokens,
                    completion_tokens=chunk.usage.completion_tokens,
                    total_tokens=chunk.usage.total_tokens,
                )

        return LLMResponse(
            content="".join(content_parts),
            tool_calls=list(tool_calls_map.values()),
            finish_reason=finish_reason,
            usage=usage,
            model_used=self.config.model,
            latency_s=0.0,
        )

    def _parse_completion(
        self, completion: ChatCompletion, latency: float
    ) -> LLMResponse:
        """Parse non-streaming completion."""
        msg = completion.choices[0].message
        content = msg.content or ""

        tool_calls = []
        if msg.tool_calls:
            for tc in msg.tool_calls:
                tool_calls.append({
                    "id": tc.id,
                    "type": tc.type,
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                })

        usage = LLMUsage(
            prompt_tokens=completion.usage.prompt_tokens if completion.usage else 0,
            completion_tokens=completion.usage.completion_tokens if completion.usage else 0,
            total_tokens=completion.usage.total_tokens if completion.usage else 0,
        )

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            finish_reason=completion.choices[0].finish_reason or "stop",
            usage=usage,
            model_used=completion.model,
            latency_s=latency,
        )

    async def chat_structured(
        self,
        messages: list[dict[str, Any]],
        response_model: type[BaseModel],
        temperature: float = 0.3,
    ) -> BaseModel:
        """Get structured JSON output from model."""
        json_schema = response_model.model_json_schema()
        response_format = {
            "type": "json_schema",
            "json_schema": {
                "name": response_model.__name__,
                "schema": json_schema,
            },
        }

        response = await self.chat(
            messages,
            temperature=temperature,
            response_format=response_format,
        )

        # Parse the JSON response
        content = response.content.strip()
        # Remove markdown code fences if present
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(lines[1:-1]) if lines[-1].startswith("```") else "\n".join(lines[1:])

        try:
            data = json.loads(content)
            return response_model(**data)
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(f"Failed to parse structured response: {e}")
            logger.debug(f"Raw content: {content[:500]}")
            raise

    def estimate_cost(self) -> float:
        """Rough cost estimate based on usage."""
        return self.total_usage.cost_usd
