from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite+aiosqlite:///./pif.db"
    upstream_llm_url: str = "https://api.openai.com/v1"
    upstream_api_key: str = ""
    corpus_path: str = "src/pif/detection/corpus"
    block_threshold: float = 0.75
    store_payloads: bool = False
    max_request_size_bytes: int = 1_048_576
    dashboard_api_key: str | None = None
    rate_limit: str = "60/minute"


settings = Settings()


class AttackType(str, Enum):
    DIRECT_INJECTION = "direct_injection"
    PROMPT_LEAKING = "prompt_leaking"
    JAILBREAK_PERSONA = "jailbreak_persona"
    ROLEPLAY_FRAMING = "roleplay_framing"
    HYPOTHETICAL_FRAMING = "hypothetical_framing"
    INDIRECT_INJECTION = "indirect_injection"
    OBFUSCATION = "obfuscation"
    MANY_SHOT = "many_shot"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ADVERSARIAL_SUFFIX = "adversarial_suffix"
    RAG_POISONING = "rag_poisoning"
    AGENTIC_INJECTION = "agentic_injection"
    MULTIMODAL_INJECTION = "multimodal_injection"
    BENIGN = "benign"


class DetectionResult(BaseModel):
    is_injection: bool
    confidence: float = Field(ge=0.0, le=1.0)
    attack_type: AttackType
    matched_patterns: list[str] = []
    layer_triggered: int = 0  # 0=none, 1=heuristics, 2=semantic
    latency_ms: float = 0.0


class AttackEvent(BaseModel):
    id: str
    timestamp: str
    model: str | None
    attack_type: AttackType
    confidence: float
    blocked: bool
    payload_hash: str
    payload_preview: str | None
    layer_triggered: int
    latency_ms: float


class StatsResponse(BaseModel):
    total_requests: int
    blocked_total: int
    blocked_today: int
    block_rate: float
    avg_latency_ms: float


class TimelineBucket(BaseModel):
    hour: str
    total: int
    blocked: int


class AttackTypeCount(BaseModel):
    attack_type: AttackType
    count: int


# OpenAI-compatible message
class ChatMessage(BaseModel):
    role: str
    content: str | list[Any]


class ChatCompletionRequest(BaseModel):
    model: str
    messages: list[ChatMessage]
    stream: bool = False
    temperature: float | None = None
    max_tokens: int | None = None
    model_config = {"extra": "allow"}
