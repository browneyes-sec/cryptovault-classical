from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class CipherAction(str, Enum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


class CipherRequest(BaseModel):
    cipher: str = Field(..., description="Cipher name (e.g., 'caesar')", examples=["caesar"])
    key: str = Field(..., description="Encryption/decryption key", examples=["3"])
    plaintext: str = Field("", description="Plaintext to encrypt")
    ciphertext: str = Field("", description="Ciphertext to decrypt")
    action: CipherAction = Field(..., description="encrypt or decrypt")


class CipherResponse(BaseModel):
    result: str
    steps: list[str]
    cipher: str
    action: str


class AnalysisMethod(str, Enum):
    FREQUENCY = "frequency"
    INDEX_OF_COINCIDENCE = "index-of-coincidence"
    KASISKI = "kasiski"
    BRUTE_FORCE = "brute-force"


class AnalysisRequest(BaseModel):
    text: str = Field(..., description="Text to analyze")
    language: str = Field("en", description="Expected language")
    key: str = Field("", description="Key for brute-force (optional)")


class FrequencyBar(BaseModel):
    letter: str
    count: int
    percentage: float


class FrequencyResponse(BaseModel):
    frequencies: list[FrequencyBar]
    chi_squared: float
    classification: str
    index_of_coincidence: float


class KasiskiResponse(BaseModel):
    repeated_sequences: list[dict[str, Any]]
    estimated_key_length: int
    recovered_key: str | None


class BruteForceResult(BaseModel):
    key: str
    plaintext: str
    confidence: float


class BruteForceResponse(BaseModel):
    results: list[BruteForceResult]
    cipher: str


class CipherInfo(BaseModel):
    name: str
    category: str
    key_type: str
    description: str
    breakable: bool


class CiphersResponse(BaseModel):
    ciphers: list[CipherInfo]


class LabSubmitRequest(BaseModel):
    answer: str = Field(..., description="User's answer")
    lab_id: str = Field(..., description="Lab identifier")


class LabSubmitResponse(BaseModel):
    correct: bool
    feedback: str
    hint: str | None = None


class HealthResponse(BaseModel):
    status: str
    version: str
    ciphers_loaded: int
