from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..main import CIPHER_REGISTRY, CIPHER_METADATA
from ..models import CipherInfo, CiphersResponse

router = APIRouter()


@router.get("/ciphers", response_model=CiphersResponse)
async def list_ciphers() -> CiphersResponse:
    ciphers = []
    for name in sorted(CIPHER_REGISTRY.keys()):
        meta = CIPHER_METADATA.get(name, {})
        ciphers.append(CipherInfo(
            name=name,
            category=meta.get("category", "Unknown"),
            key_type=meta.get("key_type", "Unknown"),
            description=meta.get("description", ""),
            breakable=meta.get("breakable", "true") == "true",
        ))
    return CiphersResponse(ciphers=ciphers)


@router.get("/ciphers/{name}", response_model=CipherInfo)
async def get_cipher(name: str) -> CipherInfo:
    name = name.lower().replace(" ", "_").replace("-", "_")

    if name not in CIPHER_REGISTRY:
        raise HTTPException(
            status_code=404,
            detail=f"Cipher '{name}' not found. Available: {', '.join(sorted(CIPHER_REGISTRY))}",
        )

    meta = CIPHER_METADATA.get(name, {})
    return CipherInfo(
        name=name,
        category=meta.get("category", "Unknown"),
        key_type=meta.get("key_type", "Unknown"),
        description=meta.get("description", ""),
        breakable=meta.get("breakable", "true") == "true",
    )
