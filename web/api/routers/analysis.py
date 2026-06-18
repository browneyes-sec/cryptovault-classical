from __future__ import annotations

from fastapi import APIRouter, HTTPException

from cryptovault.cryptanalysis import (
    frequency_analysis,
    chi_squared_test,
    index_of_coincidence,
    classify_text,
    kasiski_examination,
    estimate_key_length,
    recover_key,
)
from cryptovault.ciphers import CaesarCipher, VigenereCipher, AffineCipher, RailFenceCipher

from ..main import CIPHER_REGISTRY
from ..models import (
    AnalysisRequest,
    FrequencyBar,
    FrequencyResponse,
    KasiskiResponse,
    BruteForceResult,
    BruteForceResponse,
)

router = APIRouter()


@router.post("/analysis/frequency", response_model=FrequencyResponse)
async def analyze_frequency(req: AnalysisRequest) -> FrequencyResponse:
    try:
        freq = frequency_analysis(req.text)
        chi2 = chi_squared_test(req.text)
        ioc = index_of_coincidence(req.text)
        classification_result = classify_text(req.text)
        classification = classification_result[0] if isinstance(classification_result, tuple) else str(classification_result)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Analysis error: {e}")

    bars = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        count = freq.get(letter, 0)
        total = sum(freq.values()) or 1
        percentage = round(count / total * 100, 2)
        bars.append(FrequencyBar(letter=letter, count=count, percentage=percentage))

    return FrequencyResponse(
        frequencies=bars,
        chi_squared=round(chi2, 4),
        classification=classification,
        index_of_coincidence=round(ioc, 6),
    )


@router.post("/analysis/index-of-coincidence")
async def analyze_ioc(req: AnalysisRequest) -> dict:
    try:
        ioc = index_of_coincidence(req.text)
        classification = classify_text(req.text)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Analysis error: {e}")

    return {
        "index_of_coincidence": round(ioc, 6),
        "classification": classification,
        "expected_english": 0.0667,
        "expected_random": 0.0385,
    }


@router.post("/analysis/kasiski", response_model=KasiskiResponse)
async def analyze_kasiski(req: AnalysisRequest) -> KasiskiResponse:
    try:
        repeated = kasiski_examination(req.text)
        key_length = estimate_key_length(req.text)
        key = recover_key(req.text, key_length) if key_length > 0 else None
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Analysis error: {e}")

    seq_list = []
    for seq, positions in repeated.items():
        seq_list.append({
            "sequence": seq,
            "positions": positions,
            "count": len(positions),
        })
    seq_list.sort(key=lambda x: x["count"], reverse=True)

    return KasiskiResponse(
        repeated_sequences=seq_list[:20],
        estimated_key_length=key_length,
        recovered_key=key,
    )


@router.post("/analysis/brute-force", response_model=BruteForceResponse)
async def analyze_brute_force(req: AnalysisRequest) -> BruteForceResponse:
    if not req.ciphertext:
        raise HTTPException(status_code=400, detail="ciphertext is required for brute-force")

    results: list[BruteForceResult] = []

    try:
        cipher = CaesarCipher()
        cracked = cipher.crack(req.ciphertext)
        for key_val, plaintext, confidence in cracked[:10]:
            results.append(BruteForceResult(
                key=str(key_val),
                plaintext=plaintext,
                confidence=round(confidence, 4),
            ))
    except Exception:
        pass

    if not results:
        try:
            cipher = VigenereCipher()
            cracked = cipher.crack(req.ciphertext)
            for key_val, plaintext, confidence in cracked[:10]:
                results.append(BruteForceResult(
                    key=str(key_val),
                    plaintext=plaintext,
                    confidence=round(confidence, 4),
                ))
        except Exception:
            pass

    return BruteForceResponse(
        results=results,
        cipher="caesar" if results else "unknown",
    )
