from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..models import LabSubmitRequest, LabSubmitResponse

router = APIRouter()

LAB_ANSWERS: dict[str, dict[str, str]] = {
    "caesar-fundamentals": {
        "expected": "KHOOR",
        "hint": "Try shifting each letter back by the key amount.",
        "feedback_correct": "Correct! Caesar cipher with shift 3 transforms HELLO to KHOOR.",
        "feedback_incorrect": "Not quite. Remember: each letter shifts by the key value.",
    },
    "vigenere-breaking": {
        "expected": "KEY",
        "hint": "Use Kasiski examination to find repeated patterns, then determine key length.",
        "feedback_correct": "Correct! The Vigenère key is KEY.",
        "feedback_incorrect": "Try using Kasiski examination on the ciphertext first.",
    },
    "frequency-analysis": {
        "expected": "monoalphabetic",
        "hint": "Check if letter frequencies match English distribution (single peaks).",
        "feedback_correct": "Correct! This text uses monoalphabetic substitution.",
        "feedback_incorrect": "Think about whether the frequency distribution shows one alphabet or multiple.",
    },
    "playfair-cracking": {
        "expected": "SECRET",
        "hint": "Start with common digraphs like TH, HE, IN. Try crib-dragging.",
        "feedback_correct": "Correct! The Playfair key is SECRET.",
        "feedback_incorrect": "Try crib-dragging with common English digraphs.",
    },
    "field-ciphers": {
        "expected": "ATTACK",
        "hint": "First identify the ADFGVX substitution, then reverse the columnar transposition.",
        "feedback_correct": "Correct! You've broken the ADFGVX cipher.",
        "feedback_incorrect": "Remember: ADFGVX uses a 6x6 Polybius square followed by columnar transposition.",
    },
}


@router.post("/labs/{lab_id}/submit", response_model=LabSubmitResponse)
async def submit_lab(lab_id: str, req: LabSubmitRequest) -> LabSubmitResponse:
    if lab_id not in LAB_ANSWERS:
        raise HTTPException(
            status_code=404,
            detail=f"Lab '{lab_id}' not found. Available: {', '.join(sorted(LAB_ANSWERS))}",
        )

    lab = LAB_ANSWERS[lab_id]
    correct = req.answer.strip().upper() == lab["expected"].upper()

    if correct:
        return LabSubmitResponse(
            correct=True,
            feedback=lab["feedback_correct"],
        )
    else:
        return LabSubmitResponse(
            correct=False,
            feedback=lab["feedback_incorrect"],
            hint=lab["hint"],
        )
