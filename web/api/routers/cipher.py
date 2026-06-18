from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..main import CIPHER_REGISTRY
from ..models import (
    CipherRequest,
    CipherResponse,
)

router = APIRouter()


def _generate_steps(
    cipher_name: str, plaintext: str, key: str, action: str, result: str
) -> list[str]:
    steps: list[str] = []
    steps.append(f"Cipher: {cipher_name.replace('_', ' ').title()}")
    steps.append(f"Action: {action}")

    if cipher_name == "caesar":
        steps.append(f"Shift each letter by {key} positions")
    elif cipher_name == "vigenere":
        steps.append(f"Using keyword: {key}")
        steps.append("Apply each keyword letter as a separate Caesar shift")
    elif cipher_name == "vernam":
        steps.append("XOR each plaintext byte with corresponding key byte")
    elif cipher_name == "playfair":
        steps.append(f"Using keyword: {key} to build 5x5 Polybius square")
        steps.append("Split plaintext into digraph pairs")
        steps.append("Apply Playfair rules (same row, same column, rectangle)")
    elif cipher_name == "railfence":
        steps.append(f"Using {key} rails in zigzag pattern")
        steps.append("Read off each rail to produce ciphertext")
    elif cipher_name == "affine":
        steps.append(f"Using key pair: {key}")
        steps.append("Apply E(x) = (ax + b) mod 26")
    elif cipher_name == "atbash":
        steps.append("Replace each letter with its alphabet reversal (A↔Z, B↔Y)")
    elif cipher_name == "bacon":
        steps.append("Encode each letter as 5-bit binary using Bacon alphabet")
    elif cipher_name == "hill":
        steps.append(f"Using key matrix: {key}")
        steps.append("Multiply plaintext vector by key matrix mod 26")
    elif cipher_name == "bifid":
        steps.append(f"Using keyword: {key} to build 5x5 Polybius square")
        steps.append("Write row/column coordinates vertically")
        steps.append("Read coordinates horizontally in pairs")
    elif cipher_name == "trifid":
        steps.append(f"Using keyword: {key} to build 3x3x3 cube")
        steps.append("Separate level/row/col coordinates")
        steps.append("Recombine coordinates into new trigrams")
    elif cipher_name == "foursquare":
        steps.append(f"Using keywords: {key}")
        steps.append("Use two Polybius squares for digraph substitution")
    elif cipher_name == "porta":
        steps.append(f"Using keyword: {key}")
        steps.append("Apply reciprocal substitution table per keyword letter")
    elif cipher_name == "adfgvx":
        steps.append(f"Using Polybius key and columnar key: {key}")
        steps.append("Map each letter to ADFGVX pair via 6x6 Polybius")
        steps.append("Apply columnar transposition to the result")
    elif cipher_name == "monoalphabetic":
        steps.append(f"Using substitution alphabet: {key}")
        steps.append("Replace each letter according to substitution map")
    elif cipher_name in ("columnar", "inverted_columnar", "symmetric_columnar"):
        steps.append(f"Using keyword: {key} to determine column order")
        steps.append("Write plaintext into rows, read off by column order")
    elif cipher_name == "myszkowski":
        steps.append(f"Using repeated keyword: {key}")
        steps.append("Group columns by repeated key letters")
        steps.append("Read off columns in alphabetical order of key")

    if action == "encrypt":
        steps.append(f"Plaintext:  {plaintext}")
        steps.append(f"Ciphertext: {result}")
    else:
        steps.append(f"Ciphertext: {plaintext}")
        steps.append(f"Plaintext:  {result}")

    return steps


@router.post("/cipher", response_model=CipherResponse)
async def cipher_operation(req: CipherRequest) -> CipherResponse:
    name = req.cipher.lower().replace(" ", "_").replace("-", "_")

    if name not in CIPHER_REGISTRY:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown cipher: '{req.cipher}'. Available: {', '.join(sorted(CIPHER_REGISTRY))}",
        )

    cipher_cls = CIPHER_REGISTRY[name]
    cipher = cipher_cls()

    key = req.key
    if name in ("caesar",):
        try:
            key = int(key)
        except ValueError:
            raise HTTPException(status_code=400, detail="Caesar key must be an integer (0-25)")
    elif name in ("affine",):
        try:
            parts = [int(x.strip()) for x in key.split(",")]
            key = (parts[0], parts[1])
        except (ValueError, IndexError):
            raise HTTPException(status_code=400, detail="Affine key must be 'a,b' (e.g., '5,8')")
    elif name in ("railfence",):
        try:
            key = int(key)
        except ValueError:
            raise HTTPException(status_code=400, detail="Rail Fence key must be an integer (number of rails)")
    elif name in ("hill",):
        try:
            parts = [int(x.strip()) for x in key.split(",")]
            dim = int(len(parts) ** 0.5)
            key = [parts[i*dim:(i+1)*dim] for i in range(dim)]
        except (ValueError, IndexError):
            raise HTTPException(status_code=400, detail="Hill key must be comma-separated integers (e.g., '3,2,5,7')")

    try:
        if req.action.value == "encrypt":
            if not req.plaintext:
                raise HTTPException(status_code=400, detail="plaintext is required for encrypt")
            result = cipher.encrypt(req.plaintext, key)
            source = req.plaintext
        else:
            if not req.ciphertext:
                raise HTTPException(status_code=400, detail="ciphertext is required for decrypt")
            result = cipher.decrypt(req.ciphertext, key)
            source = req.ciphertext
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Cipher error: {e}")

    steps = _generate_steps(name, source, req.key, req.action.value, result)

    return CipherResponse(
        result=result,
        steps=steps,
        cipher=name,
        action=req.action.value,
    )
