from __future__ import annotations

import time

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from cryptovault import (
    CaesarCipher,
    VigenereCipher,
    VernamCipher,
    PlayfairCipher,
    RailFenceCipher,
    AffineCipher,
    AtbashCipher,
    BaconCipher,
    HillCipher,
    BifidCipher,
    TrifidCipher,
    FourSquareCipher,
    PortaCipher,
    ADFGVXCipher,
    MonoalphabeticCipher,
    MyszkowskiCipher,
    ColumnarTransposition,
    InvertedColumnarTransposition,
    SymmetricColumnarTransposition,
)

from .models import HealthResponse

CIPHER_REGISTRY: dict[str, type] = {
    "caesar": CaesarCipher,
    "vigenere": VigenereCipher,
    "vernam": VernamCipher,
    "playfair": PlayfairCipher,
    "railfence": RailFenceCipher,
    "affine": AffineCipher,
    "atbash": AtbashCipher,
    "bacon": BaconCipher,
    "hill": HillCipher,
    "bifid": BifidCipher,
    "trifid": TrifidCipher,
    "foursquare": FourSquareCipher,
    "porta": PortaCipher,
    "adfgvx": ADFGVXCipher,
    "monoalphabetic": MonoalphabeticCipher,
    "myszkowski": MyszkowskiCipher,
    "columnar": ColumnarTransposition,
    "inverted_columnar": InvertedColumnarTransposition,
    "symmetric_columnar": SymmetricColumnarTransposition,
}

CIPHER_METADATA: dict[str, dict[str, str]] = {
    "caesar": {"category": "Monoalphabetic", "key_type": "Shift (0-25)", "description": "Fixed shift substitution", "breakable": "true"},
    "vigenere": {"category": "Polyalphabetic", "key_type": "Keyword", "description": "Polyalphabetic keyword substitution", "breakable": "true"},
    "vernam": {"category": "XOR/OTP", "key_type": "Random bits", "description": "XOR one-time pad (perfect secrecy)", "breakable": "false"},
    "playfair": {"category": "Digraph", "key_type": "Keyword (5x5)", "description": "Digraph substitution using Polybius square", "breakable": "true"},
    "railfence": {"category": "Transposition", "key_type": "Rail count", "description": "Zigzag transposition", "breakable": "true"},
    "affine": {"category": "Monoalphabetic", "key_type": "(a,b) pair", "description": "Modular arithmetic substitution", "breakable": "true"},
    "atbash": {"category": "Monoalphabetic", "key_type": "None (fixed)", "description": "Alphabet reversal involution", "breakable": "true"},
    "bacon": {"category": "Steganographic", "key_type": "Alphabet map", "description": "Binary-coded steganographic encoding", "breakable": "true"},
    "hill": {"category": "Polygraphic", "key_type": "Matrix", "description": "Matrix multiplication mod 26", "breakable": "true"},
    "bifid": {"category": "Fractionation", "key_type": "Keyword (5x5)", "description": "Fractionation + transposition", "breakable": "true"},
    "trifid": {"category": "Fractionation", "key_type": "Keyword (3x3x3)", "description": "3D fractionation with 27-char cube", "breakable": "true"},
    "foursquare": {"category": "Digraph", "key_type": "Two keywords", "description": "Double keyed digraph substitution", "breakable": "true"},
    "porta": {"category": "Polyalphabetic", "key_type": "Keyword", "description": "Reciprocal polyalphabetic substitution", "breakable": "true"},
    "adfgvx": {"category": "Composite", "key_type": "Polybius + columnar", "description": "WWI field cipher (Polybius + transposition)", "breakable": "true"},
    "monoalphabetic": {"category": "Monoalphabetic", "key_type": "Permutation", "description": "General single-alphabet replacement", "breakable": "true"},
    "myszkowski": {"category": "Transposition", "key_type": "Repeated keyword", "description": "Columnar variant with repeated-key grouping", "breakable": "true"},
    "columnar": {"category": "Transposition", "key_type": "Keyword", "description": "Standard keyword column reordering", "breakable": "true"},
    "inverted_columnar": {"category": "Transposition", "key_type": "Keyword", "description": "Inverted sort order columnar", "breakable": "true"},
    "symmetric_columnar": {"category": "Transposition", "key_type": "Permutation", "description": "Symmetric permutation columnar", "breakable": "true"},
}

START_TIME = time.time()

app = FastAPI(
    title="CryptoVault Classical",
    description="Interactive classical cryptography learning platform",
    version="0.2.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from .routers import analysis, cipher, ciphers, labs  # noqa: E402

app.include_router(cipher.router, prefix="/api", tags=["cipher"])
app.include_router(analysis.router, prefix="/api", tags=["analysis"])
app.include_router(ciphers.router, prefix="/api", tags=["ciphers"])
app.include_router(labs.router, prefix="/api", tags=["labs"])


@app.get("/api/health", response_model=HealthResponse, tags=["health"])
async def health_check() -> HealthResponse:
    return HealthResponse(
        status="healthy",
        version="0.2.0",
        ciphers_loaded=len(CIPHER_REGISTRY),
    )


app.mount("/", StaticFiles(directory="web/static", html=True), name="static")
