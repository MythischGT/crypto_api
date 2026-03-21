"""
/api/utils  —  Number-theory utility endpoints.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import sys, os

_HERE       = os.path.dirname(os.path.abspath(__file__))
_GALOIS_SRC = os.path.normpath(os.path.join(_HERE, "..", "..", "galoiscore", "src"))
if _GALOIS_SRC not in sys.path:
    sys.path.insert(0, _GALOIS_SRC)

from utils.primes    import is_prime, next_prime, generate_large_prime
from utils.arithmetic import xgcd, mod_inverse

router = APIRouter()

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class IsPrimeIn(BaseModel):
    n: str

class NextPrimeIn(BaseModel):
    n: str

class GeneratePrimeIn(BaseModel):
    bits: int

class ModInverseIn(BaseModel):
    a: str
    m: str

class XGCDIn(BaseModel):
    a: str
    b: str

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/is_prime", summary="Miller-Rabin primality test")
def check_prime(body: IsPrimeIn):
    try:
        n = int(body.n, 0)
    except ValueError:
        raise HTTPException(400, f"Invalid integer: {body.n!r}")
    result = is_prime(n)
    return {"n": str(n), "is_prime": result, "bits": n.bit_length() if n > 0 else 0}

@router.post("/next_prime", summary="Smallest prime >= n")
def get_next_prime(body: NextPrimeIn):
    try:
        n = int(body.n, 0)
    except ValueError:
        raise HTTPException(400, f"Invalid integer: {body.n!r}")
    if n < 0:
        raise HTTPException(400, "n must be non-negative")
    result = next_prime(n)
    return {"input": str(n), "next_prime": str(result), "hex": hex(result)}

@router.post("/generate_prime", summary="Generate a random prime of exactly *bits* bits")
def gen_prime(body: GeneratePrimeIn):
    if body.bits < 2:
        raise HTTPException(400, "bits must be >= 2")
    if body.bits > 4096:
        raise HTTPException(400, "bits must be <= 4096 (API limit)")
    p = generate_large_prime(body.bits)
    return {
        "bits": body.bits,
        "prime": str(p),
        "hex": hex(p),
        "actual_bits": p.bit_length(),
    }

@router.post("/mod_inverse", summary="Modular multiplicative inverse of a mod m")
def modular_inverse(body: ModInverseIn):
    try:
        a = int(body.a, 0)
        m = int(body.m, 0)
    except ValueError as e:
        raise HTTPException(400, str(e))
    try:
        inv = mod_inverse(a, m)
        return {
            "a": str(a), "m": str(m),
            "inverse": str(inv),
            "hex": hex(inv),
            "check": f"{a} × {inv} ≡ {(a * inv) % m} (mod {m})",
        }
    except ZeroDivisionError as e:
        raise HTTPException(400, str(e))

@router.post("/xgcd", summary="Extended Euclidean algorithm: gcd(a,b) = a·x + b·y")
def extended_gcd(body: XGCDIn):
    try:
        a = int(body.a, 0)
        b = int(body.b, 0)
    except ValueError as e:
        raise HTTPException(400, str(e))
    g, x, y = xgcd(a, b)
    return {
        "a": str(a), "b": str(b),
        "gcd": str(g),
        "x": str(x), "y": str(y),
        "check": f"{a}·({x}) + {b}·({y}) = {a*x + b*y}",
    }