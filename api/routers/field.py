"""
/api/field  —  Prime-field arithmetic endpoints.

All numbers are passed as strings to support 256-bit integers in JSON.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import sys, os

_HERE       = os.path.dirname(os.path.abspath(__file__))
_GALOIS_SRC = os.path.normpath(os.path.join(_HERE, "..", "..", "galoiscore", "src"))
if _GALOIS_SRC not in sys.path:
    sys.path.insert(0, _GALOIS_SRC)

from core.prime import PrimeField

router = APIRouter()

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class FieldElementIn(BaseModel):
    prime: str
    value: str

class BinaryOpIn(BaseModel):
    prime: str
    a: str
    b: str

class PowIn(BaseModel):
    prime: str
    base: str
    exp: str

class FieldElementOut(BaseModel):
    prime: str
    value: str
    hex: str

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _field(prime_s: str) -> PrimeField:
    try:
        p = int(prime_s, 0)
    except ValueError:
        raise HTTPException(400, f"Invalid prime: {prime_s!r}")
    try:
        return PrimeField(p)
    except Exception as e:
        raise HTTPException(400, str(e))

def _elem(F: PrimeField, v_s: str):
    try:
        v = int(v_s, 0)
    except ValueError:
        raise HTTPException(400, f"Invalid value: {v_s!r}")
    try:
        return F(v)
    except Exception as e:
        raise HTTPException(400, str(e))

def _out(el) -> FieldElementOut:
    return FieldElementOut(
        prime=str(el.prime),
        value=str(el.num),
        hex=hex(el.num),
    )

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/element", response_model=FieldElementOut, summary="Create / validate a field element")
def create_element(body: FieldElementIn):
    """Return the canonical representative of *value* in GF(*prime*)."""
    F  = _field(body.prime)
    el = _elem(F, body.value)
    return _out(el)

@router.post("/add", response_model=FieldElementOut, summary="a + b  mod  prime")
def add(body: BinaryOpIn):
    F = _field(body.prime)
    return _out(_elem(F, body.a) + _elem(F, body.b))

@router.post("/sub", response_model=FieldElementOut, summary="a − b  mod  prime")
def sub(body: BinaryOpIn):
    F = _field(body.prime)
    return _out(_elem(F, body.a) - _elem(F, body.b))

@router.post("/mul", response_model=FieldElementOut, summary="a × b  mod  prime")
def mul(body: BinaryOpIn):
    F = _field(body.prime)
    return _out(_elem(F, body.a) * _elem(F, body.b))

@router.post("/div", response_model=FieldElementOut, summary="a / b  mod  prime")
def div(body: BinaryOpIn):
    F = _field(body.prime)
    try:
        return _out(_elem(F, body.a) / _elem(F, body.b))
    except (ValueError, ZeroDivisionError) as e:
        raise HTTPException(400, str(e))

@router.post("/pow", response_model=FieldElementOut, summary="base ^ exp  mod  prime")
def power(body: PowIn):
    F = _field(body.prime)
    try:
        exp = int(body.exp, 0)
    except ValueError:
        raise HTTPException(400, f"Invalid exponent: {body.exp!r}")
    try:
        return _out(_elem(F, body.base) ** exp)
    except Exception as e:
        raise HTTPException(400, str(e))

@router.post("/inverse", response_model=FieldElementOut, summary="Multiplicative inverse of a in GF(prime)")
def inverse(body: FieldElementIn):
    F = _field(body.prime)
    try:
        return _out(_elem(F, body.value).inverse())
    except Exception as e:
        raise HTTPException(400, str(e))

@router.post("/neg", response_model=FieldElementOut, summary="Additive inverse (negation) of a in GF(prime)")
def neg(body: FieldElementIn):
    F = _field(body.prime)
    return _out(-_elem(F, body.value))