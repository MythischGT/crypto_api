"""
/api/ecc  —  Elliptic-curve endpoints.
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
from crypto.ecc.curves import get_curve, SEC_P256K1, P_256, P_384
from crypto.ecc.point import Point

router = APIRouter()

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

NAMED_CURVES = {
    "secp256k1": SEC_P256K1,
    "p256":      P_256,
    "p384":      P_384,
}

class PointOut(BaseModel):
    x: Optional[str] = None
    y: Optional[str] = None
    x_hex: Optional[str] = None
    y_hex: Optional[str] = None
    is_infinity: bool

class CurveInfo(BaseModel):
    name: str
    p: str
    a: str
    b: str
    n: str
    h: int
    Gx: str
    Gy: str
    bit_size: int

class ScalarMulIn(BaseModel):
    curve: str
    k: str
    x: Optional[str] = None
    y: Optional[str] = None

class PointAddIn(BaseModel):
    curve: str
    x1: str
    y1: str
    x2: str
    y2: str

class PointValidateIn(BaseModel):
    curve: str
    x: str
    y: str

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_curve(name: str):
    try:
        return get_curve(name.lower())
    except KeyError:
        raise HTTPException(400, f"Unknown curve {name!r}. Valid: {list(NAMED_CURVES)}")

def _curve_prime(c) -> int:
    """
    CurveParameters stores the prime inside its field elements,
    not as a top-level attribute.  Access it safely via a or G.
    """
    # Prefer c.a since it's always a PrimeFieldElement (even when a=0)
    if hasattr(c, "p") and isinstance(c.p, int):
        return c.p
    try:
        return c.a.prime        # a is a PrimeFieldElement
    except AttributeError:
        return c.G.x.prime      # fall back to generator x-coordinate field

def _point_out(p: Point) -> PointOut:
    if p.is_infinity():
        return PointOut(is_infinity=True)
    return PointOut(
        x=str(p.x.num),
        y=str(p.y.num),
        x_hex=hex(p.x.num),
        y_hex=hex(p.y.num),
        is_infinity=False,
    )

def _load_point(curve, x_s: str, y_s: str) -> Point:
    prime = _curve_prime(curve)
    F = PrimeField(prime)
    try:
        x = F(int(x_s, 0))
        y = F(int(y_s, 0))
        a = F(curve.a)   # same F — integer 0 for secp256k1
        b = F(curve.b)   # same F — integer 7 for secp256k1
        return Point(x, y, a, b)
    except Exception as e:
        raise HTTPException(400, f"Invalid coordinate: {e}")
    try:
        return Point(x, y, curve.a, curve.b)
    except ValueError as e:
        raise HTTPException(400, f"Point not on curve: {e}")

def _curve_info(c) -> CurveInfo:
    prime = _curve_prime(c)
    G = c.G
    return CurveInfo(
        name=c.name,
        p=str(prime),
        a=str(c.a),
        b=str(c.b),
        n=str(c.n),
        h=getattr(c, "h", 1),      # cofactor — defaults to 1 for standard curves
        Gx=str(G.x),
        Gy=str(G.y),
        bit_size=prime.bit_length(),
    )

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/curves", summary="List available named curves")
def list_curves():
    return [_curve_info(c) for c in NAMED_CURVES.values()]

@router.get("/curves/{name}", response_model=CurveInfo, summary="Get curve parameters")
def curve_info(name: str):
    return _curve_info(_get_curve(name))

@router.get("/curves/{name}/generator", response_model=PointOut, summary="Get the generator point G")
def generator(name: str):
    return _point_out(_get_curve(name).G)

@router.post("/point/validate", summary="Check whether (x, y) lies on the curve")
def validate_point(body: PointValidateIn):
    c = _get_curve(body.curve)
    try:
        p = _load_point(c, body.x, body.y)
        return {"on_curve": True, "point": _point_out(p)}
    except HTTPException as e:
        return {"on_curve": False, "error": e.detail}

@router.post("/point/add", response_model=PointOut, summary="P1 + P2 on the curve")
def point_add(body: PointAddIn):
    c  = _get_curve(body.curve)
    p1 = _load_point(c, body.x1, body.y1)
    p2 = _load_point(c, body.x2, body.y2)
    try:
        return _point_out(p1 + p2)
    except Exception as e:
        raise HTTPException(400, str(e))

@router.post("/scalar_mul", response_model=PointOut, summary="k × P  (defaults to k × G)")
def scalar_mul(body: ScalarMulIn):
    c = _get_curve(body.curve)
    try:
        k = int(body.k, 0)
    except ValueError:
        raise HTTPException(400, f"Invalid scalar k: {body.k!r}")

    if body.x is None or body.y is None:
        P = c.G
    else:
        P = _load_point(c, body.x, body.y)

    try:
        return _point_out(k * P)
    except Exception as e:
        raise HTTPException(400, str(e))